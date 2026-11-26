use super::*;
use crate::raw::{ClientObservation, Control, MemberReceiver};
use std::collections::VecDeque;

const REPORT_MAX_AGE: Duration = Duration::from_secs(40);
const RECENT_PORTS: usize = 32;

pub(in crate::runtime) struct RawMemberObservation {
    path: ObservedPath,
    observation: ClientObservation,
    measured: time::Instant,
}

#[derive(Default)]
pub(in crate::runtime) struct RawMemberReconnect {
    pending: Option<RawMemberObservation>,
    used_ports: VecDeque<u16>,
}

impl RawMemberReconnect {
    pub(in crate::runtime) async fn prepare(&mut self, base: ObservedPath) -> Result<SocketAddr> {
        if let Some(pending) = &self.pending
            && pending.measured.elapsed() < REPORT_MAX_AGE
            && pending.path.local.ip() == base.local.ip()
            && pending.path.mapped.ip() == base.mapped.ip()
            && pending.path.observer == base.observer
        {
            return Ok(pending.path.mapped.into());
        }

        self.pending = None;
        let observation = ClientObservation::rotated(
            base.local.into(), base.observer.into(), self.used_ports.make_contiguous(),
        ).await?;
        let path = ObservedPath::new(observation.local, observation.mapped, observation.observer)
            .context("原始承载成员重连缺少新端口的 IPv4 映射")?;
        if path.mapped.ip() != base.mapped.ip() {
            return Err(ExitChanged.into());
        }
        if self.used_ports.len() == RECENT_PORTS {
            self.used_ports.pop_front();
        }
        self.used_ports.push_back(path.local.port());
        let mapped = observation.mapped;
        self.pending = Some(RawMemberObservation { path, observation, measured: time::Instant::now() });
        Ok(mapped)
    }

    pub(in crate::runtime) fn take(&mut self) -> Option<RawMemberObservation> {
        self.pending.take()
    }
}

pub(super) struct AttemptLog<'a> {
    control: &'a Control,
    trace: &'a Trace,
    peer: IpAddr,
    attempt: usize,
    since: i64,
}

impl<'a> AttemptLog<'a> {
    pub(super) fn new(control: &'a Control, peer: SocketAddr, trace: &'a Trace, attempt: usize) -> Self {
        trace.source(attempt, "mimic_helper");
        let since = if attempt == 0 { trace.started_unix_ms() } else { diagnostics::unix_ms() };
        Self { control, trace, peer: peer.ip(), attempt, since }
    }
}

impl Drop for AttemptLog<'_> {
    fn drop(&mut self) {
        let start = self.trace.started_unix_ms();
        self.control.visit_handshakes(self.peer, self.since, |peer, stage, at, injected| {
            self.trace.at(self.attempt, self.control.source, peer, stage, at - start, None, injected);
        });
    }
}

pub(super) fn mimic_handshake_progress(control: &Control, peer: IpAddr, since: i64) -> bool {
    let mut received = false;
    control.visit_handshakes(peer, since, |_, stage, _, _| {
        received |= matches!(stage, "rx_syn" | "rx_syn_ack" | "rx_final_ack" | "bridge_opened");
    });
    received
}

fn verified_route(running: &Running, receiver: &MemberReceiver) -> Option<CancellationToken> {
    let peer = running.peer.lock().unwrap();
    let peer = peer.as_ref().filter(|peer| peer.link.connected())?;
    peer.chosen.as_ref().and_then(|id| peer.routes.get(id)).into_iter().chain(peer.routes.values()).find_map(|route| {
        (route.verified && !route.cancel.is_cancelled() && receiver.owns_peer(route.endpoint))
            .then(|| route.cancel.clone())
    })
}

impl Engine {
    pub(in crate::runtime) async fn predict_private_raw_member(
        self: &Arc<Self>, running: &Arc<Running>, client: &Client, prepared: RawMemberObservation,
        mode: &str, target: SocketAddr, trace: &Trace, prediction: bool, request: &CancellationToken,
    ) -> Result<bool> {
        let mut log = RoundLog::new(trace.clone(), &self.events);
        let network = running.config.read().unwrap().clone();
        let SocketAddr::V4(target) = target else {
            trace.close("ipv6");
            return Ok(false);
        };
        if network.settings.mode()? != mode || network.paused || !network.enabled
            || network.settings.existing_only() || network.settings.discovery_mode != "coordinator"
        {
            trace.close("connection_or_settings_changed");
            return Ok(false);
        }
        if member_link_verified(running, None) {
            trace.close("already_connected");
            return Ok(true);
        }
        let profile = network.profile.as_ref().context("原始承载成员身份缺失")?;
        let peer = remote_member(profile).context("原始承载对端成员已移除")?;
        let path = prepared.path;
        trace.stage("rotate_stun_path");
        let stop = running.cancel.child_token();
        let _stop_guard = stop.clone().drop_guard();
        let mut helper = None;
        let operation = async {
            ensure!(discovery::local_route(target.into())? == IpAddr::V4(*path.local.ip()),
                "重连对端与新 TCP STUN 观察使用不同的本机出口");
            let receiver = prepared.observation.recovery_receiver(self, mode, target.into()).await?;
            // Cancellation of a round never owns the parent of a subsequently
            // authenticated route. On failure we explicitly join the receiver.
            let receiver = helper.insert(receiver.serve_member(self, mode, &running.cancel, &running.raw_reconnect_workers));
            ensure!(receiver.control.confirms_syn, "重连 helper 未确认支持同源 SYN");
            if mode == "mimic" {
                log.watch_mimic(&self.components, path.local.into(), target.into());
            }
            trace.stage("reconnect_helper_ready");
            let observation = prepared.observation.tcp_observation();
            if !prediction {
                trace.attempt(0, "dial");
                let _events = (mode == "mimic").then(|| AttemptLog::new(&receiver.control, target.into(), trace, 0));
                let next = time::Instant::now() + RawMemberTiming::for_mode(mode).round;
                return time::timeout_at(next, StunLease::during(
                    observation, path.addresses(), next, |status| trace.stun_lease(status),
                    async { Ok(()) }, |_| async {
                        let greeting = running.member_greeting(profile)?;
                        receiver.control.punch(target.into(), &greeting).await?;
                        Ok(wait_for_member_link(running, next, Some(target.into())).await)
                    },
                )).await.unwrap_or(Ok(false));
            }
            trace.stage("check_egress");
            let entry = self.tcp_prediction.entry(Egress::read(path).await?);
            let session = Session {
                trace: trace.clone(),
                components: &self.components,
                client,
                signal: Signal::Member { profile, peer: &peer, boot: running.boot },
                round: trace.round(),
                plan_hash: (network.settings.tcp_stun.len() == 1)
                    .then(|| ProbePlan::new(mode, path.observer.into()).hash()).transpose()?,
                path,
                observation,
                target,
                stop: &stop,
            };
            let result = tokio::select! {
                _ = entry.retired.cancelled() => { trace.close("egress_changed"); return Ok(false); },
                result = async {
                    trace.stage("warmup");
                    let estimate = entry.estimate(path, &stop, Some(trace)).await?;
                    session.run_raw(self, running, &network, &entry, estimate.as_ref(), Some(receiver)).await
                } => result,
            };
            if result.as_ref().is_err_and(|error: &anyhow::Error| error.is::<ExitChanged>()) {
                self.tcp_prediction.retire(&entry);
            }
            result
        };
        let result = tokio::select! {
            _ = stop.cancelled() => Ok(false),
            _ = request.cancelled() => Ok(false),
            result = operation => result,
        };
        let mut authenticated = matches!(result, Ok(true));
        if let Some(receiver) = helper {
            // A bridge alone is not enough. Keep the helper only for a live,
            // authenticated route and close just this round's receiver otherwise.
            if let Some(route) = verified_route(running, &receiver) {
                authenticated = true;
                receiver.retain(&self.tracker, route);
            } else {
                receiver.finish().await;
                trace.stage("reconnect_helper_stopped");
            }
        }
        drop(prepared);
        if authenticated {
            trace.stage("mesh_authenticated");
            trace.close("success");
            return Ok(true);
        }
        if request.is_cancelled() || stop.is_cancelled() {
            trace.close("round_cancelled");
        } else if let Err(error) = &result {
            trace.error(error);
            trace.close(if error.is::<StunLeaseLost>() { "stun_lease_lost" } else { "prediction_failed" });
        } else {
            trace.close(if trace.used_candidates() { "raw_reconnect_timeout" } else { "no_valid_candidates" });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::CandidateReceiver;
    use crate::runtime::reconnect::RoundOutcome;
    use tokio::net::{TcpListener, UdpSocket};

    async fn fresh_base(observer: SocketAddr) -> Result<ObservedPath> {
        let source = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?.local_addr()?;
        Ok(ObservedPath::new(source, source, observer).unwrap())
    }

    #[tokio::test]
    async fn mimic_member_dial_retry_measures_a_new_port_before_the_next_report() -> Result<()> {
        let app = crate::tests::app().await?;
        let profile = Profile::create("mimic")?;
        let (_, observer, stop, server, _) =
            crate::coordinator::prediction_fixture(app, &profile, |source| async move { Some(source) }).await?;
        let _stop = stop.clone().drop_guard();
        let base = fresh_base(observer).await?;
        let mut reconnect = RawMemberReconnect::default();
        let mut used = vec![base.local.port()];
        for _ in 0..3 {
            let endpoint = reconnect.prepare(base).await?;
            assert_eq!(reconnect.prepare(base).await?, endpoint, "Keep the same endpoint while negotiating one round");
            let prepared = reconnect.take().unwrap();
            assert_eq!(prepared.path.mapped, prepared.path.local);
            assert_eq!(prepared.path.mapped.port(), endpoint.port());
            assert!(!used.contains(&endpoint.port()));
            used.push(endpoint.port());
            let lease = prepared.observation.retain_stun().await?;
            let status = serde_json::to_value(*lease.status().borrow())?;
            assert_eq!(status["local"], endpoint.to_string());
            assert_eq!(status["observer"], observer.to_string());
            assert_eq!(status["state"], "binding_ok");
        }
        stop.cancel();
        server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn mimic_member_burst_retry_submits_from_the_replacement_helper_source() -> Result<()> {
        let app = crate::tests::app().await?;
        let profile = Profile::create("mimic")?;
        let (_, observer, stop, server, _) =
            crate::coordinator::prediction_fixture(app.clone(), &profile, |source| async move { Some(source) }).await?;
        let _stop = stop.clone().drop_guard();
        let base = fresh_base(observer).await?;
        let peer = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?.local_addr()?;
        let entry = Cache::default().entry(Egress {
            local: *base.local.ip(), public: *base.mapped.ip(), interface: 1, observer: base.observer,
        });
        let mut reconnect = RawMemberReconnect::default();
        let mut previous = base.local.port();
        for _ in 0..2 {
            reconnect.prepare(base).await?;
            let prepared = reconnect.take().unwrap();
            let path = prepared.path;
            assert_ne!(path.local.port(), previous);
            previous = path.local.port();
            let control = Control::test_probe_control(path.local.into(), true);
            let trace = Trace::new(Uuid::new_v4(), "reconnect", "burst", "mimic");
            trace.attempt(0, "burst");
            {
                let _events = AttemptLog::new(&control, peer, &trace, 0);
                let punch = RawPunch { mode: "mimic", path, peer, client: false, fake: None,
                    control: Some(&control), member: true, trace: &trace, attempt: 0, stop: &stop };
                let (ports, complete) = punch.candidates(&app.engine, &entry, None, path.mapped.port()).await?;
                assert!(complete && ports.contains(&path.mapped.port()));
            }
            let data = trace.snapshot();
            assert_eq!(data["attempts"]["0"]["l_mid"], path.local.port());
            assert_eq!(data["attempts"]["0"]["packets_from"], "mimic_helper");
            assert!(data["attempts"]["0"]["sockets"].as_array().unwrap().iter().any(|socket|
                socket["local"] == path.local.to_string() && socket["times_ms"]["syn_confirmed_by_helper"].is_number()));
            trace.close("raw_reconnect_timeout");
        }
        stop.cancel();
        server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn raw_member_retry_with_new_helper_transfers_authenticated_packets_and_releases_on_cold_stop() -> Result<()> {
        for mode in ["phantun", "tcpraw"] {
            verify_raw_member_retry(mode).await.with_context(|| format!("验证 {mode} 重连数据面"))?;
        }
        Ok(())
    }

    async fn verify_raw_member_retry(mode: &str) -> Result<()> {
        let left_app = crate::tests::app().await?;
        let right_app = crate::tests::app().await?;
        let mut owner = Profile::create(mode)?;
        let guest = Profile::import(&owner.issue(None)?.export()?)?;
        // Exercise the real MeshLink/UDP bridge with a loopback stand-in for
        // the packet driver. Tests need no host driver or network privileges.
        let left = super::super::tests::install_peer_with_listener(&left_app, owner.clone(), true, "tcp").await?;
        let right = super::super::tests::install_peer_with_listener(&right_app, guest.clone(), false, "tcp").await?;
        for running in [&left, &right] {
            let mut cfg = running.config.write().unwrap();
            Arc::make_mut(&mut cfg).settings.path_selection = format!("{mode}-only");
        }
        let (_, observer, stop, server, _) = crate::coordinator::prediction_fixture(
            left_app.clone(), &owner, |source| async move { Some(source) },
        ).await?;
        let _server_stop = stop.clone().drop_guard();
        let (base_left, base_right) = (fresh_base(observer).await?, fresh_base(observer).await?);
        let first = Uuid::new_v4();
        for running in [&left, &right] {
            let mut reconnect = running.reconnect.lock().unwrap();
            assert!(!reconnect.private_raw());
            let (request, _) = reconnect.report();
            assert!(reconnect.begin(first, None, &request));
        }
        let (old, old_bridge) = CandidateReceiver::test_member_bridge(base_left.local.into(), base_right.mapped.into()).await?;
        let old_address = old.socket.local_addr()?;
        let old = old.serve_member(&left_app.engine, mode, &left.cancel, &left.raw_reconnect_workers);
        // The first candidate fails with a silent bridge.
        assert!(!wait_for_member_link(&left, time::Instant::now() + Duration::from_millis(40), None).await);
        old.finish().await;
        assert!(UdpSocket::bind(old_address).await.is_ok(), "old bridge still owns its local socket");
        drop(old_bridge);
        for running in [&left, &right] {
            let mut reconnect = running.reconnect.lock().unwrap();
            let (request, _) = reconnect.report();
            reconnect.complete(first, &request, RoundOutcome::RawTimedOut);
            assert!(reconnect.private_raw() && reconnect.retiring_raw_listener());
        }

        let mut left_retry = RawMemberReconnect::default();
        let mut right_retry = RawMemberReconnect::default();
        let left_endpoint = left_retry.prepare(base_left).await?;
        let right_endpoint = right_retry.prepare(base_right).await?;
        let left_path = left_retry.take().unwrap();
        let right_path = right_retry.take().unwrap();
        assert_ne!(left_path.path.local, base_left.local);
        assert_ne!(right_path.path.local, base_right.local);
        let (left_raw, left_io) = CandidateReceiver::test_member_bridge(left_path.path.local.into(), right_endpoint).await?;
        let (right_raw, right_io) = CandidateReceiver::test_member_bridge(right_path.path.local.into(), left_endpoint).await?;
        let (left_udp, right_udp) = (left_raw.socket.local_addr()?, right_raw.socket.local_addr()?);
        let left_receiver = left_raw.serve_member(&left_app.engine, mode, &left.cancel, &left.raw_reconnect_workers);
        let right_receiver = right_raw.serve_member(&right_app.engine, mode, &right.cancel, &right.raw_reconnect_workers);
        assert_eq!(left_receiver.control.source, left_endpoint);
        assert_eq!(right_receiver.control.source, right_endpoint);
        let greeting = right.member_greeting(&guest)?;
        left_io.send_to(&greeting, left_udp).await?;
        let relay = tokio::spawn(async move {
            // Each synthetic helper receives on its own UDP socket and sends
            // the other side's frame from that same socket.
            let mut from_left = [0; 2048];
            let mut from_right = [0; 2048];
            loop {
                tokio::select! {
                    packet = left_io.recv_from(&mut from_left) => {
                        let (size, _) = packet?;
                        right_io.send_to(&from_left[..size], right_udp).await?;
                    }
                    packet = right_io.recv_from(&mut from_right) => {
                        let (size, _) = packet?;
                        left_io.send_to(&from_right[..size], left_udp).await?;
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        });
        let end = time::Instant::now() + Duration::from_secs(5);
        let (left_ok, right_ok) = tokio::join!(
            wait_for_member_link(&left, end, Some(right_endpoint)),
            wait_for_member_link(&right, end, Some(left_endpoint)),
        );
        assert!(left_ok && right_ok);
        let left_route = verified_route(&left, &left_receiver).unwrap();
        let right_route = verified_route(&right, &right_receiver).unwrap();
        left_receiver.retain(&left_app.engine.tracker, left_route);
        right_receiver.retain(&right_app.engine.tracker, right_route);
        drop((left_path, right_path));
        let outgoing = crate::tests::packet(owner.local_ip()?, guest.local_ip()?, 0x42);
        let incoming = crate::tests::packet(guest.local_ip()?, owner.local_ip()?, 0x71);
        left.memory.as_ref().unwrap().inject(outgoing.clone())?;
        right.memory.as_ref().unwrap().inject(incoming.clone())?;
        time::timeout(Duration::from_secs(5), async {
            while left.metrics.read().unwrap().received == 0 || right.metrics.read().unwrap().received == 0 {
                time::sleep(Duration::from_millis(20)).await;
            }
        }).await?;
        assert_eq!(left.memory.as_ref().unwrap().drain(), [incoming]);
        assert_eq!(right.memory.as_ref().unwrap().drain(), [outgoing]);
        let left_id = left.config.read().unwrap().id.clone();
        let right_id = right.config.read().unwrap().id.clone();
        tokio::try_join!(left_app.engine.remove(&left_id), right_app.engine.remove(&right_id))?;
        assert!(left.raw_reconnect_workers.is_empty() && right.raw_reconnect_workers.is_empty());
        assert!(UdpSocket::bind(left_udp).await.is_ok() && UdpSocket::bind(right_udp).await.is_ok());
        relay.abort();
        let _ = relay.await;
        stop.cancel();
        server.await?;
        left_app.engine.shutdown().await?;
        right_app.engine.shutdown().await?;
        Ok(())
    }
}
