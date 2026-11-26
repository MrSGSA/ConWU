use super::*;
use crate::model::{Network, Settings};
use conwu_core::nat_tcp_punch::estimator::PortCoupling;
use std::sync::atomic::Ordering;
use tokio::{net::TcpListener, sync::oneshot};

const LOCAL: Ipv4Addr = Ipv4Addr::LOCALHOST;
const TEST_WAIT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn native_member_anchor_failure_drops_live_middle_before_publishing_empty_offer() -> Result<()> {
    use tokio::io::AsyncReadExt;
    for mode in ["tcp", "https"] {
        let listener = TcpListener::bind((LOCAL, 0)).await?;
        let (connection, (mut peer, _)) = tokio::try_join!(
            TcpStream::connect(listener.local_addr()?), listener.accept(),
        )?;
        let mut middle = std::pin::pin!(Some(async move {
            let _connection = connection;
            std::future::pending::<std::io::Result<TcpStream>>().await
        }));
        let trace = Trace::new(Uuid::new_v4(), "reconnect", "burst", mode);
        trace.attempt(0, "burst");
        trace.stage("anchors_failed");
        let mut signalled = false;
        let offer = async {
            let mut byte = [0];
            assert_eq!(time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??, 0);
            signalled = true;
            Ok(())
        };
        let started = time::Instant::now();
        assert!(finish_native_offer(middle.as_mut(), true, &trace, offer).await?.is_none());
        assert!(signalled && middle.is_none() && started.elapsed() < OPEN_WAIT);
        assert!(trace.native_sampling_failed());
        assert!(trace.snapshot()["attempts"]["0"]["ordered_ports"].as_array().unwrap().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn tcpraw_missing_receipt_keeps_anchors_and_recovers_on_a_new_sender() -> Result<()> {
    let app = crate::tests::app().await?;
    let profile = Profile::create("tcpraw")?;
    let (_, observer, stop, task, _) =
        crate::coordinator::prediction_fixture(app.clone(), &profile, |source| async move { Some(source) }).await?;
    let _stop = stop.clone().drop_guard();
    let observer = ipv4(observer);
    let local = SocketAddrV4::new(LOCAL, socket_port()?);
    let peer = SocketAddr::from((LOCAL, socket_port()?));
    let original = ObservedPath { local, mapped: local, observer };
    let entry = Cache::default().entry(Egress { local: LOCAL, public: LOCAL, interface: 1, observer });
    let trace = Trace::new(Uuid::new_v4(), "reconnect", "burst", "tcpraw");
    let policy = SenderRecovery::default();
    assert!(policy.replacement(original, peer).await?.is_none());
    let old_control = crate::raw::Control::test_probe_control(local.into(), false);
    let punch = RawPunch { mode: "tcpraw", path: original, peer, client: false, fake: None,
        control: Some(&old_control), member: true, trace: &trace, attempt: 0, stop: &stop };
    let failure = punch.candidates(&app.engine, &entry, None, local.port()).await.unwrap_err();
    assert!(failure.is::<MissingSynReceipt>());
    let data = trace.snapshot();
    assert!(data["attempts"]["0"]["p1"].is_number() && data["attempts"]["0"]["p2"].is_number());
    policy.missing_receipt(peer);
    let fresh = policy.replacement(original, peer).await?.unwrap();
    assert_ne!(fresh.local.port(), local.port());
    assert_eq!(fresh.local, fresh.mapped);
    let path = ObservedPath::new(fresh.local, fresh.mapped, fresh.observer).unwrap();
    let control = crate::raw::Control::test_probe_control(fresh.local, true);
    let second = RawPunch { control: Some(&control), path, attempt: 1, ..punch };
    let (ports, complete) = second.candidates(&app.engine, &entry, None, fresh.mapped.port()).await?;
    assert!(complete && ports.contains(&fresh.mapped.port()));
    policy.authenticated(peer);
    assert!(policy.replacement(original, peer).await?.is_none());
    stop.cancel();
    task.await?;
    Ok(())
}

#[tokio::test]
async fn mimic_first_pair_retries_observe_distinct_ports_on_the_same_reflector() -> Result<()> {
    let app = crate::tests::app().await?;
    let profile = Profile::create("mimic")?;
    let (_, observer, stop, task, _) =
        crate::coordinator::prediction_fixture(app, &profile, |source| async move { Some(source) }).await?;
    let _stop = stop.clone().drop_guard();
    let mut local = SocketAddr::from((LOCAL, socket_port()?));
    let mut used = vec![local.port()];
    for _ in 0..5 {
        let observed = crate::raw::ClientObservation::rotated(local, observer, &used).await?;
        assert!(!used.contains(&observed.local.port()));
        assert_eq!(observed.observer, observer);
        assert_eq!(observed.mapped, observed.local);
        let lease = observed.retain_stun().await?;
        assert_eq!(serde_json::to_value(*lease.status().borrow())?["state"], "binding_ok");
        local = observed.local;
        used.push(local.port());
    }
    stop.cancel();
    task.await?;
    Ok(())
}

fn ipv4(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("expected IPv4 loopback"),
    }
}

fn socket_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind((LOCAL, 0))?
        .local_addr()?
        .port())
}

#[tokio::test]
async fn faketcp_tail_waits_for_the_confirmed_middle_syn() -> Result<()> {
    let sent = Mutex::new(Vec::new());
    let timestamp = |label| {
        let mut sent = sent.lock().unwrap();
        sent.push(label);
        sent.len() as u64
    };
    let (first, middle, last) = submit_faketcp_burst(
        || timestamp("anchor1"),
        async {
            time::sleep(Duration::from_millis(20)).await;
            Ok(timestamp("syn"))
        },
        || timestamp("anchor2"),
    ).await?;
    assert!(first <= middle && middle <= last);
    assert_eq!(*sent.lock().unwrap(), ["anchor1", "syn", "anchor2"]);
    let failed = submit_faketcp_burst(|| (), async { anyhow::bail!("driver refused SYN") },
        || panic!("tail must not be sent if the middle SYN failed")).await;
    assert!(failed.is_err());
    Ok(())
}

#[test]
fn mimic_member_allows_delayed_candidates_and_mesh_authentication() {
    let mimic = RawMemberTiming::for_mode("mimic");
    let lag = Duration::from_millis(3500);
    assert!(mimic.offer >= RAW_MEMBER_OFFER_WAIT + lag);
    assert!(mimic.publish > lag && mimic.mesh > lag);
    assert!(mimic.round >= mimic.offer + super::super::RAW_CANDIDATE_HELPER_WAIT + mimic.mesh);
    for mode in ["faketcp", "phantun", "tcpraw"] {
        let timing = RawMemberTiming::for_mode(mode);
        assert_eq!(timing.offer, RAW_MEMBER_OFFER_WAIT);
        assert_eq!(timing.publish, PUBLISH_WAIT);
        assert_eq!(timing.round, if mode == "faketcp" { FAKETCP_MEMBER_WINDOW } else { RAW_MEMBER_WINDOW });
    }
}

#[test]
fn reconnect_counts_only_a_published_or_dialed_candidate_list() {
    let trace = Trace::new(Uuid::new_v4(), "reconnect", "member", "phantun");
    trace.attempt(0, "burst");
    trace.ports(0, &[]);
    trace.stage("offer_published");
    assert!(!trace.used_candidates());

    trace.attempt(1, "dial");
    trace.ports(1, &[42300, 42301]);
    assert!(!trace.used_candidates());
    trace.stage("candidate_connect");
    assert!(trace.used_candidates());
}

#[test]
fn raw_anchor_rounds_keep_the_middle_and_change_both_neighbors() -> Result<()> {
    let middle = SocketAddrV4::new(LOCAL, socket_port()?);
    let egress = Cache::default().entry(Egress {
        observer: SocketAddrV4::new(LOCAL, 3478),
        interface: 1,
        local: LOCAL,
        public: LOCAL,
    });
    let first = egress.reserve_raw_anchors(middle)?.map(|a| a.port());
    let second = egress.reserve_raw_anchors(middle)?.map(|a| a.port());
    assert!(second.iter().all(|p| !first.contains(p) && p.abs_diff(middle.port()) <= 16));
    Ok(())
}

async fn install_peer(
    app: &Arc<crate::backend::App>,
    profile: Profile,
    owner: bool,
) -> Result<Arc<Running>> {
    let mode = profile.pair.mode.clone();
    install_peer_with_listener(app, profile, owner, &mode).await
}

pub(super) async fn install_peer_with_listener(
    app: &Arc<crate::backend::App>, profile: Profile, owner: bool, listener_mode: &str,
) -> Result<Arc<Running>> {
    let mut settings = Settings::default();
    settings.path_selection = format!("{listener_mode}-only");
    settings.discovery_mode = "direct".into();
    settings.listen_port = socket_port()?;
    settings.source_port = socket_port()?;
    while settings.source_port == settings.listen_port {
        settings.source_port = socket_port()?;
    }
    settings.tcp_stun.clear();
    settings.extra.insert(
        "disableGatewayMapping".into(),
        serde_json::Value::Bool(true),
    );
    let network = Network {
        projection: Default::default(),
        legacy_adapter: None,
        id: conwu_core::id(),
        name: "TCP 预测回环".into(),
        configuration_id: conwu_core::id(),
        settings,
        profile: Some(profile),
        enabled: true,
        paused: false,
        created_here: owner,
        created_at: conwu_core::unix_seconds(),
        approved_settings: None,
        peer_name: String::new(),
        pkarr_seed: String::new(),
        pkarr_sequence: 0,
        peer_pkarr: String::new(),
        bootstrap: vec![],
        creation_operation: String::new(),
        creation_digest: String::new(),
    };
    let id = network.id.clone();
    app.engine.install(network).await?;
    app.engine.current(&id).context("回环网络未启动")
}

fn coordinated_config(running: &Running, service: &str) -> Arc<Network> {
    let mut current = running.config.write().unwrap();
    let mut next = current.as_ref().clone();
    next.settings.discovery_mode = "coordinator".into();
    next.settings.service = service.into();
    *current = Arc::new(next);
    current.clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coordinated_tcp_prediction_delivers_authenticated_loopback_traffic() -> Result<()> {
    for mode in ["tcp", "https"] {
        verify_later_stream_candidate(mode).await
            .with_context(|| format!("{mode} 未完成后续候选验证"))?;
    }
    Ok(())
}

async fn verify_later_stream_candidate(mode: &str) -> Result<()> {
    // Reserve the first candidate before either application binds a listener.
    let unavailable = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    unavailable.bind(&SocketAddr::from((LOCAL, 0)).into())?;
    let center = unavailable.local_addr()?.as_socket().context("缺少测试端口")?.port();
    let correct = center.checked_add(2).context("测试端口超出范围")?;
    let predicted = TcpListener::bind((LOCAL, correct)).await?;
    let target = TcpListener::bind((LOCAL, 0)).await?;

    let host = crate::tests::app().await?;
    let client_app = crate::tests::app().await?;
    let mut owner = Profile::create(mode)?;
    if mode == "https" {
        owner.pair.transport_key_pin = Some(host.engine.identity.pin.clone());
    }
    let guest = Profile::import(&owner.issue(None)?.export()?)?;
    let a = install_peer(&host, owner.clone(), true).await?;
    let b = install_peer(&client_app, guest.clone(), false).await?;

    // The two listener halves simulate NAT port forwarding on loopback.
    let b_mapped = ipv4(target.local_addr()?);
    let a_mapped = SocketAddrV4::new(LOCAL, correct);
    let b_local = SocketAddrV4::new(LOCAL, socket_port()?);
    let forward_stop = CancellationToken::new();
    let _forward_guard = forward_stop.clone().drop_guard();
    let stop = forward_stop.clone();
    let forward = tokio::spawn(async move {
        let ((mut left, _), (mut right, source)) =
            tokio::try_join!(target.accept(), predicted.accept())?;
        let result = tokio::select! {
            _ = stop.cancelled() => Ok(()),
            result = tokio::io::copy_bidirectional(&mut left, &mut right) => result.map(|_| ()),
        };
        result.map(|_| source)
    });

    let pending = Arc::new(Mutex::new(
        None::<(SocketAddr, oneshot::Sender<SocketAddr>)>,
    ));
    let stall_anchors = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stall = stall_anchors.clone();
    let (coordinator, observer, stop, server, requests) =
        crate::coordinator::prediction_fixture(host.clone(), &owner, move |remote| {
            let pending = pending.clone();
            let stall = stall.load(Ordering::Relaxed);
            async move {
                if remote == SocketAddr::V4(b_local) {
                    return Some(b_mapped.into());
                }
                if stall { time::sleep(Duration::from_secs(3)).await; return None; }
                // Both anchor replies arrive later than the previous warmup
                // and tail deadlines, even after a successful TCP open.
                time::sleep(Duration::from_millis(470)).await;
                // Wide warmup prebinds the two anchors in local port order.
                // Both orders rank the unavailable candidate ahead of the listener.
                let rx = {
                    let mut pending = pending.lock().unwrap();
                    if let Some((other, tx)) = pending.take() {
                        let (first, second) = if other.port() < remote.port() {
                            (center - 1, center + 1)
                        } else {
                            (center + 1, center - 1)
                        };
                        let _ = tx.send(SocketAddr::new(LOCAL.into(), first));
                        return Some(SocketAddr::new(LOCAL.into(), second));
                    }
                    let (tx, rx) = oneshot::channel();
                    *pending = Some((remote, tx));
                    rx
                };
                rx.await.ok()
            }
        })
        .await?;
    let _stop_guard = stop.clone().drop_guard();
    let address = format!("http://{coordinator}/");
    let client = Client::open(&address, "", false).await?;
    assert_ne!(client.endpoint, observer, "STUN must work on a separate service");
    let observer = ipv4(observer);
    let receiver_observation = discovery::observe_tcp_from(b_local.into(), observer.into()).await?;
    let receiver_observation = tokio::sync::Mutex::new(Some(receiver_observation));
    let a_path = ObservedPath {
        local: SocketAddrV4::new(LOCAL, socket_port()?),
        mapped: a_mapped,
        observer,
    };
    let b_path = ObservedPath {
        local: b_local,
        mapped: b_mapped,
        observer,
    };

    let (x, y) = tokio::try_join!(
        client.member(&owner, a.boot, a_path.mapped.into(), true, true, None),
        client.member(&guest, b.boot, b_path.mapped.into(), true, true, None),
    )?;
    let (
        crate::assistance::Schedule::Ready(round, delay),
        crate::assistance::Schedule::Ready(peer_round, _),
    ) = (
        crate::assistance::Schedule::read(&x.0, x.1)?,
        crate::assistance::Schedule::read(&y.0, y.1)?,
    )
    else {
        anyhow::bail!("回环协调未安排双端轮次")
    };
    ensure!(round == peer_round && x.0["TcpPrediction"] == true && y.0["TcpPrediction"] == true);
    time::sleep(delay).await;

    let cache = Cache::default();
    let egress = cache.entry(Egress::read(a_path).await?);
    let estimate = egress
        .estimate(a_path, &stop, None)
        .await?
        .context("回环热身未识别画像")?;
    assert_eq!(
        estimate.regime,
        NatRegime::Sequential {
            beta: PortCoupling::Independent
        }
    );
    let expected = estimate.candidates(MappingObservation {
        l1: 51000, l_mid: 51001, l2: 51002, p1: center - 1, p2: Some(center + 1),
    });
    assert_eq!(&expected[..2], &[center, correct]);
    let sender_observation = tokio::sync::Mutex::new(None);
    let sender = Session {
        trace: Trace::new(round, "reconnect", "test", mode), components: &host.engine.components,
        client: &client,
        signal: Signal::Member {
            profile: &owner,
            peer: &guest.member,
            boot: a.boot,
        },
        round,
        plan_hash: None,
        path: a_path,
        observation: &sender_observation,
        target: b_mapped,
        stop: &stop,
    };
    let receiver = Session {
        trace: Trace::new(round, "reconnect", "test", mode), components: &client_app.engine.components,
        client: &client,
        signal: Signal::Member {
            profile: &guest,
            peer: &owner.member,
            boot: b.boot,
        },
        round,
        plan_hash: None,
        path: b_path,
        observation: &receiver_observation,
        target: a_mapped,
        stop: &stop,
    };

    let dial_only = Estimate {
        samples: 6, domain: PortDomain::default(), alternate_domain: None,
        regime: if mode == "tcp" { NatRegime::Random }
            else { NatRegime::BoundedRandom { min: 30080, max: 30208 } },
    };
    // A rejected obsolete round cannot contaminate the active role declarations.
    let mut stale = Session { round: Uuid::new_v4(), ..receiver };
    assert!(stale.run(Some(dial_only.clone())).await.is_err());
    stale.round = round;
    let receiver = stale;
    let before = requests.load(Ordering::Relaxed);
    let (left, right) = time::timeout(TEST_WAIT, async {
        tokio::try_join!(sender.run(Some(estimate.clone())), receiver.run(Some(dial_only)))
    })
    .await.with_context(|| format!("未完成预测建连。发送端 {}，回连端 {}", sender.trace.snapshot(), receiver.trace.snapshot()))?
    .context("建立预测 TCP 套接字")?;
    assert!(sender.trace.snapshot()["stages_ms"]["plan_confirmed"].is_number());
    assert!(receiver.trace.snapshot()["stages_ms"]["plan_confirmed"].is_number());
    assert!(requests.load(Ordering::Relaxed) > before);
    let left = left.context("中包套接字未完成接管")?;
    let right = right.context("对端未命中预测候选")?;
    assert_eq!(right.local_addr()?, b_path.local.into());
    assert_eq!(right.peer_addr()?, a_mapped.into());
    let lease = receiver.trace.snapshot()["stun_lease"].clone();
    assert_eq!(lease["state"], "binding_ok");
    // The lease can also complete a keepalive while the candidate is connecting.
    assert!(lease["successful_checks"].as_u64().is_some_and(|count| count >= 1));
    assert_eq!(lease["local"], b_local.to_string());

    let a_config = coordinated_config(&a, &address);
    let b_config = coordinated_config(&b, &address);
    tokio::try_join!(
        host.engine
            .serve_predicted_socket(&a, &a_config, &guest.member, left, None),
        client_app
            .engine
            .serve_predicted_socket(&b, &b_config, &owner.member, right, None),
    )
    .context("把命中候选交给承载层")?;
    time::timeout(TEST_WAIT, async {
        while !a.metrics.read().unwrap().connected || !b.metrics.read().unwrap().connected {
            time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("回环预测尚未完成 MeshLink 路径验证")?;
    let left = crate::tests::packet(owner.local_ip()?, guest.local_ip()?, 0x37);
    let right = crate::tests::packet(guest.local_ip()?, owner.local_ip()?, 0x53);
    a.memory.as_ref().unwrap().inject(left.clone())?;
    b.memory.as_ref().unwrap().inject(right.clone())?;
    time::timeout(TEST_WAIT, async {
        while a.metrics.read().unwrap().received == 0 || b.metrics.read().unwrap().received == 0 {
            time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("回环预测未在两个方向交付业务报文")?;
    assert_eq!(a.memory.as_ref().unwrap().drain(), [right]);
    assert_eq!(b.memory.as_ref().unwrap().drain(), [left]);

    forward_stop.cancel();
    assert_eq!(forward.await?.context("关闭回环转发")?, b_path.local.into());
    // Use the remaining agreed sender slot against a bound, non-listening port.
    stall_anchors.store(true, Ordering::Relaxed);
    let trace = Trace::new(round, "reconnect", "burst", mode);
    trace.attempt(1, "burst");
    let dead = Session { target: SocketAddrV4::new(LOCAL, center), trace: trace.clone(), ..sender };
    match dead.burst(&estimate, 1).await {
        Err(error) => {
            let refused = error.downcast_ref::<std::io::Error>().context("s_mid lost its OS error")?;
            assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
            assert!(refused.raw_os_error().is_some());
        }
        Ok(None) => {
            // Some kernels report refusal only after the anchor deadline.
            // That pending connect must have been abandoned before signaling.
            assert!(trace.native_sampling_failed());
            assert!(trace.snapshot()["stages_ms"]["middle_abandoned_after_anchors"].is_number());
        }
        Ok(Some(_)) => panic!("middle unexpectedly connected to a non-listening port"),
    }
    let offer = receiver.signal(false, None, None, Some(1)).await?.offer.context("missing terminal offer")?;
    assert!(offer.ports.is_empty(), "early failure published live candidates");
    host.engine.shutdown().await?;
    client_app.engine.shutdown().await?;
    stop.cancel();
    server.await?;
    Ok(())
}

#[tokio::test]
async fn egress_changes_discard_the_cached_nat_profile() -> Result<()> {
    let cache = Cache::default();
    let first = Egress {
        observer: SocketAddrV4::new(LOCAL, 3478),
        local: LOCAL,
        public: Ipv4Addr::new(203, 0, 113, 11),
        interface: 1,
    };
    let original = cache.entry(first.clone());
    *original.profile.lock().await = Some(Estimate {
        samples: 6,
        domain: PortDomain::default(),
        alternate_domain: None,
        regime: NatRegime::Random,
    });
    assert!(Arc::ptr_eq(&original, &cache.entry(first.clone())));
    let moved = cache.entry(Egress {
        interface: 2,
        ..first.clone()
    });
    assert!(original.retired.is_cancelled());
    assert!(moved.profile.lock().await.is_none());
    let remapped = cache.entry(Egress {
        interface: 2,
        public: Ipv4Addr::new(203, 0, 113, 12),
        ..first
    });
    assert!(moved.retired.is_cancelled());
    assert!(remapped.profile.lock().await.is_none());
    Ok(())
}

#[test]
fn prediction_budget_distinguishes_regular_phase_shift_and_pba() {
    let observation = MappingObservation {
        l1: 52731,
        l_mid: 52737,
        l2: 52738,
        p1: 25468,
        p2: Some(25476),
    };
    let model = Estimate {
        samples: 6,
        domain: PortDomain::default(),
        alternate_domain: None,
        regime: NatRegime::Strided {
            beta: PortCoupling::Coupled,
            stride: 129,
            residuals: vec![0],
        },
    };
    assert_eq!(model.candidates(observation)[5], 25217);
    assert_eq!(model.candidates(observation).len(), 8);
    assert_eq!(
        model
            .candidates(MappingObservation {
                p2: None,
                ..observation
            })
            .len(),
        4
    );
    let block = Estimate {
        regime: NatRegime::BoundedRandom {
            min: 25472,
            max: 25599,
        },
        ..model
    };
    assert_eq!(block.candidates(observation).len(), 16);
}

#[test]
fn fixed_carrier_port_tests_both_wrap_domains_after_campus_warmup() {
    let mut estimator = NatPortEstimator::default();
    for (l1, l2, p1, p2) in [
        (54031, 54034, 5146, 5536),
        (64142, 64144, 21384, 21515),
        (61689, 61691, 21410, 21799),
        (61693, 61695, 10742, 10873),
        (61708, 61710, 12859, 12990),
        (64530, 64532, 17225, 17098),
    ] {
        estimator.observe(MappingObservation { l1, l_mid: l1 + 1, l2, p1, p2: Some(p2) });
    }
    let regime = estimator.regime().unwrap().clone();
    assert_eq!(regime, NatRegime::Strided {
        beta: PortCoupling::Coupled,
        stride: 129,
        residuals: vec![0],
    });
    let estimate = Estimate {
        samples: 6,
        domain: estimator.domain(),
        alternate_domain: estimator.alternate_domain(),
        regime,
    };
    let candidates = estimate.candidates(MappingObservation {
        l1: 54031, l_mid: 44680, l2: 54034, p1: 5146, p2: Some(5536),
    });
    assert_eq!(&candidates[..4], &[60436, 27668, 60565, 27797]);
    assert_eq!(candidates.len(), 8);
}

#[test]
fn matching_neighbors_remove_false_wrap_candidates_in_the_campus_example() {
    let model = Estimate {
        samples: 6,
        domain: PortDomain::default(),
        alternate_domain: PortDomain::new(1024, 32767),
        regime: NatRegime::Strided {
            beta: PortCoupling::Coupled,
            stride: 129,
            residuals: vec![0, 1],
        },
    };
    let far = MappingObservation { l1: 57241, l_mid: 44680, l2: 57242, p1: 3564, p2: Some(3952) };
    assert_eq!(model.candidates(far), [55644, 22876, 55645, 22877, 55773, 23005, 55774, 23006]);
    let near = MappingObservation { l1: 44679, l_mid: 44680, l2: 44681, p1: 3564, p2: Some(3953) };
    assert_eq!(model.candidates(near), [3694, 3695, 3823, 3824]);
}

#[test]
fn mimic_campus_round_covers_all_five_internal_stride_points_and_their_residuals() {
    let model = Estimate {
        samples: 6, domain: PortDomain::default(), alternate_domain: None,
        regime: NatRegime::Strided { beta: PortCoupling::Coupled, stride: 129, residuals: vec![0, 1] },
    };
    let anchors = MappingObservation { l1: 44679, l_mid: 44680, l2: 44681, p1: 16035, p2: Some(16811) };
    let candidates = model.candidates(anchors);
    assert_eq!(candidates, [16423, 16424, 16552, 16553, 16294, 16295, 16681, 16682, 16165, 16166]);
}
