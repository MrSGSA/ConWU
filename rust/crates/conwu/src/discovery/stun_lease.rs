use super::{TcpAddresses, TcpObservation, observe_tcp_before, stun_tcp};
use serde::Serialize;
use std::{fmt, future::Future, io, net::SocketAddr, time::Duration};
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
    time,
};

pub(super) const BINDING_TIMEOUT: Duration = Duration::from_millis(850);
const REOPEN_TIMEOUT: Duration = Duration::from_millis(1100);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct StunLeaseStatus {
    local: SocketAddr,
    observer: SocketAddr,
    mapped: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_mapping: Option<SocketAddr>,
    state: &'static str,
    successful_checks: u32,
    errno: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reopening_after: Option<&'static str>,
}

impl StunLeaseStatus {
    fn new(path: TcpAddresses) -> Self {
        Self {
            local: path.local,
            observer: path.observer,
            mapped: path.mapped,
            observed_mapping: None,
            state: "checking",
            successful_checks: 0,
            errno: None,
            reopening_after: None,
        }
    }

    fn confirmed(&mut self) {
        self.state = if self.reopening_after.is_some() { "reopened_binding_ok" } else { "binding_ok" };
        self.successful_checks += 1;
    }

    fn failed(&mut self, failure: &StunLeaseLost) {
        self.state = failure.state;
        self.observed_mapping = failure.observed_mapping;
        self.errno = failure
            .error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error);
    }

    fn for_native_dial(mut self) -> Self {
        self.state = match self.state {
            "peer_fin" | "peer_reset" => "closed_by_peer",
            "binding_timeout" => "recheck_timeout",
            state => state,
        };
        self
    }
}

#[derive(Debug)]
pub(crate) struct StunLeaseLost {
    state: &'static str,
    observed_mapping: Option<SocketAddr>,
    error: anyhow::Error,
}

impl StunLeaseLost {
    fn io(error: anyhow::Error) -> Self {
        let state = match error.downcast_ref::<io::Error>().map(io::Error::kind) {
            Some(io::ErrorKind::UnexpectedEof) => "peer_fin",
            Some(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe) => "peer_reset",
            Some(io::ErrorKind::TimedOut) => "binding_timeout",
            _ => "binding_failed",
        };
        Self {
            state,
            observed_mapping: None,
            error,
        }
    }

    fn missing() -> Self {
        Self {
            state: "observation_missing",
            observed_mapping: None,
            error: anyhow::anyhow!("原 TCP STUN 观察连接已不存在"),
        }
    }

    fn mapping_changed(previous: SocketAddr, mapped: SocketAddr) -> Self {
        Self {
            state: "mapping_changed",
            observed_mapping: Some(mapped),
            error: anyhow::anyhow!("STUN 公网端点从 {previous} 变为 {mapped}"),
        }
    }
}

impl fmt::Display for StunLeaseLost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP STUN 连接或映射已失效：{}", self.error)
    }
}

impl std::error::Error for StunLeaseLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

pub(super) async fn verify(observed: &mut TcpObservation) -> Result<(), StunLeaseLost> {
    let mapped = time::timeout(BINDING_TIMEOUT, stun_tcp(&mut observed.stream))
        .await
        .map_err(|_| {
            StunLeaseLost::io(
                io::Error::new(io::ErrorKind::TimedOut, "STUN 保活未收到 Binding 回复").into(),
            )
        })?
        .map_err(StunLeaseLost::io)?;
    if mapped != observed.mapped {
        return Err(StunLeaseLost::mapping_changed(observed.mapped, mapped));
    }
    Ok(())
}

async fn recheck(observed: &mut Option<TcpObservation>) -> Result<(), StunLeaseLost> {
    // A cancelled or failed Binding may leave a partially read frame. In that
    // case discard the stream so discovery can open a fresh observation.
    let mut original = observed.take().ok_or_else(StunLeaseLost::missing)?;
    match verify(&mut original).await {
        Ok(()) => {
            *observed = Some(original);
            Ok(())
        }
        Err(error) => {
            if let Some(mapped) = error.observed_mapping {
                original.mapped = mapped;
                *observed = Some(original);
            }
            Err(error)
        }
    }
}

async fn prepare(
    observed: &mut Option<TcpObservation>,
    expected: TcpAddresses,
    state: &mut StunLeaseStatus,
) -> Result<(), StunLeaseLost> {
    if let Some(actual) = observed.as_ref().map(TcpObservation::addresses) {
        if actual.local != expected.local || actual.observer != expected.observer {
            return Err(StunLeaseLost {
                state: "observation_changed",
                observed_mapping: None,
                error: anyhow::anyhow!("TCP STUN 本地端点或观察器已改变"),
            });
        }
        if actual.mapped != expected.mapped {
            return Err(StunLeaseLost::mapping_changed(expected.mapped, actual.mapped));
        }
    }
    let failure = match recheck(observed).await {
        Ok(()) => return Ok(()),
        Err(failure) if failure.observed_mapping.is_some() => return Err(failure),
        Err(failure) => failure,
    };
    state.reopening_after = Some(failure.state);
    let deadline = time::Instant::now() + REOPEN_TIMEOUT;
    let Ok(fresh) = observe_tcp_before(expected.local, expected.observer, Some(deadline)).await else {
        // Preserve the original FIN/RST or timeout if the replacement failed.
        return Err(failure);
    };
    let mapped = fresh.mapped;
    *observed = Some(fresh);
    if mapped != expected.mapped {
        return Err(StunLeaseLost::mapping_changed(expected.mapped, mapped));
    }
    Ok(())
}

async fn keepalive(
    observed: &mut Option<TcpObservation>,
    mut state: StunLeaseStatus,
    report: impl Fn(StunLeaseStatus),
) -> StunLeaseLost {
    let failure = loop {
        let Some(original) = observed.as_mut() else {
            break StunLeaseLost::missing();
        };
        let mut byte = [0];
        tokio::select! {
            // Peek catches a FIN or RST even before the next Binding request.
            read = original.stream.peek(&mut byte) => {
                let error = match read {
                    Ok(0) => io::Error::new(io::ErrorKind::UnexpectedEof, "STUN 服务端已关闭连接"),
                    Ok(_) => io::Error::new(io::ErrorKind::InvalidData, "STUN 控制连接收到非预期数据"),
                    Err(error) => error,
                };
                break StunLeaseLost::io(error.into());
            }
            _ = time::sleep(KEEPALIVE_INTERVAL) => {}
        }
        state.state = "checking";
        report(state);
        if let Err(error) = recheck(observed).await {
            break error;
        }
        state.confirmed();
        report(state);
    };
    if failure.observed_mapping.is_none() {
        drop(observed.take());
    }
    state.failed(&failure);
    report(state);
    failure
}

pub(crate) struct StunLease {
    status: watch::Receiver<StunLeaseStatus>,
    worker: Option<JoinHandle<StunLeaseLost>>,
    best_effort: bool,
}

impl StunLease {
    pub(crate) async fn start(observed: TcpObservation, best_effort: bool) -> Result<Self, StunLeaseLost> {
        // Recheck after starting the same-port receiver and before signalling Ready.
        let expected = observed.addresses();
        let mut state = StunLeaseStatus::new(expected);
        let mut observed = Some(observed);
        if let Err(error) = prepare(&mut observed, expected, &mut state).await {
            if !best_effort || !matches!(error.state, "peer_fin" | "peer_reset" | "binding_timeout") {
                return Err(error);
            }
            state.failed(&error);
            let (_, status) = watch::channel(state.for_native_dial());
            return Ok(Self { status, worker: None, best_effort });
        }
        state.confirmed();
        let (updates, status) = watch::channel(state);
        let worker = tokio::spawn(async move {
            keepalive(&mut observed, state, |state| {
                updates.send_replace(if best_effort { state.for_native_dial() } else { state });
            })
            .await
        });
        Ok(Self { status, worker: Some(worker), best_effort })
    }

    pub(crate) async fn during<T, Ready, Run>(
        observations: &Mutex<Option<TcpObservation>>,
        expected: TcpAddresses,
        ready_by: time::Instant,
        report: impl Fn(StunLeaseStatus),
        ready: impl Future<Output = anyhow::Result<Ready>>,
        operation: impl FnOnce(Ready) -> Run,
    ) -> anyhow::Result<T>
    where
        Run: Future<Output = anyhow::Result<T>>,
    {
        let check = async {
            let mut state = StunLeaseStatus::new(expected);
            report(state);
            let prepared = time::timeout_at(ready_by, async {
                // Discovery shares this source port and observation with the round.
                let mut observed = observations.lock().await;
                prepare(&mut observed, expected, &mut state).await?;
                Ok(observed)
            })
                .await
                .unwrap_or_else(|_| {
                    Err(StunLeaseLost::io(
                        io::Error::new(io::ErrorKind::TimedOut, "在候选等待窗口内未完成 STUN 复查")
                            .into(),
                    ))
                });
            match prepared {
                Ok(observed) => {
                    state.confirmed();
                    report(state);
                    Ok::<_, anyhow::Error>(Some((observed, state)))
                }
                Err(error) => {
                    state.failed(&error);
                    report(state.for_native_dial());
                    if error.observed_mapping.is_some() || error.state == "observation_changed" {
                        return Err(error.into());
                    }
                    Ok(None)
                }
            }
        };
        // Keep candidate signalling and Binding verification in the same
        // wait window. Short-lived observers can leave a usable mapping.
        let (lease, ready) = tokio::try_join!(check, ready)?;
        let operation = operation(ready);
        let Some((mut observed, state)) = lease else {
            return operation.await;
        };
        tokio::pin!(operation);
        tokio::select! {
            biased;
            error = keepalive(&mut observed, state, |status| report(status.for_native_dial())) => {
                if error.observed_mapping.is_some() {
                    return Err(error.into());
                }
                drop(observed);
                operation.await
            }
            result = &mut operation => result,
        }
    }

    pub(crate) fn status(&self) -> watch::Receiver<StunLeaseStatus> {
        self.status.clone()
    }

    pub(crate) async fn lost(lease: &mut Option<Self>) -> anyhow::Error {
        let Some(lease) = lease.as_mut() else {
            return std::future::pending().await;
        };
        let Some(worker) = lease.worker.as_mut() else {
            return std::future::pending().await;
        };
        let result = worker.await;
        // This future participates in several selects. Take its completed
        // JoinHandle before waiting on any subsequent handshake phase.
        lease.worker.take();
        match result {
            Ok(error) if lease.best_effort && matches!(error.state, "peer_fin" | "peer_reset" | "binding_timeout") => std::future::pending().await,
            Ok(error) => error.into(),
            Err(error) => anyhow::Error::new(error).context("STUN 保活任务异常退出"),
        }
    }
}

impl Drop for StunLease {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conwu_core::nat_tcp_punch::handover::{DialOptions, dial_candidates};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };
    use tokio_util::sync::CancellationToken;

    async fn reflect(stream: &mut TcpStream, port: u16) -> io::Result<()> {
        let mut request = [0; 20];
        stream.read_exact(&mut request).await?;
        request[..4].copy_from_slice(&[1, 1, 0, 12]);
        stream.write_all(&request).await?;
        let [high, low] = port.to_be_bytes();
        stream
            .write_all(&[0, 1, 0, 8, 0, 1, high, low, 127, 0, 0, 1])
            .await
    }

    #[tokio::test]
    async fn half_open_recheck_uses_a_fresh_connection_and_rejects_a_changed_mapping() -> anyhow::Result<()> {
        for port in [42000, 42001] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let server = listener.local_addr()?;
            let (done, hold) = oneshot::channel();
            let task = tokio::spawn(async move {
                let (mut original, source) = listener.accept().await?;
                reflect(&mut original, 42000).await?;
                let mut second = [0; 20];
                original.read_exact(&mut second).await?;
                let (mut reopened, new_source) = listener.accept().await?;
                assert_eq!(new_source, source);
                reflect(&mut reopened, port).await?;
                let _ = hold.await;
                Ok::<_, io::Error>(())
            });
            let observed = observe_tcp_before("127.0.0.1:0".parse()?, server, None).await?;
            let expected = observed.addresses();
            let slot = Mutex::new(Some(observed));
            let status = std::cell::Cell::new(StunLeaseStatus::new(expected));
            let result = StunLease::during(&slot, expected, time::Instant::now() + Duration::from_secs(3),
                |update| status.set(update), async { Ok(()) }, |()| async { Ok(()) }).await;
            assert_eq!(status.get().reopening_after, Some("binding_timeout"));
            assert_eq!(slot.lock().await.as_ref().unwrap().mapped.port(), port);
            if port == 42000 {
                result?;
                assert_eq!(status.get().state, "reopened_binding_ok");
            } else {
                assert!(result.unwrap_err().is::<StunLeaseLost>());
                assert_eq!(status.get().state, "mapping_changed");
            }
            let _ = done.send(());
            task.await??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn one_shot_observer_is_rejected_before_ready() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = listener.local_addr()?;
        let (done, keep_open) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            reflect(&mut stream, 42000).await?;
            stream.shutdown().await?;
            // Keep the read half alive to test FIN without triggering a reset.
            let _ = keep_open.await;
            Ok::<_, io::Error>(())
        });
        let observed = crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
        let error = StunLease::start(observed, false)
            .await
            .err()
            .expect("a closed observer is not ready");
        assert_eq!(error.state, "peer_fin");
        let _ = done.send(());
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn raw_pairing_accepts_a_one_shot_observer_with_a_known_mapping() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = listener.local_addr()?;
        let (done, keep_open) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            reflect(&mut stream, 42000).await?;
            stream.shutdown().await?;
            let _ = keep_open.await;
            Ok::<_, io::Error>(())
        });
        let observed = crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
        let mut lease = Some(StunLease::start(observed, true).await?);
        assert_eq!(lease.as_ref().unwrap().status().borrow().state, "closed_by_peer");
        assert!(time::timeout(Duration::from_millis(40), StunLease::lost(&mut lease)).await.is_err());
        let _ = done.send(());
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn pairing_lease_keeps_same_stream_and_reports_mapping_drift() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            for port in [42000, 42000, 42000, 42001] {
                reflect(&mut stream, port).await?;
            }
            Ok::<_, io::Error>(())
        });
        let observed = crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
        let lease = StunLease::start(observed, false).await?;
        let status = lease.status();
        assert_eq!(status.borrow().successful_checks, 1);
        let mut lease = Some(lease);
        let error = time::timeout(Duration::from_secs(15), StunLease::lost(&mut lease)).await?;
        assert!(error.is::<StunLeaseLost>());
        assert_eq!(status.borrow().state, "mapping_changed");
        assert_eq!(status.borrow().successful_checks, 2);
        assert_eq!(status.borrow().mapped.port(), 42000);
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn pairing_lease_detects_rst_between_binding_requests() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = listener.local_addr()?;
        let (reset, allow_reset) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            reflect(&mut stream, 42000).await?;
            reflect(&mut stream, 42000).await?;
            let _ = allow_reset.await;
            socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))
        });
        let observed = crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
        let lease = StunLease::start(observed, false).await?;
        let status = lease.status();
        let mut lease = Some(lease);
        reset.send(()).unwrap();
        let error = time::timeout(Duration::from_secs(3), StunLease::lost(&mut lease)).await?;
        assert!(error.is::<StunLeaseLost>());
        assert_eq!(status.borrow().state, "peer_reset");
        assert!(status.borrow().errno.is_some());
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn native_dial_rechecks_and_keeps_the_original_stun_connection() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            // Initial observation, pre-dial recheck, keepalive and discovery reuse.
            for _ in 0..4 {
                reflect(&mut stream, 42000).await?;
            }
            Ok::<_, io::Error>(())
        });
        let observed = crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
        let expected = observed.addresses();
        let slot = Mutex::new(Some(observed));
        let (updates, mut status) = watch::channel(StunLeaseStatus::new(expected));
        time::timeout(
            Duration::from_secs(10),
            StunLease::during(
                &slot,
                expected,
                time::Instant::now() + BINDING_TIMEOUT,
                |state| {
                    updates.send_replace(state);
                },
                async { Ok(()) },
                |()| async {
                    status
                        .wait_for(|state| state.successful_checks == 2)
                        .await?;
                    Ok(())
                },
            ),
        )
        .await??;
        assert_eq!(status.borrow().state, "binding_ok");
        assert_eq!(status.borrow().local, expected.local);
        recheck(&mut *slot.lock().await).await?;
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn native_dial_rejects_a_changed_stun_mapping_before_connect() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            reflect(&mut stream, 42000).await?;
            reflect(&mut stream, 42001).await
        });
        let observed = crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
        let expected = observed.addresses();
        let slot = Mutex::new(Some(observed));
        let status = std::cell::Cell::new(StunLeaseStatus::new(expected));
        let result: anyhow::Result<()> = StunLease::during(
            &slot,
            expected,
            time::Instant::now() + BINDING_TIMEOUT,
            |state| status.set(state),
            async { Ok(()) },
            |()| async { panic!("stale mapping reached dial") },
        )
        .await;
        assert!(result.unwrap_err().is::<StunLeaseLost>());
        assert_eq!(status.get().state, "mapping_changed");
        assert_eq!(status.get().observed_mapping.unwrap().port(), 42001);
        assert_eq!(slot.lock().await.as_ref().unwrap().mapped.port(), 42001);
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn native_dial_keeps_its_source_port_after_recheck_reset_or_timeout() -> anyhow::Result<()>
    {
        for reset in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let peer = TcpListener::bind("127.0.0.1:0").await?;
            let target = peer.local_addr()?;
            let server = listener.local_addr()?;
            let (offer_seen, receiving_offer) = oneshot::channel();
            let (done, hold) = oneshot::channel();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                reflect(&mut stream, 42000).await?;
                let mut request = [0; 20];
                stream.read_exact(&mut request).await?;
                let _ = receiving_offer.await;
                if reset {
                    socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
                } else {
                    let _ = hold.await;
                }
                Ok::<_, io::Error>(())
            });
            let observed =
                crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
            let expected = observed.addresses();
            let slot = Mutex::new(Some(observed));
            let status = std::cell::Cell::new(StunLeaseStatus::new(expected));
            let stream = time::timeout(
                Duration::from_secs(10),
                StunLease::during(
                    &slot,
                    expected,
                    time::Instant::now() + Duration::from_secs(4),
                    |state| status.set(state),
                    async {
                        let _ = offer_seen.send(());
                        Ok(target.port())
                    },
                    |port| async move {
                        let stream = dial_candidates(
                            &[port],
                            target.ip(),
                            expected.local,
                            DialOptions {
                                reuse_address: true,
                                ..Default::default()
                            },
                            &CancellationToken::new(),
                        )
                        .await?;
                        Ok(stream)
                    },
                ),
            )
            .await??;
            assert_eq!(stream.local_addr()?, expected.local);
            let (_, from_peer) = time::timeout(Duration::from_secs(2), peer.accept()).await??;
            assert_eq!(from_peer, expected.local);
            let outcome = status.get();
            assert_eq!(
                outcome.state,
                if reset {
                    "closed_by_peer"
                } else {
                    "recheck_timeout"
                }
            );
            assert_eq!(outcome.errno.is_some(), reset);
            #[cfg(windows)]
            if reset {
                assert_eq!(outcome.errno, Some(10054));
            }
            assert_eq!(outcome.successful_checks, 0);
            assert!(slot.lock().await.is_none());
            let _ = done.send(());
            task.await??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn native_dial_continues_after_stun_fin_or_reset_during_keepalive() -> anyhow::Result<()>
    {
        for reset in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let server = listener.local_addr()?;
            let (dialing, dial_started) = oneshot::channel();
            let (done, hold) = oneshot::channel();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                reflect(&mut stream, 42000).await?;
                reflect(&mut stream, 42000).await?;
                dial_started.await.unwrap();
                if reset {
                    socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
                } else {
                    stream.shutdown().await?;
                    let _ = hold.await;
                }
                Ok::<_, io::Error>(())
            });
            let observed =
                crate::discovery::observe_tcp_from("127.0.0.1:0".parse()?, server).await?;
            let expected = observed.addresses();
            let slot = Mutex::new(Some(observed));
            let (updates, mut status) = watch::channel(StunLeaseStatus::new(expected));
            time::timeout(
                Duration::from_secs(5),
                StunLease::during(
                    &slot,
                    expected,
                    time::Instant::now() + BINDING_TIMEOUT,
                    |state| {
                        updates.send_replace(state);
                    },
                    async { Ok(()) },
                    |()| async {
                        dialing.send(()).unwrap();
                        status
                            .wait_for(|state| state.state == "closed_by_peer")
                            .await?;
                        Ok(())
                    },
                ),
            )
            .await??;
            let outcome = *status.borrow();
            assert_eq!(outcome.state, "closed_by_peer");
            assert_eq!(outcome.errno.is_some(), reset);
            assert_eq!(outcome.successful_checks, 1);
            assert!(slot.lock().await.is_none());
            let _ = done.send(());
            task.await??;
        }
        Ok(())
    }
}
