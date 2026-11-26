use crate::runtime::remote_member;
use conwu_core::{identity::Profile, metadata::Snapshot};
use std::{net::SocketAddr, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const RETRY_DELAYS: [u64; 5] = [2, 4, 8, 15, 15];
const RESAMPLE_DELAY: u64 = 2;
const BACKGROUND_RETRY_DELAY: u64 = 15;
const NATIVE_RESAMPLE_DELAYS: [u64; 5] = [2, 4, 4, 8, 15];

#[derive(Clone, Copy, Debug)]
pub(super) enum RoundOutcome {
    Connected,
    CandidatesTried,
    Resample,
    NativeResample,
    RawTimedOut,
}

#[derive(PartialEq, Eq)]
pub(super) struct PeerPresence {
    revision: i64,
    device: String,
    boot: Option<Uuid>,
    endpoints: Vec<SocketAddr>,
    paused: bool,
}

impl PeerPresence {
    pub(super) fn read(profile: &Profile, snapshot: &Snapshot) -> Option<Self> {
        conwu_core::metadata::successor(&snapshot.directory, profile.directory.as_ref()?).ok()?;
        let peer = remote_member(profile)?;
        if !snapshot.directory.members.contains(&peer) {
            return None;
        }
        let envelope = snapshot.nodes.iter().find(|node| node.slot == peer.slot && node.device == peer.device)?;
        let announcement = envelope.open(profile, &peer).ok()?;
        let mut endpoints: Vec<_> = announcement.existing_endpoints.into_iter().flatten()
            .chain([announcement.endpoint]).filter_map(|endpoint| endpoint.parse().ok()).collect();
        endpoints.sort_unstable();
        endpoints.dedup();
        Some(Self { revision: envelope.revision, device: peer.device, boot: announcement.boot_id,
            endpoints, paused: announcement.connection_paused })
    }
}

pub(super) struct Reconnect {
    peer: Option<PeerPresence>,
    epoch: CancellationToken,
    failures: usize,
    due: Instant,
    round: Option<Uuid>,
    finished: Option<Uuid>,
    native_resamples: usize,
    fast_native_poll: bool,
    private_raw: bool,
    retire_raw_listener: bool,
}

impl Default for Reconnect {
    fn default() -> Self {
        Self { peer: None, epoch: CancellationToken::new(), failures: 0,
            due: Instant::now(), round: None, finished: None, native_resamples: 0,
            fast_native_poll: false, private_raw: false, retire_raw_listener: false }
    }
}

impl Reconnect {
    pub(super) fn reset(&mut self) {
        self.epoch.cancel();
        self.epoch = CancellationToken::new();
        self.failures = 0;
        self.due = Instant::now();
        self.round = None;
        self.finished = None;
        self.native_resamples = 0;
        self.fast_native_poll = false;
        self.private_raw = false;
        self.retire_raw_listener = false;
    }

    /// Return whether to wake discovery and whether the prior link is stale.
    pub(super) fn update_peer(&mut self, next: PeerPresence) -> (bool, bool) {
        if self.peer.as_ref().is_some_and(|peer| peer.device == next.device && next.revision <= peer.revision) {
            return (false, false);
        }
        let restarted = self.peer.as_ref().is_some_and(|peer| peer.device == next.device
            && peer.boot.is_some() && next.boot.is_some() && peer.boot != next.boot);
        let changed = self.peer.as_ref().is_none_or(|peer| peer.device != next.device || peer.boot != next.boot
            || peer.endpoints != next.endpoints || peer.paused != next.paused);
        self.peer = Some(next);
        if changed { self.reset(); }
        (changed, restarted)
    }

    pub(super) fn delay(&self) -> Duration {
        self.due.saturating_duration_since(Instant::now())
    }

    pub(super) fn report(&self) -> (CancellationToken, Option<Uuid>) {
        (self.epoch.child_token(), self.finished)
    }

    pub(super) fn fast_native_poll(&self) -> Option<Duration> {
        self.fast_native_poll.then(|| self.delay())
    }

    pub(super) fn take_fast_native_poll(&mut self) -> bool {
        self.delay().is_zero() && std::mem::take(&mut self.fast_native_poll)
    }

    pub(super) fn private_raw(&self) -> bool { self.private_raw }
    pub(super) fn retiring_raw_listener(&self) -> bool { self.retire_raw_listener }
    pub(super) fn retire_raw_listener(&mut self, needed: bool) { self.retire_raw_listener = needed; }

    pub(super) fn begin(&mut self, round: Uuid, peer_boot: Option<Uuid>, request: &CancellationToken) -> bool {
        if request.is_cancelled() || !self.delay().is_zero() || self.round == Some(round)
            || self.peer.as_ref().is_some_and(|peer| peer.paused
                || peer.boot.is_some() && peer_boot.is_some() && peer.boot != peer_boot)
        {
            return false;
        }
        self.round = Some(round);
        true
    }

    pub(super) fn complete(&mut self, round: Uuid, request: &CancellationToken, outcome: RoundOutcome) {
        if request.is_cancelled() || self.round != Some(round) { return; }
        self.finished = Some(round);
        self.fast_native_poll = false;
        if !matches!(outcome, RoundOutcome::NativeResample) {
            self.native_resamples = 0;
        }
        if matches!(outcome, RoundOutcome::RawTimedOut) && !self.private_raw {
            self.private_raw = true;
            self.retire_raw_listener = true;
        }
        let delay = match outcome {
            RoundOutcome::Connected => { self.connected(); return; }
            RoundOutcome::NativeResample => {
                let delay = NATIVE_RESAMPLE_DELAYS.get(self.native_resamples).copied().unwrap_or(BACKGROUND_RETRY_DELAY);
                self.native_resamples = (self.native_resamples + 1).min(NATIVE_RESAMPLE_DELAYS.len());
                self.fast_native_poll = delay <= 4;
                delay
            }
            RoundOutcome::CandidatesTried | RoundOutcome::RawTimedOut if self.failures < RETRY_DELAYS.len() => {
                let delay = RETRY_DELAYS[self.failures];
                self.failures += 1;
                delay
            }
            _ if self.failures >= RETRY_DELAYS.len() => BACKGROUND_RETRY_DELAY,
            RoundOutcome::Resample => RESAMPLE_DELAY,
            RoundOutcome::CandidatesTried | RoundOutcome::RawTimedOut => BACKGROUND_RETRY_DELAY,
        };
        self.due = Instant::now() + Duration::from_secs(delay);
        tracing::debug!(%round, ?outcome, effective_rounds = self.failures, delay, "成员重连轮次结束");
    }

    pub(super) fn connected(&mut self) {
        self.failures = 0;
        self.native_resamples = 0;
        self.fast_native_poll = false;
        self.private_raw = false;
        self.retire_raw_listener = false;
        self.due = Instant::now();
        if self.round.is_some() { self.finished = self.round; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tcp_prediction::diagnostics::Trace;

    fn presence(revision: i64, boot: Uuid, port: u16) -> PeerPresence {
        PeerPresence { revision, device: "peer".into(), boot: Some(boot),
            endpoints: vec![SocketAddr::from(([127,0,0,1], port))], paused: false }
    }

    #[tokio::test]
    async fn resumes_with_backoff_and_resets_on_endpoint_or_boot_change() {
        let mut reconnect = Reconnect::default();
        let boot = Uuid::new_v4();
        assert_eq!(reconnect.update_peer(presence(1, boot, 41000)), (true, false));
        for (index, delay) in [2, 4, 8, 15, 15, 15].into_iter().enumerate() {
            let round = Uuid::new_v4();
            let (request, _) = reconnect.report();
            assert!(reconnect.begin(round, Some(boot), &request));
            reconnect.complete(round, &request, RoundOutcome::CandidatesTried);
            assert_eq!(reconnect.failures, (index + 1).min(5));
            assert_eq!(reconnect.report().1, Some(round));
            assert!(reconnect.delay().as_secs_f64() > delay as f64 - 0.1);
            assert!(!reconnect.begin(Uuid::new_v4(), Some(boot), &request));
            reconnect.due = Instant::now();
        }
        let (prior, _) = reconnect.report();
        assert_eq!(reconnect.update_peer(presence(2, boot, 41001)), (true, false));
        assert!(prior.is_cancelled());
        assert_eq!(reconnect.failures, 0);
        assert!(reconnect.report().1.is_none());
        assert_eq!(reconnect.update_peer(presence(1, boot, 41000)), (false, false));
        let next = Uuid::new_v4();
        assert_eq!(reconnect.update_peer(presence(3, next, 41001)), (true, true));
        let (request, _) = reconnect.report();
        assert!(!reconnect.begin(Uuid::new_v4(), Some(boot), &request));
        assert!(reconnect.begin(Uuid::new_v4(), Some(next), &request));
    }

    #[tokio::test]
    async fn missing_anchors_do_not_spend_the_five_effective_rounds() {
        let mut reconnect = Reconnect::default();
        for round_number in 0..5 {
            let missing = Uuid::new_v4();
            let (request, _) = reconnect.report();
            assert!(reconnect.begin(missing, None, &request));
            reconnect.complete(missing, &request, RoundOutcome::Resample);
            assert_eq!(reconnect.report().1, Some(missing));
            assert_eq!(reconnect.failures, round_number);
            assert!(reconnect.delay().as_secs_f64() > 1.9);
            assert!(reconnect.delay() <= Duration::from_secs(2));
            reconnect.due = Instant::now();
            let effective = Uuid::new_v4();
            assert!(reconnect.begin(effective, None, &request));
            reconnect.complete(effective, &request, RoundOutcome::CandidatesTried);
            assert_eq!(reconnect.failures, round_number + 1);
            reconnect.due = Instant::now();
        }
    }

    #[tokio::test]
    async fn native_anchor_failure_and_empty_offer_use_the_same_short_then_capped_backoff() {
        for mode in ["tcp", "https"] {
            let (mut sender, mut dialer) = (Reconnect::default(), Reconnect::default());
            for expected in [2, 4, 4, 8, 15, 15] {
                let round = Uuid::new_v4();
                for (side, role, reason) in [
                    (&mut sender, "burst", "anchors_failed"), (&mut dialer, "dial", "empty_offer"),
                ] {
                    let (request, _) = side.report();
                    assert!(side.begin(round, None, &request));
                    let trace = Trace::new(round, "reconnect", role, mode);
                    trace.attempt(0, role);
                    if role == "burst" { trace.stage("middle_abandoned_after_anchors"); }
                    trace.close(reason);
                    assert!(trace.native_sampling_failed());
                    side.complete(round, &request, RoundOutcome::NativeResample);
                    assert_eq!(side.report().1, Some(round));
                    assert_eq!(side.failures, 0);
                    assert!(side.delay() <= Duration::from_secs(expected));
                    assert!(side.delay() >= Duration::from_millis(expected * 1000 - 250));
                    assert_eq!(side.fast_native_poll().is_some(), expected <= 4);
                    assert!(!side.begin(Uuid::new_v4(), None, &request));
                    side.due = Instant::now();
                    assert_eq!(side.take_fast_native_poll(), expected <= 4);
                    assert!(!side.take_fast_native_poll());
                }
            }
        }
    }
}
