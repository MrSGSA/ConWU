//! A round only accepts typed addresses, numeric observations and source-defined labels.
//! The journal stores this object separately from its short human-readable message.
use super::{BurstTiming, Estimate, MappingObservation};
use crate::{discovery::StunLeaseStatus, runtime::Event};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

pub(crate) fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Default, Serialize)]
pub(crate) struct Attempt {
    role: &'static str,
    stages_ms: BTreeMap<&'static str, i64>,
    outcome: Option<&'static str>,
    l1: Option<u16>,
    l_mid: Option<u16>,
    l2: Option<u16>,
    p1: Option<u16>,
    p2: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    burst_times_us: Option<[i64; 3]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    burst_alpha: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    k_span: Option<usize>,
    ordered_ports: Vec<u16>,
    packets_from: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_capture: Option<NetworkCapture>,
    pub(super) sockets: Vec<Tuple>,
}

#[derive(Serialize)]
struct NetworkCapture {
    layer: &'static str,
    ingress_open: bool,
    egress_open: bool,
    packets: Vec<ObservedPacket>,
}

#[derive(Serialize)]
struct ObservedPacket {
    local: SocketAddr,
    remote: SocketAddr,
    stage: &'static str,
    elapsed_ms: i64,
    interface: Option<u32>,
    expected_ip: bool,
}

#[derive(Serialize)]
pub(super) struct Tuple {
    local: SocketAddr,
    remote: SocketAddr,
    protocol: &'static str,
    times_ms: BTreeMap<&'static str, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    driver_injected_bytes: BTreeMap<&'static str, u32>,
    errno: Option<i32>,
    error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_source: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct Summary {
    pub(crate) round: Uuid,
    pub(crate) flow: &'static str,
    transport: String,
    role: &'static str,
    regime: Option<String>,
    valid_samples: usize,
    profile_source: &'static str,
    start_unix_ms: i64,
    elapsed_ms: i64,
    stages_ms: BTreeMap<&'static str, i64>,
    pub(crate) last_stage: &'static str,
    pub(crate) close_reason: &'static str,
    errno: Option<i32>,
    error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_source: Option<&'static str>,
    attempts: BTreeMap<usize, Attempt>,
    stun_lease: Option<StunLeaseStatus>,
}

#[derive(Clone)]
pub(crate) struct Trace {
    start: Instant,
    inner: Arc<Mutex<Summary>>,
}

impl Trace {
    pub(crate) fn new(round: Uuid, flow: &'static str, role: &'static str, mode: &str) -> Self {
        Self {
            start: Instant::now(),
            inner: Arc::new(Mutex::new(Summary {
                round,
                flow,
                role,
                transport: mode.to_owned(),
                regime: None,
                valid_samples: 0,
                profile_source: "not_sampled",
                start_unix_ms: unix_ms(),
                elapsed_ms: 0,
                stages_ms: Default::default(),
                last_stage: "start",
                close_reason: "cancelled",
                errno: None,
                error_kind: None,
                error_source: None,
                attempts: Default::default(),
                stun_lease: None,
            })),
        }
    }
    pub(crate) fn elapsed(&self) -> i64 {
        self.start.elapsed().as_millis() as i64
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> serde_json::Value {
        serde_json::to_value(&*self.inner.lock().unwrap()).expect("serializable round")
    }
    pub(crate) fn set_round(&self, round: Uuid) {
        self.inner.lock().unwrap().round = round;
    }
    pub(super) fn round(&self) -> Uuid {
        self.inner.lock().unwrap().round
    }
    pub(super) fn started_unix_ms(&self) -> i64 {
        self.inner.lock().unwrap().start_unix_ms
    }
    pub(crate) fn stage(&self, stage: &'static str) {
        let mut data = self.inner.lock().unwrap();
        let ms = self.elapsed();
        data.stages_ms.entry(stage).or_insert(ms);
        if let Some(attempt) = data.attempts.values_mut().next_back() {
            attempt.stages_ms.entry(stage).or_insert(ms);
        }
        data.last_stage = stage;
    }
    pub(crate) fn close(&self, reason: &'static str) {
        let mut data = self.inner.lock().unwrap();
        data.close_reason = reason;
        if let Some(a) = data.attempts.values_mut().next_back() {
            a.outcome = Some(reason);
        }
    }
    pub(crate) fn error(&self, err: &anyhow::Error) {
        if let Some(e) = err.chain().find_map(|e| e.downcast_ref::<io::Error>()) {
            let mut data = self.inner.lock().unwrap();
            data.errno = e.raw_os_error();
            data.error_kind = Some(format!("{:?}", e.kind()));
            data.error_source = Some(error_source(e));
        }
    }
    pub(crate) fn stun_lease(&self, status: StunLeaseStatus) {
        self.inner.lock().unwrap().stun_lease = Some(status);
    }
    pub(super) fn profile(
        &self,
        estimate: Option<&Estimate>,
        samples: usize,
        source: &'static str,
    ) {
        let mut data = self.inner.lock().unwrap();
        data.regime = estimate.map(|e| format!("{:?}", e.regime));
        data.valid_samples = samples;
        data.profile_source = source;
    }
    pub(crate) fn attempt(&self, n: usize, role: &'static str) {
        self.inner
            .lock()
            .unwrap()
            .attempts
            .entry(n)
            .or_default()
            .role = role;
    }
    pub(super) fn anchors(&self, n: usize, o: MappingObservation) {
        let mut data = self.inner.lock().unwrap();
        let a = data.attempts.entry(n).or_default();
        a.p1 = Some(o.p1);
        a.p2 = o.p2;
    }
    pub(super) fn burst_timing(&self, n: usize, timing: BurstTiming, span: Option<usize>) {
        let mut data = self.inner.lock().unwrap();
        let a = data.attempts.entry(n).or_default();
        let first = timing.first_us as i64;
        a.burst_times_us = Some([0, timing.middle_us as i64 - first, timing.last_us as i64 - first]);
        a.burst_alpha = timing.alpha();
        a.k_span = span;
    }
    pub(super) fn local_ports(&self, n: usize, (l1, l_mid, l2): (u16, u16, u16)) {
        let mut data = self.inner.lock().unwrap();
        let a = data.attempts.entry(n).or_default();
        a.l1 = Some(l1);
        a.l_mid = Some(l_mid);
        a.l2 = Some(l2);
    }
    pub(crate) fn ports(&self, n: usize, ports: &[u16]) {
        self.inner
            .lock()
            .unwrap()
            .attempts
            .entry(n)
            .or_default()
            .ordered_ports = ports.to_vec();
    }

    pub(in crate::runtime) fn used_candidates(&self) -> bool {
        self.inner.lock().unwrap().attempts.values().any(|attempt|
            !attempt.ordered_ports.is_empty()
                && (attempt.stages_ms.contains_key("offer_published") || attempt.stages_ms.contains_key("candidate_connect")))
    }
    pub(in crate::runtime) fn native_sampling_failed(&self) -> bool {
        let data = self.inner.lock().unwrap();
        data.flow == "reconnect" && matches!(data.transport.as_str(), "tcp" | "https")
            && (data.stages_ms.contains_key("middle_abandoned_after_anchors")
                || data.stages_ms.contains_key("middle_finished_with_failed_anchors") || data.close_reason == "empty_offer")
            && data.attempts.values().all(|attempt| attempt.ordered_ports.is_empty())
    }

    pub(in crate::runtime) fn raw_reconnect_timed_out(&self) -> bool {
        self.inner.lock().unwrap().close_reason == "raw_reconnect_timeout"
    }
    pub(crate) fn source(&self, n: usize, source: &'static str) {
        self.inner
            .lock()
            .unwrap()
            .attempts
            .entry(n)
            .or_default()
            .packets_from = Some(source);
    }
    pub(crate) fn socket(
        &self,
        n: usize,
        local: SocketAddr,
        remote: SocketAddr,
        stage: &'static str,
        err: Option<&io::Error>,
    ) {
        self.at(n, local, remote, stage, self.elapsed(), err, None)
    }
    pub(crate) fn at(
        &self,
        n: usize,
        local: SocketAddr,
        remote: SocketAddr,
        stage: &'static str,
        ms: i64,
        err: Option<&io::Error>,
        injected: Option<u32>,
    ) {
        let mut data = self.inner.lock().unwrap();
        let sockets = &mut data.attempts.entry(n).or_default().sockets;
        let i = match sockets
            .iter()
            .position(|s| s.local == local && s.remote == remote)
        {
            Some(i) => i,
            None if sockets.len() < 32 => {
                sockets.push(Tuple {
                    local,
                    remote,
                    protocol: "tcp",
                    times_ms: Default::default(),
                    driver_injected_bytes: Default::default(),
                    errno: None,
                    error_kind: None,
                    error_source: None,
                });
                sockets.len() - 1
            }
            None => return,
        };
        let t = &mut sockets[i];
        t.times_ms.entry(stage).or_insert(ms);
        if let Some(bytes) = injected {
            t.driver_injected_bytes.entry(stage).or_insert(bytes);
        }
        if matches!(
            stage,
            "tx_syn"
                | "rx_syn"
                | "tx_syn_ack"
                | "rx_syn_ack"
                | "rx_rst"
                | "tx_rst"
                | "rx_fin"
                | "rx_tcp"
                | "rx_first"
                | "tx_first"
        ) {
            let first = t.times_ms.entry("first_packet").or_insert(ms);
            *first = (*first).min(ms);
        }
        if let Some(e) = err {
            t.errno = e.raw_os_error();
            t.error_kind = Some(format!("{:?}", e.kind()));
            t.error_source = Some(error_source(e));
        } else if matches!(stage, "deadline" | "anchor_deadline" | "mesh_deadline") && t.error_source.is_none() {
            t.error_kind = Some("TimedOut".to_owned());
            t.error_source = Some("application_deadline");
        }
    }

    #[cfg(windows)]
    pub(super) fn begin_network_capture(&self) {
        let mut data = self.inner.lock().unwrap();
        data.attempts.entry(0).or_default().network_capture = Some(NetworkCapture {
            layer: "windivert_network_sniff",
            ingress_open: false,
            egress_open: false,
            packets: Vec::new(),
        });
    }

    #[cfg(windows)]
    pub(super) fn capture_opened(&self, ingress: bool, egress: bool) {
        let mut data = self.inner.lock().unwrap();
        if let Some(capture) = data.attempts.get_mut(&0).and_then(|a| a.network_capture.as_mut()) {
            capture.ingress_open = ingress;
            capture.egress_open = egress;
        }
    }

    #[cfg(windows)]
    pub(super) fn observe_packet(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        stage: &'static str,
        interface: Option<u32>,
        expected_ip: bool,
    ) {
        let mut data = self.inner.lock().unwrap();
        let Some(capture) = data.attempts.get_mut(&0).and_then(|a| a.network_capture.as_mut()) else { return };
        let packets = &mut capture.packets;
        if packets.len() >= 64
            || (!expected_ip && packets.iter().filter(|p| !p.expected_ip).count() >= 8)
            || packets.iter().any(|p| p.remote == remote && p.stage == stage && p.interface == interface)
        {
            return;
        }
        packets.push(ObservedPacket { local, remote, stage, elapsed_ms: self.elapsed(), interface, expected_ip });
    }
}

fn error_source(error: &io::Error) -> &'static str {
    if error.raw_os_error().is_some() {
        "os"
    } else if error.kind() == io::ErrorKind::TimedOut {
        "application_deadline"
    } else {
        "io"
    }
}

/// The owner emits exactly once, including when the surrounding task is cancelled.
pub(crate) struct RoundLog {
    pub trace: Trace,
    events: mpsc::Sender<Event>,
    pub(crate) mimic: Option<(crate::raw::Control, SocketAddr, bool)>,
    pub(crate) stun_lease: Option<watch::Receiver<StunLeaseStatus>>,
    #[cfg(windows)]
    mimic_watch: Option<super::wire::MimicWatch>,
}
impl RoundLog {
    pub(crate) fn new(trace: Trace, events: &mpsc::Sender<Event>) -> Self {
        Self {
            trace,
            events: events.clone(),
            mimic: None,
            stun_lease: None,
            #[cfg(windows)]
            mimic_watch: None,
        }
    }

    pub(crate) fn watch_mimic(
        &mut self, components: &std::path::Path, local: SocketAddr, peer: SocketAddr,
    ) {
        #[cfg(windows)]
        if let (SocketAddr::V4(local), SocketAddr::V4(peer)) = (local, peer) {
            self.mimic_watch = Some(super::wire::MimicWatch::open(components, local, *peer.ip(), &self.trace));
        }
        #[cfg(not(windows))]
        let _ = (components, local, peer);
    }
}
impl Drop for RoundLog {
    fn drop(&mut self) {
        #[cfg(windows)]
        drop(self.mimic_watch.take());
        let t = &self.trace;
        if t.inner.lock().unwrap().round.is_nil() {
            return;
        }
        if let Some((control, target, include_prepared)) = &self.mimic {
            let start = t.inner.lock().unwrap().start_unix_ms;
            control.visit_handshakes(target.ip(), start, |peer, stage, at, injected| {
                if *include_prepared || peer == *target {
                    t.at(0, control.source, peer, stage, at - start, None, injected);
                    if stage == "ticket_queued" && !include_prepared {
                        t.stage("ticket_queued");
                        t.close("ticket_handoff");
                    }
                }
            });
        }
        let mut data = t.inner.lock().unwrap();
        data.elapsed_ms = t.elapsed();
        if let Some(status) = &self.stun_lease {
            data.stun_lease = Some(*status.borrow());
        }
        let event = Event::PunchSummary(serde_json::to_value(&*data).expect("serializable round"));
        if let Err(mpsc::error::TrySendError::Full(event)) = self.events.try_send(event) {
            let events = self.events.clone();
            tokio::spawn(async move {
                let _ = events.send(event).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_reports_os_errors_and_application_deadlines_separately() {
        let local = "192.0.2.1:63432".parse().unwrap();
        let refused = "198.51.100.1:50001".parse().unwrap();
        let pending = "198.51.100.1:50002".parse().unwrap();
        let trace = Trace::new(Uuid::new_v4(), "first_pair", "member", "tcp");
        trace.attempt(0, "dial");
        trace.socket(0, local, refused, "socket_failed", Some(&io::Error::from_raw_os_error(10060)));
        trace.socket(0, local, pending, "deadline", None);
        let data = trace.snapshot();
        let sockets = data["attempts"]["0"]["sockets"].as_array().unwrap();
        assert_eq!(sockets[0]["error_source"], "os");
        assert_eq!(sockets[0]["errno"], 10060);
        assert_eq!(sockets[1]["error_source"], "application_deadline");
        assert_eq!(sockets[1]["error_kind"], "TimedOut");
        assert!(sockets[1]["errno"].is_null());
    }

    #[cfg(windows)]
    #[test]
    fn mimic_summary_separates_injection_and_passive_packets() {
        let local = "192.0.2.1:63432".parse().unwrap();
        let known = "198.51.100.1:50001".parse().unwrap();
        let other_port = "198.51.100.1:50002".parse().unwrap();
        let other_ip = "198.51.100.2:50002".parse().unwrap();
        let trace = Trace::new(Uuid::new_v4(), "first_pair", "dial", "mimic");
        let (sender, mut receiver) = mpsc::channel(1);
        let log = RoundLog::new(trace.clone(), &sender);
        trace.begin_network_capture();
        trace.capture_opened(true, true);
        trace.at(0, local, known, "tx_syn", 1, None, Some(48));
        trace.observe_packet(local, other_port, "rx_syn", Some(7), true);
        trace.observe_packet(local, other_ip, "rx_syn", Some(7), false);
        trace.observe_packet(local, known, "tx_syn", Some(7), true);
        drop(log);

        let Event::PunchSummary(data) = receiver.try_recv().unwrap() else { panic!("missing summary") };
        let attempt = &data["attempts"]["0"];
        assert_eq!(attempt["sockets"][0]["driver_injected_bytes"]["tx_syn"], 48);
        let packets = attempt["network_capture"]["packets"].as_array().unwrap();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0]["remote"], other_port.to_string());
        assert_eq!(packets[1]["remote"], other_ip.to_string());
        assert_eq!(packets[1]["expected_ip"], false);
        assert_eq!(packets[2]["interface"], 7);
        assert!(packets[2].get("driver_injected_bytes").is_none());
    }
}
