use super::{Assist, Client, MemberReport, MemberRequest, TCP_PREDICTION_TTL, signed};
use anyhow::{Context, Result, ensure};
use conwu_core::{
    code::{raw_tcp_mode, stream_mode},
    crypto as c,
    identity::{Member, Profile},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr, time::Instant};
use uuid::Uuid;

const ROUNDS: usize = 2;
pub(crate) const MAX_PORTS: usize = 16;

pub(super) fn valid_ports(ports: &[u16]) -> bool {
    ports.len() <= MAX_PORTS
        && ports.iter().enumerate()
            .all(|(i, port)| *port >= 1024 && !ports[..i].contains(port))
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct PredictionUpdate {
    pub round: Uuid,
    pub can_burst: bool,
    pub offer: Option<PredictionOffer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_hint: Option<PredictionRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) enum PredictionRole {
    Strided,
    Sequential,
}

#[derive(Clone, PartialEq, Eq)]
struct Declaration {
    can_burst: bool,
    role: Option<PredictionRole>,
    hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct PredictionOffer {
    pub attempt: u8,
    pub ports: Vec<u16>,
}

impl PredictionUpdate {
    fn declaration(&self) -> Declaration {
        Declaration { can_burst: self.can_burst, role: self.role_hint, hash: self.plan_hash.clone() }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(!self.round.is_nil(), "端口预测轮次无效");
        ensure!((self.can_burst || self.role_hint.is_none()) && self.plan_hash.as_ref().is_none_or(|hash|
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())), "端口预测声明无效");
        if let Some(offer) = &self.offer {
            ensure!(
                self.can_burst
                    && usize::from(offer.attempt) < ROUNDS
                    && valid_ports(&offer.ports),
                "端口预测候选无效"
            );
        }
        Ok(())
    }
}

pub(super) struct RoomPrediction {
    round: Uuid,
    ready: [Option<Declaration>; 2],
    offers: [Option<PredictionOffer>; ROUNDS],
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct RoomPredictionReply {
    pub round: Uuid,
    pub senders: Option<Vec<u8>>,
    pub offers: [Option<PredictionOffer>; ROUNDS],
}

impl RoomPrediction {
    pub(super) fn update(
        state: &mut Option<Self>,
        slot: usize,
        update: PredictionUpdate,
    ) -> Result<RoomPredictionReply> {
        update.validate()?;
        if state.as_ref().is_none_or(|state| state.round != update.round) {
            *state = Some(Self { round: update.round, ready: Default::default(), offers: Default::default() });
        }
        let state = state.as_mut().unwrap();
        let declaration = update.declaration();
        ensure!(*state.ready[slot].get_or_insert_with(|| declaration.clone()) == declaration,
            "端口预测配置或角色已改变");
        let senders = state.ready[0].as_ref().zip(state.ready[1].as_ref())
            .map(|(a, b)| sender_order(0, a, 1, b)).transpose()?;
        if let Some(offer) = update.offer {
            let attempt = usize::from(offer.attempt);
            ensure!(
                senders.as_ref().and_then(|plan| plan.get(attempt)) == Some(&(slot as u8)),
                "端口预测发送角色无效"
            );
            ensure!(
                *state.offers[attempt].get_or_insert_with(|| offer.clone()) == offer,
                "端口预测候选已提交"
            );
        }
        let offers = std::array::from_fn(|attempt| {
            senders.as_ref().and_then(|plan| plan.get(attempt))
                .filter(|&&sender| usize::from(sender) != slot)
                .and(state.offers[attempt].as_ref())
                .cloned()
        });
        Ok(RoomPredictionReply { round: state.round, senders, offers })
    }
}

fn sender_order(a: u8, first: &Declaration, b: u8, second: &Declaration) -> Result<Vec<u8>> {
    ensure!(first.hash == second.hash, "双方端口预测配置哈希不一致");
    Ok(match (first.can_burst, second.can_burst) {
        (true, true) if first.role == Some(PredictionRole::Strided) && second.role == Some(PredictionRole::Sequential) => vec![a],
        (true, true) if second.role == Some(PredictionRole::Strided) && first.role == Some(PredictionRole::Sequential) => vec![b],
        (true, true) => vec![a.min(b), a.max(b)],
        (true, false) => vec![a; ROUNDS],
        (false, true) => vec![b; ROUNDS],
        (false, false) => vec![],
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct PredictionSignal {
    pub(super) update: Option<PredictionUpdate>,
    signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) round_control: Option<RoundControl>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct RoundControl {
    pub(super) finished: Option<Uuid>,
    signature: String,
}

fn signed_control(network: &str, request: &MemberRequest, finished: Option<Uuid>) -> Result<Vec<u8>> {
    c::signed_json(&json!({
        "domain":"conwu-member-prediction-round-v1",
        "report":hex::encode(c::hash(&signed(network, request)?)),
        "finished":finished,
    }))
}
fn signed_update(
    network: &str,
    request: &MemberRequest,
    update: &Option<PredictionUpdate>,
) -> Result<Vec<u8>> {
    c::signed_json(&json!({
        "domain": "conwu-tcp-port-prediction-v1",
        "report": hex::encode(c::hash(&signed(network, request)?)),
        "update": update,
    }))
}

impl PredictionSignal {
    pub(super) fn verify(
        &self,
        network: &str,
        request: &MemberRequest,
        member: &Member,
    ) -> Result<()> {
        ensure!(stream_mode(&request.mode) || raw_tcp_mode(&request.mode), "承载不支持 TCP 预测");
        if let Some(update) = &self.update {
            update.validate()?;
        }
        ensure!(
            c::verify(
                &member.signing_key,
                &signed_update(network, request, &self.update)?,
                &self.signature
            ),
            "端口预测签名无效"
        );
        if let Some(control) = &self.round_control {
            ensure!(self.update.is_none() && control.finished.is_none_or(|id| !id.is_nil())
                && c::verify(&member.signing_key, &signed_control(network, request, control.finished)?, &control.signature),
                "预测轮次状态签名无效");
        }
        Ok(())
    }
}

impl MemberRequest {
    pub(super) fn enable_prediction(
        &mut self,
        profile: &Profile,
        update: Option<PredictionUpdate>,
    ) -> Result<()> {
        // Keep the primary report signature readable by older coordinators.
        let signature = c::sign(
            &profile.signing_private,
            &signed_update(&profile.pair.network, self, &update)?,
        )?;
        self.prediction = Some(PredictionSignal { update, signature, round_control: None });
        Ok(())
    }

    pub(super) fn synchronize_prediction(&mut self, profile: &Profile, finished: Option<Uuid>) -> Result<()> {
        self.enable_prediction(profile, None)?;
        let signature = c::sign(&profile.signing_private, &signed_control(&profile.pair.network, self, finished)?)?;
        self.prediction.as_mut().unwrap().round_control = Some(RoundControl { finished, signature });
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct PredictionReply {
    pub round: Uuid,
    pub senders: Option<Vec<u8>>,
    offers: [Option<MemberRequest>; ROUNDS],
}

impl PredictionReply {
    pub(crate) fn peer_offer(
        &self,
        network: &str,
        peer: &Member,
        endpoint: SocketAddr,
        mode: &str,
        attempt: usize,
    ) -> Result<Option<&PredictionOffer>> {
        let Some(report) = self.offers.get(attempt).context("端口预测序号无效")? else {
            return Ok(None);
        };
        report.verify(network, peer, endpoint.ip())?;
        ensure!(
            report.endpoint.parse::<SocketAddr>()? == endpoint && report.mode == mode,
            "端口预测与对端候选不符"
        );
        let update = report.prediction_update().context("端口预测内容缺失")?;
        let offer = update.offer.as_ref().context("端口预测候选缺失")?;
        ensure!(
            update.round == self.round && usize::from(offer.attempt) == attempt,
            "端口预测与协调轮次不符"
        );
        Ok(Some(offer))
    }
}

pub(super) struct RoundPrediction {
    round: Uuid,
    start: Instant,
    ready: BTreeMap<u8, Declaration>,
    offers: [Option<MemberRequest>; ROUNDS],
}

impl RoundPrediction {
    fn new(round: Uuid, start: Instant) -> Self {
        Self {
            round,
            start,
            ready: BTreeMap::new(),
            offers: Default::default(),
        }
    }

    fn senders(&self, a: u8, b: u8) -> Result<Option<Vec<u8>>> {
        self.ready.get(&a).zip(self.ready.get(&b)).map(|(first, second)|
            sender_order(a, first, b, second)).transpose()
    }
}

fn current_report(report: &MemberReport, now: Instant) -> bool {
    report.confirmed
        && report.latest.prediction.is_some()
        && now.duration_since(report.received) < TCP_PREDICTION_TTL
}

impl Assist {
    /// Called under the coordinator's current membership authorization.
    pub(crate) fn exchange_prediction(
        &self,
        network: &str,
        input: MemberRequest,
        peer: &Member,
    ) -> Result<Value> {
        let update = input.prediction_update().context("端口预测内容缺失")?;
        let now = Instant::now();
        let members = self.members.lock().unwrap();
        let caller = members
            .get(&(network.into(), input.slot))
            .context("本机尚无协调报告")?;
        let remote = members
            .get(&(network.into(), peer.slot))
            .context("对端尚无协调报告")?;
        ensure!(
            current_report(caller, now)
                && current_report(remote, now)
                && caller.latest.boot == input.boot
                && caller.latest.device == input.device
                && caller.latest.endpoint == input.endpoint
                && caller.latest.mode == input.mode
                && remote.latest.device == peer.device
                && remote.latest.mode == input.mode,
            "端口预测的成员或出口已改变"
        );
        let rounds = self.rounds.lock().unwrap();
        let schedule = rounds
            .get(network)
            .filter(|row| {
                row.prediction
                    && row.round == update.round
                    && now.duration_since(row.start) < TCP_PREDICTION_TTL
            })
            .context("端口预测轮次无效或过期")?;
        let mut predictions = self.predictions.lock().unwrap();
        predictions.retain(|_, row| now.duration_since(row.start) < TCP_PREDICTION_TTL);
        let state = predictions
            .entry(network.into())
            .or_insert_with(|| RoundPrediction::new(schedule.round, schedule.start));
        if state.round != schedule.round {
            *state = RoundPrediction::new(schedule.round, schedule.start);
        }

        let declaration = update.declaration();
        let senders = if let Some(offer) = &update.offer {
            ensure!(state.ready.get(&input.slot) == Some(&declaration), "端口预测配置或角色已改变");
            let senders = state
                .senders(input.slot, peer.slot)?
                .context("端口预测尚未同步")?;
            let attempt = usize::from(offer.attempt);
            ensure!(
                senders.get(attempt) == Some(&input.slot),
                "端口预测发送角色无效"
            );
            if let Some(prior) = &state.offers[attempt] {
                ensure!(
                    prior.prediction_update().and_then(|r| r.offer.as_ref()) == Some(offer),
                    "端口预测候选已提交"
                );
            } else {
                state.offers[attempt] = Some(input.clone());
            }
            Some(senders)
        } else {
            ensure!(
                *state.ready.entry(input.slot).or_insert_with(|| declaration.clone()) == declaration,
                "端口预测配置或角色已改变"
            );
            state.senders(input.slot, peer.slot)?
        };
        let offers = state.offers.each_ref().map(|offer| {
            offer
                .as_ref()
                .filter(|report| report.slot == peer.slot)
                .cloned()
        });
        Ok(serde_json::to_value(PredictionReply {
            round: state.round,
            senders,
            offers,
        })?)
    }
}

impl Client {
    pub(crate) async fn prediction(
        &self,
        profile: &Profile,
        boot: Uuid,
        endpoint: SocketAddr,
        update: PredictionUpdate,
    ) -> Result<PredictionReply> {
        let round = update.round;
        let mut request = MemberRequest::create(profile, boot, endpoint)?;
        request.enable_prediction(profile, Some(update))?;
        let auth = hex::encode_upper(profile.pair.key("discovery-auth"));
        let path = format!("v3/mesh/{}/tcp-assist", profile.pair.network);
        let input = serde_json::to_value(request)?;
        let response = super::retry_pair_step("同步成员预测", super::transient_signal,
            |_| self.post(&path, &input, Some(&auth))).await?;
        let reply: PredictionReply = serde_json::from_value(response)?;
        ensure!(reply.round == round, "端口预测协调轮次已改变");
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strided_peer_sends_without_reversing_roles_and_mismatched_hashes_are_rejected() -> Result<()> {
        let round = Uuid::new_v4();
        let make = |role, hash: &str| PredictionUpdate {
            round, can_burst: true, role_hint: Some(role), plan_hash: Some(hash.repeat(64)), ..Default::default()
        };
        let sequential = make(PredictionRole::Sequential, "a");
        let strided = make(PredictionRole::Strided, "a");
        for slot in [0, 1] {
            let mut room = None;
            assert!(RoomPrediction::update(&mut room, slot, sequential.clone())?.senders.is_none());
            assert_eq!(RoomPrediction::update(&mut room, 1 - slot, strided.clone())?.senders, Some(vec![(1 - slot) as u8]));
        }
        let mut room = None;
        RoomPrediction::update(&mut room, 0, sequential)?;
        assert!(RoomPrediction::update(&mut room, 1, make(PredictionRole::Strided, "b")).is_err());
        Ok(())
    }

    #[test]
    fn dial_only_peers_wait_for_both_declarations_before_stopping() -> Result<()> {
        let update = PredictionUpdate { round: Uuid::new_v4(), ..Default::default() };
        let mut room = None;
        assert!(RoomPrediction::update(&mut room, 0, update.clone())?.senders.is_none());
        assert_eq!(RoomPrediction::update(&mut room, 1, update.clone())?.senders, Some(vec![]));
        assert_eq!(RoomPrediction::update(&mut room, 0, update)?.senders, Some(vec![]));
        Ok(())
    }

    #[test]
    fn signed_offers_are_bound_to_the_current_member_round_and_sender() -> Result<()> {
        for mode in ["tcp", "https", "faketcp", "phantun", "mimic", "tcpraw"] {
            verify_signed_member_offer(mode).with_context(|| format!("{mode} 成员重连候选校验"))?;
        }
        Ok(())
    }

    fn verify_signed_member_offer(mode: &str) -> Result<()> {
        let service = Assist::default();
        let mut owner = Profile::create(mode)?;
        let guest = Profile::import(&owner.issue(None)?.export()?)?;
        let network = &owner.pair.network;
        let a: SocketAddr = "203.0.113.1:44000".parse()?;
        let b: SocketAddr = "203.0.113.2:44001".parse()?;
        let a_boot = Uuid::new_v4();
        let b_boot = Uuid::new_v4();
        let request =
            |profile: &Profile, boot, endpoint: SocketAddr, update: Option<PredictionUpdate>| -> Result<MemberRequest> {
                let mut report = MemberRequest::create(profile, boot, endpoint)?;
                if update.is_some() {
                    report.enable_prediction(profile, update)?;
                } else {
                    report.synchronize_prediction(profile, None)?;
                }
                report.verify(network, &profile.member, endpoint.ip())?;
                Ok(report)
            };
        service.member(network, request(&owner, a_boot, a, None)?, &guest.member)?;
        let scheduled =
            service.member(network, request(&guest, b_boot, b, None)?, &owner.member)?;
        assert_eq!(scheduled["TcpPrediction"], true);
        let round = serde_json::from_value::<Uuid>(scheduled["Round"].clone())?;
        let ready = |can_burst, offer| {
            Some(PredictionUpdate {
                round,
                can_burst,
                offer,
                ..Default::default()
            })
        };
        let a_ready = request(&owner, a_boot, a, ready(true, None))?;
        let b_ready = request(&guest, b_boot, b, ready(true, None))?;
        service.exchange_prediction(network, a_ready, &guest.member)?;
        service.exchange_prediction(network, b_ready.clone(), &owner.member)?;

        let offer = PredictionOffer {
            attempt: 0,
            ports: vec![45001, 45003],
        };
        let bad_role = request(&guest, b_boot, b, ready(true, Some(offer.clone())))?;
        assert!(
            service
                .exchange_prediction(network, bad_role, &owner.member)
                .is_err()
        );
        let stale_boot = request(&owner, Uuid::new_v4(), a, ready(true, Some(offer.clone())))?;
        assert!(
            service
                .exchange_prediction(network, stale_boot, &guest.member)
                .is_err()
        );

        let signed = request(&owner, a_boot, a, ready(true, Some(offer.clone())))?;
        let mut forged = signed.clone();
        forged
            .prediction
            .as_mut()
            .unwrap()
            .update
            .as_mut()
            .unwrap()
            .offer
            .as_mut()
            .unwrap()
            .ports[0] = 45002;
        assert!(forged.verify(network, &owner.member, a.ip()).is_err());
        service.exchange_prediction(network, signed, &guest.member)?;
        let replacement = PredictionOffer {
            ports: vec![45002],
            ..offer.clone()
        };
        let replacement = request(&owner, a_boot, a, ready(true, Some(replacement)))?;
        assert!(
            service
                .exchange_prediction(network, replacement, &guest.member)
                .is_err()
        );
        let reply: PredictionReply = serde_json::from_value(service.exchange_prediction(
            network,
            b_ready,
            &owner.member,
        )?)?;
        assert_eq!(
            reply.peer_offer(network, &owner.member, a, mode, 0)?,
            Some(&offer)
        );
        assert!(
            reply
                .peer_offer(network, &owner.member, b, mode, 0)
                .is_err()
        );
        assert!(
            reply
                .peer_offer(network, &owner.member, a, mode, 1)?
                .is_none()
        );
        Ok(())
    }
}
