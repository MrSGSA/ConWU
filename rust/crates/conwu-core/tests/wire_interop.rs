use conwu_core::{crypto as c, identity::Profile, link::Link, pairing::KeyExchange};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Oracle {
    fn new() -> Self {
        let path = std::env::var("CONWU_DOTNET_ORACLE")
            .expect("set CONWU_DOTNET_ORACLE to the built development oracle DLL");
        let mut child = Command::new("dotnet")
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }
    fn call(&mut self, v: Value) -> Value {
        writeln!(self.input, "{v}").unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).expect("oracle JSON reply");
        assert!(
            v["ok"].as_bool().unwrap(),
            "legacy rejected operation: {}",
            v["error"]
        );
        v["result"].clone()
    }
}
impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[test]
#[ignore = "development oracle required"]
fn legacy_rejoin_and_traversal_contracts() {
    let mut o = Oracle::new();
    let fixture = o.call(json!({"op":"identity-fixture"}));
    let owner: Profile = serde_json::from_value(fixture["owner"].clone()).unwrap();
    let guest: Profile = serde_json::from_value(fixture["guest"].clone()).unwrap();
    let rejoin = o.call(json!({"op":"rejoin-create","profile":guest,"code":"123456"}));
    let proof: conwu_core::rejoin::Proof = serde_json::from_value(rejoin["proof"].clone()).unwrap();
    assert_eq!(proof.fingerprint().unwrap(), rejoin["digest"]);
    assert_eq!(
        proof
            .resolve(
                &owner,
                "123456",
                rejoin["commitment"].as_str().unwrap(),
                &[]
            )
            .unwrap(),
        Some(guest.member.clone())
    );
    let commitment = KeyExchange::new(None).unwrap().commitment;
    let proof = conwu_core::rejoin::Credential::retain(&guest)
        .unwrap()
        .prove("654321", &commitment)
        .unwrap();
    let result=o.call(json!({"op":"rejoin-resolve","profile":owner,"code":"654321","commitment":commitment,"proof":proof}));
    assert_eq!(
        result["member"],
        serde_json::to_value(&guest.member).unwrap()
    );
    let now = conwu_core::unix_seconds();
    let mut message:conwu_core::traversal::Message=serde_json::from_value(json!({"Version":1,"MessageId":uuid::Uuid::new_v4(),"FromSlot":owner.member.slot,"FromDevice":owner.member.device,"FromBoot":uuid::Uuid::new_v4(),"ToSlot":guest.member.slot,"ToDevice":guest.member.device,"ToBoot":uuid::Uuid::new_v4(),"Sequence":1,"AttemptId":uuid::Uuid::new_v4(),"NominationRevision":1,"ValidationNonce":uuid::Uuid::new_v4(),"Profile":2,"ProtocolClientSlot":1,"NominatorSlot":1,"Candidate":{"Id":uuid::Uuid::new_v4(),"Version":1,"Endpoint":"203.0.113.10:45000","ObservationTarget":"198.51.100.10:3478","ObservedAt":now,"Expires":now+90,"Purpose":2},"PeerCandidate":null,"Stage":1,"Expires":now+55,"Signature":""})).unwrap();
    message.sign(&owner).unwrap();
    let verified = o.call(json!({"op":"traversal-verify","profile":owner,"message":message}));
    assert_eq!(
        verified["fingerprint"],
        hex::encode_upper(message.fingerprint(&owner.pair.network).unwrap())
    );
    let signed: conwu_core::traversal::Message = serde_json::from_value(
        o.call(json!({"op":"traversal-sign","profile":owner,"message":message})),
    )
    .unwrap();
    signed
        .verify(&owner.pair.network, &owner.member, &guest.member)
        .unwrap();
    let mut full = message;
    full.stage = 3;
    let mut remote = full.candidate.clone().unwrap();
    remote.id = uuid::Uuid::new_v4();
    remote.endpoint = "198.51.100.20:45000".into();
    full.peer_candidate = Some(remote);
    full.sign(&owner).unwrap();
    let context =
        conwu_core::path::Context::from_message(&owner.pair.network, &full, true).unwrap();
    let digest = o.call(json!({"op":"path-digest","context":context}));
    assert_eq!(
        digest["digest"],
        hex::encode_upper(context.digest().unwrap())
    );
}
#[test]
#[ignore = "development oracle required"]
fn legacy_crypto_and_wire_compatibility() {
    let mut o = Oracle::new();
    for value in [
        json!({"Text":"a+b<>&'\"\\中文\n","Nested":[1,null,false]}),
        json!({"domain":"test","Base64":"+/==","Zero":0}),
    ] {
        let legacy = o.call(json!({"op":"canonical","value":value}));
        assert_eq!(
            String::from_utf8(c::signed_json(&value).unwrap()).unwrap(),
            legacy["text"].as_str().unwrap()
        );
    }
    let fixture = o.call(json!({"op":"identity-fixture"}));
    let owner: Profile = serde_json::from_value(fixture["owner"].clone()).unwrap();
    owner.validate().expect("C# member/directory signatures");
    let guest: Profile = serde_json::from_value(fixture["guest"].clone()).unwrap();
    guest.validate().unwrap();
    let shared = owner.shared_key(&guest.member).unwrap();
    assert_eq!(
        hex::encode_upper(&*shared),
        fixture["shared"].as_str().unwrap()
    );
    let mut native = Profile::create("tcp").unwrap();
    let enrollment = native.issue(None).unwrap();
    let native_guest = Profile::import(&enrollment.export().unwrap()).unwrap();
    let announcement = conwu_core::metadata::Announcement {
        slot: native.member.slot,
        device: native.member.device.clone(),
        revision: conwu_core::unix_seconds() * 1000,
        expires: conwu_core::unix_seconds() + 120,
        endpoint: "203.0.113.10:44680".into(),
        name: "Rust 互通测试".into(),
        boot_id: None,
        traversal: None,
        pkarr_source: None,
        existing_endpoints: Some(vec!["203.0.113.10:44680".into()]),
        existing_entry_only: true,
        connection_paused: true,
    };
    let envelope = conwu_core::metadata::Envelope::seal(&native, &announcement).unwrap();
    let opened = o.call(json!({"op":"metadata-open","profile":native_guest,"envelope":envelope}));
    assert_eq!(opened["Name"], announcement.name);
    assert_eq!(opened["ConnectionPaused"], true);
    let remote: conwu_core::metadata::Envelope = serde_json::from_value(
        o.call(json!({"op":"metadata-seal","profile":native,"announcement":announcement})),
    )
    .unwrap();
    assert_eq!(
        remote.open(&native_guest, &native.member).unwrap().name,
        announcement.name
    );
    let notice = conwu_core::departure::Notice::create(&native_guest).unwrap();
    let source = format!("pkarr://{}", "y".repeat(52));
    let mut record = conwu_core::rendezvous::Announcement {
        version: 1,
        mode: "tcp".into(),
        expires: conwu_core::unix_seconds() + 180,
        endpoints: vec!["203.0.113.10:42000".into()],
        state: None,
    };
    let state = conwu_core::rendezvous::State::new(uuid::Uuid::new_v4(), "PKARR 互通");
    record.state = Some(
        state
            .seal(&native, &native_guest.member, &source, &record)
            .unwrap(),
    );
    let opened=o.call(json!({"op":"pkarr-state-open","profile":native_guest,"source":source,"announcement":record}));
    assert_eq!(opened["Name"], "PKARR 互通");
    assert_eq!(opened["Boot"], state.boot.to_string());
    let sealed=o.call(json!({"op":"pkarr-state-seal","profile":native,"source":source,"announcement":record,"state":state}));
    record.state = Some(sealed["cipher"].as_str().unwrap().into());
    assert_eq!(
        conwu_core::rendezvous::State::open(&native_guest, &native.member, &source, &record)
            .unwrap()
            .boot,
        state.boot
    );
    assert_eq!(
        o.call(json!({"op":"departure-validate","notice":notice,"owner":native.owner_key}))["valid"],
        true
    );
    let validated = o.call(json!({"op":"identity-validate","profile":native}));
    assert_eq!(
        validated["shared"].as_str().unwrap(),
        hex::encode_upper(&*native_guest.shared_key(&native.member).unwrap())
    );
    let room = conwu_core::id();
    let candidate = conwu_core::id();
    let remote = o.call(json!({"op":"pair-new"}));
    let key = KeyExchange::new(None).unwrap();
    let pair_shared = key
        .derive(
            remote["publicKey"].as_str().unwrap(),
            remote["commitment"].as_str().unwrap(),
            &room,
            &candidate,
            false,
        )
        .unwrap();
    let result=o.call(json!({"op":"pair-derive","publicKey":key.public,"commitment":key.commitment,"room":room,"candidate":candidate,"owner":true}));
    assert_eq!(
        hex::encode_upper(&*pair_shared),
        result["shared"].as_str().unwrap()
    );
    assert_eq!(
        KeyExchange::sas(&pair_shared),
        result["sas"].as_str().unwrap()
    );
    assert_eq!(
        KeyExchange::decrypt(
            &pair_shared,
            result["cipher"].as_str().unwrap(),
            &room,
            &candidate
        )
        .unwrap(),
        "oracle approval"
    );
    let cipher = KeyExchange::encrypt(&pair_shared, "Rust approval", &room, &candidate).unwrap();
    assert_eq!(o.call(json!({"op":"pair-decrypt","shared":hex::encode(&*pair_shared),"cipher":cipher,"room":room,"candidate":candidate}))["text"],"Rust approval");
    for round in 0..3 {
        o.call(json!({"op":"link-new","local":1,"remote":2,"shared":hex::encode(&*shared)}));
        let mut rust = Link::new(2, 1, *shared).unwrap();
        let a = o.call(json!({"op":"receive","frame":c::b64(rust.hello().unwrap())}));
        assert!(a["authenticated"].as_bool().unwrap());
        let b = rust.receive(&c::unb64(a["reply"].as_str().unwrap()).unwrap(), true);
        assert!(b.authenticated);
        assert!(
            o.call(json!({"op":"receive","frame":c::b64(b.reply.unwrap())}))["connected"]
                .as_bool()
                .unwrap()
        );
        assert!(rust.connected());
        for size in [0, 1, 52, 1280] {
            let packet = vec![round; size];
            let frame = rust.data(&packet, 0).unwrap().unwrap();
            let received = o.call(json!({"op":"receive","frame":c::b64(&frame)}));
            assert_eq!(
                c::unb64(received["packet"].as_str().unwrap()).unwrap(),
                packet
            );
            assert!(
                !o.call(json!({"op":"receive","frame":c::b64(&frame)}))["authenticated"]
                    .as_bool()
                    .unwrap()
            );
            let other = o.call(json!({"op":"data","payload":c::b64(&packet)}));
            assert_eq!(
                rust.receive(&c::unb64(other["frame"].as_str().unwrap()).unwrap(), true)
                    .packet
                    .unwrap(),
                packet
            );
        }
        let packet = vec![42; 1280];
        for lane in 1..=3 {
            let frame = rust.data(&packet, lane).unwrap().unwrap();
            assert_eq!(
                o.call(json!({"op":"receive","frame":c::b64(frame)}))["packet"],
                c::b64(&packet)
            );
            let other = o.call(json!({"op":"lane","lane":lane,"payload":c::b64(&packet)}));
            let frame = c::unb64(other["frame"].as_str().unwrap()).unwrap();
            assert!(!rust.receive(&frame, false).authenticated);
            assert_eq!(rust.receive(&frame, true).packet.unwrap(), packet);
        }
        let ping = o.call(json!({"op":"ping"}));
        let pong = rust
            .receive(&c::unb64(ping["frame"].as_str().unwrap()).unwrap(), true)
            .reply
            .unwrap();
        assert!(
            o.call(json!({"op":"receive","frame":c::b64(pong)}))["authenticated"]
                .as_bool()
                .unwrap()
        );
    }
}
