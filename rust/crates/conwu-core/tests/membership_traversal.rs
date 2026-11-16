use anyhow::Result;
use conwu_core::{
    crypto as c,
    identity::Profile,
    pairing::KeyExchange,
    rejoin::Credential,
    traversal::{Candidate, Inbox, Message},
    unix_seconds,
};
use uuid::Uuid;

#[test]
fn rejoin_proof_is_bound_to_locator_commitment_and_current_membership() -> Result<()> {
    let mut owner = Profile::create("faketcp")?;
    let enrollment = owner.issue(None)?;
    let guest = Profile::import(&enrollment.export()?)?;
    let retained = Credential::retain(&guest).unwrap();
    let key = KeyExchange::new(None)?;
    let proof = retained.prove("123456", &key.commitment)?;
    assert_eq!(
        proof.resolve(&owner, "123456", &key.commitment, &[])?,
        Some(guest.member.clone())
    );
    assert!(
        proof
            .resolve(&owner, "654321", &key.commitment, &[])
            .is_err()
    );
    assert!(
        proof
            .resolve(&owner, "123456", &hex::encode_upper(c::random::<32>()), &[])
            .is_err()
    );
    let replacement = owner.reissue_for_device(&guest.member.device, None)?;
    let history =
        conwu_core::rejoin::remember(&owner, &[], guest.member.clone(), &replacement.member);
    assert_eq!(
        proof.resolve(&owner, "123456", &key.commitment, &history)?,
        Some(replacement.member.clone())
    );
    owner.remove_peer(replacement.member.slot)?;
    assert!(
        proof
            .resolve(&owner, "123456", &key.commitment, &history)?
            .is_none()
    );
    Ok(())
}

fn offer(owner: &Profile, peer: &Profile) -> Message {
    let now = unix_seconds();
    Message {
        version: 1,
        message_id: Uuid::new_v4(),
        from_slot: owner.member.slot,
        from_device: owner.member.device.clone(),
        from_boot: Uuid::new_v4(),
        to_slot: peer.member.slot,
        to_device: peer.member.device.clone(),
        to_boot: Uuid::new_v4(),
        sequence: 1,
        attempt_id: Uuid::new_v4(),
        nomination_revision: 1,
        validation_nonce: Uuid::new_v4(),
        profile: 2,
        protocol_client_slot: 1,
        nominator_slot: 1,
        candidate: Some(Candidate {
            id: Uuid::new_v4(),
            version: 1,
            endpoint: "203.0.113.10:45000".into(),
            observation_target: Some("198.51.100.10:3478".into()),
            observed_at: now,
            expires: now + 90,
            purpose: 2,
            prediction: None,
            peer_reflexive: false,
            exploration: None,
            standby: false,
        }),
        peer_candidate: None,
        stage: 1,
        expires: now + 55,
        signature: String::new(),
    }
}

#[test]
fn signed_inbox_is_atomic_rejects_conflicts_and_accepts_new_boot() -> Result<()> {
    let mut owner = Profile::create("faketcp")?;
    let peer = Profile::import(&owner.issue(None)?.export()?)?;
    let directory = owner.directory.as_ref().unwrap();
    let mut inbox = Inbox::default();
    let mut first = offer(&owner, &peer);
    first.sign(&owner)?;
    inbox.insert(&owner.pair.network, directory, vec![first.clone()])?;
    inbox.insert(&owner.pair.network, directory, vec![first.clone()])?;
    assert_eq!(inbox.snapshot().len(), 1);
    let mut conflict = first.clone();
    conflict.message_id = Uuid::new_v4();
    conflict.sign(&owner)?;
    assert!(
        inbox
            .insert(&owner.pair.network, directory, vec![conflict])
            .is_err()
    );
    let mut restarted = first.clone();
    restarted.from_boot = Uuid::new_v4();
    restarted.message_id = Uuid::new_v4();
    restarted.attempt_id = Uuid::new_v4();
    restarted.sign(&owner)?;
    inbox.insert(&owner.pair.network, directory, vec![restarted.clone()])?;
    let before = inbox.snapshot();
    restarted.sequence += 1;
    restarted.message_id = Uuid::new_v4();
    restarted.sign(&owner)?;
    let mut forged = restarted.clone();
    forged.message_id = Uuid::new_v4();
    assert!(
        inbox
            .insert(&owner.pair.network, directory, vec![restarted, forged])
            .is_err()
    );
    assert_eq!(inbox.snapshot(), before);
    let another = Profile::create("faketcp")?;
    assert!(
        inbox
            .insert(
                &another.pair.network,
                another.directory.as_ref().unwrap(),
                vec![]
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn native_check_and_nomination_bind_the_actual_path() -> Result<()> {
    use conwu_core::path::{Context, NativeCheck, Nomination, Stage};
    let mut owner = Profile::create("faketcp")?;
    let peer = Profile::import(&owner.issue(None)?.export()?)?;
    let mut ready = offer(&owner, &peer);
    ready.stage = 3;
    let mut remote = ready.candidate.clone().unwrap();
    remote.id = Uuid::new_v4();
    remote.endpoint = "198.51.100.20:45000".into();
    ready.peer_candidate = Some(remote);
    ready.sign(&owner)?;
    let a = Context::from_message(&owner.pair.network, &ready, true)?;
    let b = Context::from_message(&owner.pair.network, &ready, false)?;
    assert_eq!(a.digest()?, b.digest()?);
    let shared = owner.shared_key(&peer.member)?;
    let check_a = NativeCheck::new(&a, &shared)?;
    let check_b = NativeCheck::new(&b, &shared)?;
    let probe = check_a.frame(1, &check_a.challenge)?;
    assert!(check_b.valid(&probe) && !check_a.valid(&probe));
    let mut corrupt = probe.clone();
    corrupt[60] ^= 1;
    assert!(!check_b.valid(&corrupt));
    let path_a = Uuid::new_v4();
    let path_b = Uuid::new_v4();
    let mut a = Nomination::new(a, path_a, 1, std::time::Duration::from_secs(8), true)?;
    let mut b = Nomination::new(b, path_b, 1, std::time::Duration::from_secs(8), true)?;
    let initial = a.tick();
    assert!(b.receive(Uuid::new_v4(), &initial[0]).is_empty());
    for _ in 0..12 {
        let mut to_b = a.tick();
        to_b.extend(initial.clone());
        let mut to_a = b.tick();
        for f in to_b {
            to_a.extend(b.receive(path_b, &f));
        }
        for f in to_a {
            let answers = a.receive(path_a, &f);
            for answer in answers {
                let responses = b.receive(path_b, &answer);
                for response in responses {
                    a.receive(path_a, &response);
                }
            }
        }
        if a.stage == Stage::Selected && b.stage == Stage::Selected {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(260));
    }
    assert_eq!(a.stage, Stage::Selected);
    assert_eq!(b.stage, Stage::Selected);
    b.cancel();
    for frame in a.tick() {
        assert!(b.receive(path_b, &frame).is_empty());
    }
    assert_eq!(b.stage, Stage::Cancelled);
    Ok(())
}
