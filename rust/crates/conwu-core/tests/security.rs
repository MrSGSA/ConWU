use conwu_core::{
    crypto as c,
    identity::Profile,
    link::Link,
    pairing::{Host, KeyExchange, Request},
};
#[test]
fn authenticated_handshake_and_replay() {
    let secret = c::random();
    let (mut a, mut b) = (
        Link::new(1, 2, secret).unwrap(),
        Link::new(2, 1, secret).unwrap(),
    );
    let response = b.receive(&a.hello().unwrap(), false);
    assert!(response.authenticated);
    assert!(!b.connected());
    let reply = a.receive(&response.reply.unwrap(), false);
    assert!(a.connected());
    assert!(b.receive(&reply.reply.unwrap(), false).authenticated);
    assert!(b.connected());
    let mut frames: Vec<_> = (0..4100)
        .map(|i| a.data(&(i as u32).to_be_bytes(), 0).unwrap().unwrap())
        .collect();
    assert!(b.receive(&frames[4099], false).authenticated);
    assert!(!b.receive(&frames[0], false).authenticated);
    assert!(b.receive(&frames[100], false).authenticated);
    assert!(!b.receive(&frames[100], false).authenticated);
    *frames[101].last_mut().unwrap() ^= 1;
    assert!(!b.receive(&frames[101], false).authenticated);
    assert!(
        !b.receive(&a.data(b"lane", 1).unwrap().unwrap(), false)
            .authenticated
    );
}
#[test]
fn commitments_and_approval_are_mandatory() {
    let (mut host, guest) = (
        Host::new("主机", None).unwrap(),
        KeyExchange::new(None).unwrap(),
    );
    let mut profile = Profile::create("tcp").unwrap();
    let request = Request {
        id: conwu_core::id(),
        method: "join".into(),
        code: host.ticket.code.clone(),
        commitment: guest.commitment.clone(),
        name: "从机".into(),
        ..Default::default()
    };
    let ticket = host.request(&request).unwrap().ticket.unwrap();
    assert!(host.approve(&mut profile, "000000", &[], None).is_err());
    assert_eq!(profile.directory.as_ref().unwrap().members.len(), 1);
    let mut reveal = Request {
        id: conwu_core::id(),
        method: "reveal".into(),
        room: ticket.room.clone(),
        token: ticket.token.clone(),
        public_key: guest.public.clone(),
        ..Default::default()
    };
    reveal.token = "invalid".into();
    assert!(host.request(&reveal).is_err());
    reveal.token = ticket.token.clone();
    host.request(&reveal).unwrap();
    let shared = guest
        .derive(
            &host.key.public,
            &host.key.commitment,
            &ticket.room,
            &ticket.candidate,
            false,
        )
        .unwrap();
    let sas = KeyExchange::sas(&shared);
    assert_eq!(sas, host.sas().unwrap());
    host.approve(&mut profile, &sas, &[], None).unwrap();
    assert_eq!(profile.directory.as_ref().unwrap().members.len(), 2);
    let enrollment = KeyExchange::decrypt(
        &shared,
        &host.state.ciphertext,
        &ticket.room,
        &ticket.candidate,
    )
    .unwrap();
    let (peer, _, _) = conwu_core::identity::import_bundle(&enrollment).unwrap();
    peer.validate().unwrap();
    assert_eq!(
        profile.shared_key(&peer.member).unwrap().as_slice(),
        peer.shared_key(&profile.member).unwrap().as_slice()
    );
}
