//! Signed Offer/Ready/Start on the existing v3 coordinator, followed by an
//! authenticated full-MTU SLF1 exchange and in-path SLN1 nomination.
use crate::{
    discovery::{self, TcpObservation},
    native::{Attachment, Descriptor},
    raw::Firewall,
    runtime::{Engine, Running},
    transport::Pipe,
};
use anyhow::{Context as _, Result, ensure};
use conwu_core::{
    crypto as c,
    identity::{Member, Profile},
    metadata::{Envelope, Snapshot},
    path::{Context, NativeCheck},
    traversal::{Candidate, Capabilities, Message},
    unix_seconds,
};
use serde_json::json;
use std::{
    net::SocketAddr,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, process::Command, sync::mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub fn capabilities(running: &Running) -> Option<Capabilities> {
    let n = running.config.read().unwrap();
    if n.settings.existing_only() || n.settings.mode().ok() != Some("faketcp") {
        return None;
    }
    Some(Capabilities {
        version: 1,
        native_abi: 1,
        boot_id: running.boot,
        profiles: vec![2],
        background_upgrade: 1,
        tcp_peer_reflexive: if cfg!(windows) && n.settings.tcp_peer_reflexive {
            1
        } else {
            0
        },
        ..Default::default()
    })
}
struct Lease {
    observation: TcpObservation,
    candidate: Candidate,
    generation: Uuid,
    id: Uuid,
    _guard: Firewall,
    #[cfg(windows)]
    capture: Arc<crate::capture::Owner>,
}
impl Lease {
    async fn gather(engine: &Engine, running: &Running, learning: bool) -> Result<Self> {
        let n = running.config.read().unwrap().clone();
        let url = url::Url::parse(&n.settings.service)?;
        let observer = format!(
            "{}:{}",
            url.host_str().context("协调地址缺少主机")?,
            url.port_or_known_default().context("协调地址缺少端口")?
        );
        let observation =
            discovery::observe_tcp(n.settings.source_port, &[observer], engine, "faketcp").await?;
        let guard = Firewall::open("faketcp", true, observation.local, "127.0.0.1:9".parse()?)?;
        guard.protect(observation.local, observation.observer)?;
        #[cfg(windows)]
        let capture = crate::capture::Owner::open(
            &engine.components,
            observation.local,
            observation.observer,
            &running.cancel,
        )?;
        let now = unix_seconds();
        let candidate = Candidate {
            id: Uuid::new_v4(),
            version: 1,
            endpoint: observation.mapped.to_string(),
            observation_target: Some(observation.observer.to_string()),
            observed_at: now,
            expires: now + 90,
            purpose: 2,
            prediction: None,
            peer_reflexive: learning,
            exploration: None,
            standby: false,
        };
        Ok(Self {
            observation,
            candidate,
            generation: Uuid::new_v4(),
            id: Uuid::new_v4(),
            _guard: guard,
            #[cfg(windows)]
            capture,
        })
    }
}
struct Prepared {
    attachment: Arc<Attachment>,
    socket: Arc<UdpSocket>,
    application: Option<SocketAddr>,
    lease: Lease,
    check: NativeCheck,
    context: Context,
    config: std::path::PathBuf,
    stop: CancellationToken,
    #[cfg(windows)]
    session: Arc<crate::capture::Session>,
}
impl Prepared {
    async fn create(
        engine: &Engine,
        lease: Lease,
        context: Context,
        profile: &Profile,
        peer: &Member,
        remote: SocketAddr,
        parent: &CancellationToken,
    ) -> Result<Self> {
        let shared = profile.shared_key(peer)?;
        let check = NativeCheck::new(&context, &shared)?;
        let raw_key = c::hkdf(&*shared, &check.digest, b"streamlink-native-outer-v1");
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let application = if context.protocol_client {
            Some(UdpSocket::bind("127.0.0.1:0").await?.local_addr()?)
        } else {
            None
        };
        let bind = application.unwrap_or(lease.observation.local);
        let target = if context.protocol_client {
            remote
        } else {
            socket.local_addr()?
        };
        let text = zeroize::Zeroizing::new(format!(
            "{}\n-l {bind}\n-r {target}\n-k {}\n--raw-mode faketcp\n--fix-gro\n--seq-mode 3\n--fake-http test.ustc.edu.cn\n--log-level 4\n--disable-color\n",
            if context.protocol_client { "-c" } else { "-s" },
            hex::encode_upper(&*raw_key)
        ));
        let name = format!("managed-raw-{}.conf", conwu_core::id());
        engine.store.write(&name, text.as_bytes(), false)?;
        let config = engine.store.checked_file(&name)?;
        let mut command = Command::new(engine.components.join(if cfg!(windows) {
            "udp2raw-native.exe"
        } else {
            "udp2raw-native"
        }));
        command
            .current_dir(&engine.components)
            .arg("--conf-file")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("STREAMLINK_ALLOW_DRIVER_INSTALL", "0");
        let descriptor = Descriptor {
            attach: Uuid::new_v4(),
            lease: lease.id,
            generation: lease.generation,
            local: lease.observation.local,
            observer: lease.observation.observer,
            peer: remote,
            server: !context.protocol_client,
            broker: cfg!(windows),
            wire_metadata: cfg!(windows),
            peer_reflexive: lease.candidate.peer_reflexive,
        };
        #[cfg(windows)]
        let session = lease.capture.register(descriptor.clone())?;
        let attachment = Attachment::prepare(
            command,
            descriptor,
            &std::env::temp_dir(),
            parent,
            #[cfg(windows)]
            Some(session.clone()),
        )
        .await;
        let attachment = match attachment {
            Ok(a) => a,
            Err(e) => {
                let _ = std::fs::remove_file(&config);
                return Err(e);
            }
        };
        Ok(Self {
            stop: parent.child_token(),
            attachment,
            socket,
            application,
            lease,
            check,
            context,
            config,
            #[cfg(windows)]
            session,
        })
    }
    async fn activate(&mut self) -> Result<Duration> {
        self.attachment.start().await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut timer = tokio::time::interval(Duration::from_millis(200));
        let mut buffer = [0; 2049];
        let mut sends = 0;
        loop {
            tokio::select! {
                _=self.stop.cancelled()=>anyhow::bail!("受管路径已取消"),
                _=self.attachment.cancel.cancelled()=>anyhow::bail!("原生受管承载已退出"),
                _=tokio::time::sleep_until(deadline)=>anyhow::bail!("SLF1 双向全尺寸路径校验超时"),
                _=timer.tick()=>if let Some(to)=self.application {if sends<96{self.socket.send_to(&self.check.frame(1,&self.check.challenge)?,to).await?;sends+=1;}},
                incoming=self.socket.recv_from(&mut buffer)=>{
                    let(n,from)=incoming?;
                    if !from.ip().is_loopback()||self.application.is_some_and(|a|a!=from)||!self.check.valid(&buffer[..n]){continue;}
                    self.application.get_or_insert(from);
                    if buffer[4]==1{if sends<120{self.socket.send_to(&self.check.frame(2,&buffer[40..56])?,from).await?;sends+=1;}}
                    else if c::eq(&buffer[40..56],&self.check.challenge){
                        #[cfg(windows)]self.session.freeze();
                        let left=deadline.saturating_duration_since(tokio::time::Instant::now());ensure!(!left.is_zero(),"路径校验已过期");return Ok(left);
                    }
                }
            }
        }
    }
    fn pipe(&self, remaining: Duration) -> Pipe {
        let (tx, mut outgoing) = mpsc::channel::<Vec<u8>>(128);
        let (incoming, rx) = mpsc::channel(128);
        let cancel = self.stop.child_token();
        let token = cancel.clone();
        let socket = self.socket.clone();
        let application = self.application.unwrap();
        let network = self.context.network_id.clone();
        let check = self.check.clone();
        let deadline = Instant::now() + remaining;
        tokio::spawn(async move {
            let _cancel = token.clone().drop_guard();
            let mut buffer = [0; 2049];
            let mut completions = 0;
            loop {
                tokio::select! {_=token.cancelled()=>break,
                    p=outgoing.recv()=>match p{Some(p)=>if let Some((wire,body))=conwu_core::link::unwrap(&p){if wire==network&&socket.send_to(body,application).await.is_err(){break;}},None=>break},
                    p=socket.recv_from(&mut buffer)=>match p{Ok((n,from))if from==application&&n<=1344=>{
                        if n>=4&&&buffer[..4]==b"SLM4"{if let Ok(frame)=conwu_core::link::wrap(&network,&buffer[..n]){let _=incoming.try_send(frame);}}
                        else if Instant::now()<deadline&&completions<24&&check.valid(&buffer[..n])&&buffer[4]==1{if let Ok(frame)=check.frame(2,&buffer[40..56]){let _=socket.send_to(&frame,application).await;completions+=1;}}
                        // Stale SLF1 never extends an attempt or reaches business.
                    },Ok(_)=>{},Err(_)=>break}
                }
            }
        });
        Pipe {
            tx,
            rx,
            cancel,
            pin: String::new(),
        }
    }
    async fn close(&mut self) -> Result<()> {
        self.stop.cancel();
        self.attachment.close().await?;
        #[cfg(windows)]
        self.lease.capture.close().await?;
        let _ = std::fs::remove_file(&self.config);
        Ok(())
    }
    fn peer(&self) -> SocketAddr {
        #[cfg(windows)]
        {
            self.session.peer()
        }
        #[cfg(not(windows))]
        {
            self.attachment.descriptor.peer
        }
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.stop.cancel();
        self.attachment.cancel.cancel();
    }
}
struct Attempt {
    message: Message,
    lease: Option<Lease>,
    prepared: Option<Prepared>,
    began: Instant,
    started: bool,
    path: Option<CancellationToken>,
    last_publish: Instant,
    remote_sequence: i64,
}
async fn close_confirmed(mut prepared: Prepared) {
    while prepared.close().await.is_err() {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
fn stamp(profile: &Profile, message: &mut Message, sequence: &mut i64) -> Result<()> {
    *sequence += 1;
    message.sequence = *sequence;
    message.message_id = Uuid::new_v4();
    message.expires = unix_seconds() + 55;
    message.sign(profile)
}
fn response(
    profile: &Profile,
    peer: &Member,
    boot: Uuid,
    remote: Uuid,
    candidate: Candidate,
    offer: Option<&Message>,
    sequence: &mut i64,
) -> Result<Message> {
    let mut message = Message {
        version: 1,
        message_id: Uuid::new_v4(),
        from_slot: profile.member.slot,
        from_device: profile.member.device.clone(),
        from_boot: boot,
        to_slot: peer.slot,
        to_device: peer.device.clone(),
        to_boot: remote,
        sequence: 1,
        attempt_id: offer.map_or_else(Uuid::new_v4, |o| o.attempt_id),
        nomination_revision: offer.map_or(1, |o| o.nomination_revision),
        validation_nonce: offer.map_or_else(Uuid::new_v4, |o| o.validation_nonce),
        profile: 2,
        protocol_client_slot: profile.member.slot.min(peer.slot),
        nominator_slot: profile.member.slot.min(peer.slot),
        candidate: Some(candidate),
        peer_candidate: offer.and_then(|o| o.candidate.clone()),
        stage: if offer.is_some() { 2 } else { 1 },
        expires: unix_seconds() + 55,
        signature: String::new(),
    };
    stamp(profile, &mut message, sequence)?;
    Ok(message)
}
async fn post(
    http: &reqwest::Client,
    settings: &crate::model::Settings,
    profile: &Profile,
    message: &Message,
) -> Result<()> {
    http.post(
        url::Url::parse(&settings.service)?
            .join(&format!("v3/mesh/{}/traversal", profile.pair.network))?,
    )
    .bearer_auth(hex::encode_upper(profile.pair.key("discovery-auth")))
    .json(&json!({"Messages":[message]}))
    .send()
    .await?
    .error_for_status()?;
    Ok(())
}
struct WatchCursor {
    epoch: Uuid,
    cursor: i64,
    unsupported: bool,
}
async fn snapshot(
    http: &reqwest::Client,
    settings: &crate::model::Settings,
    profile: &Profile,
    boot: Uuid,
    watch: &mut WatchCursor,
) -> Result<Snapshot> {
    let base = url::Url::parse(&settings.service)?;
    let auth = hex::encode_upper(profile.pair.key("discovery-auth"));
    let mut watched = !watch.unsupported;
    let response = if watched {
        let request =
            crate::coordinator::WatchRequest::create(profile, boot, watch.epoch, watch.cursor)?;
        let response = http
            .post(base.join(&format!("v3/mesh/{}/watch", profile.pair.network))?)
            .timeout(Duration::from_secs(35))
            .bearer_auth(&auth)
            .json(&request)
            .send()
            .await?;
        if matches!(response.status().as_u16(), 404 | 405) {
            watch.unsupported = true;
            watched = false;
            http.get(base.join(&format!("v3/mesh/{}", profile.pair.network))?)
                .bearer_auth(&auth)
                .send()
                .await?
        } else {
            response
        }
    } else {
        http.get(base.join(&format!("v3/mesh/{}", profile.pair.network))?)
            .bearer_auth(&auth)
            .send()
            .await?
    }
    .error_for_status()?;
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut bytes = vec![];
    while let Some(part) = stream.next().await {
        bytes.extend_from_slice(&part?);
        ensure!(bytes.len() <= 196608, "打洞快照过大");
    }
    if watched {
        let reply: crate::coordinator::WatchResponse = conwu_core::parse_rest(&bytes)?;
        ensure!(
            !reply.server_epoch.is_nil()
                && reply.cursor >= 0
                && reply.changes.len() <= 128
                && (reply.server_epoch != watch.epoch
                    || reply.cursor >= watch.cursor
                    || reply.reset)
                && (reply.server_epoch == watch.epoch || reply.reset),
            "协调等待游标无效"
        );
        watch.epoch = reply.server_epoch;
        watch.cursor = reply.cursor;
        Ok(reply.snapshot)
    } else {
        Ok(conwu_core::parse_rest(&bytes)?)
    }
}
pub async fn run(engine: Arc<Engine>, running: Arc<Running>) {
    let mut attempt: Option<Attempt> = None;
    let mut sequence = 0;
    let mut retry = Instant::now();
    let mut next_error = Instant::now();
    let mut http: Option<(String, reqwest::Client)> = None;
    let mut watch = WatchCursor {
        epoch: Uuid::nil(),
        cursor: 0,
        unsupported: false,
    };
    loop {
        tokio::select! {_=running.cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(350))=>{}}
        let n = running.config.read().unwrap().clone();
        if n.profile
            .as_ref()
            .is_none_or(|p| crate::runtime::remote_member(p).is_none())
            || attempt
                .as_ref()
                .is_some_and(|a| a.path.as_ref().is_some_and(CancellationToken::is_cancelled))
        {
            if let Some(mut old) = attempt.take() {
                if let Some(path) = old.path.take() {
                    path.cancel();
                }
                if let Some(prepared) = old.prepared.take() {
                    close_confirmed(prepared).await;
                }
            }
        }
        if n.settings.mode().ok() != Some("faketcp")
            || n.settings.existing_only()
            || n.settings.discovery_mode != "coordinator"
            || n.settings.service.is_empty()
            || n.paused
        {
            continue;
        }
        let Some(profile) = n.profile.as_ref() else {
            continue;
        };
        let Some(peer) = crate::runtime::remote_member(profile) else {
            continue;
        };
        let result=async{
            let key=format!("{}/{}",n.settings.service,n.settings.certificate_pin);
            if http.as_ref().is_none_or(|(k,_)|*k!=key){http=Some((key,crate::transport::pinned_http(&n.settings.certificate_pin)?));watch=WatchCursor{epoch:Uuid::nil(),cursor:0,unsupported:false};}
            let http=&http.as_ref().unwrap().1;
            let state=tokio::select!{_=running.cancel.cancelled()=>anyhow::bail!("受管打洞已取消"),r=snapshot(http,&n.settings,profile,running.boot,&mut watch)=>r?};
            conwu_core::metadata::successor(&state.directory,profile.directory.as_ref().unwrap())?;
            let remote=state.nodes.iter().find(|e|e.slot==peer.slot&&e.device==peer.device).and_then(|e:&Envelope|e.open(profile,&peer).ok()).and_then(|a|a.traversal).and_then(|v|serde_json::from_value::<Capabilities>(v).ok()).filter(|c|c.validate().is_ok()&&c.profiles.contains(&2));
            let Some(remote)=remote else{return Ok::<(),anyhow::Error>(())};
            let learning=capabilities(&running).is_some_and(|c|c.tcp_peer_reflexive==1)&&remote.tcp_peer_reflexive==1&&state.capabilities.tcp_peer_reflexive==1;
            if attempt.as_ref().is_some_and(|a|a.message.to_boot!=remote.boot_id||a.message.to_slot!=peer.slot||a.message.to_device!=peer.device||a.path.as_ref().is_some_and(CancellationToken::is_cancelled)||a.began.elapsed()>Duration::from_secs(35)&&!a.started){
                if let Some(mut old)=attempt.take(){if let Some(path)=old.path.take(){path.cancel();}if let Some(p)=old.prepared.take(){close_confirmed(p).await;}}retry=Instant::now()+Duration::from_secs(5);
            }
            for message in state.traversal.iter().filter(|m|m.from_slot==peer.slot&&m.to_slot==profile.member.slot&&m.from_boot==remote.boot_id&&m.to_boot==running.boot){
                message.verify(&profile.pair.network,&peer,&profile.member)?;
                ensure!(message.profile==2&&message.protocol_client_slot==profile.member.slot.min(peer.slot)&&message.nominator_slot==profile.member.slot.min(peer.slot),"受管路径角色不符");
                if message.stage==1&&peer.slot<profile.member.slot&&attempt.is_none()&&Instant::now()>=retry&&!running.metrics.read().unwrap().connected{
                    let candidate=message.candidate.as_ref().context("Offer 缺少候选")?;
                    ensure!(candidate.prediction.is_none()&&(!candidate.peer_reflexive||learning)&&candidate.exploration.is_none()&&!candidate.standby,"尚未授权此增强候选");
                    let lease=Lease::gather(&engine,&running,learning).await?;
                    let ready=response(profile,&peer,running.boot,remote.boot_id,lease.candidate.clone(),Some(message),&mut sequence)?;
                    let context=Context::from_message(&profile.pair.network,&ready,true)?;
                    let prepared=Prepared::create(&engine,lease,context,profile,&peer,candidate.endpoint.parse()?,&running.cancel).await?;
                    attempt=Some(Attempt{message:ready,lease:None,prepared:Some(prepared),began:Instant::now(),started:false,path:None,last_publish:Instant::now(),remote_sequence:message.sequence});
                    post(http,&n.settings,profile,&attempt.as_ref().unwrap().message).await?;
                    running.metrics.write().unwrap().managed=json!({"phase":"Ready","attempt":message.attempt_id,"selected":false});
                    continue;
                }
                let Some(active)=attempt.as_mut()else{continue};
                if message.attempt_id!=active.message.attempt_id||message.nomination_revision!=active.message.nomination_revision||message.validation_nonce!=active.message.validation_nonce||message.sequence<=active.remote_sequence{continue;}
                if message.stage==4{active.began=Instant::now()-Duration::from_secs(40);active.started=false;continue;}
                ensure!(message.peer_candidate==active.message.candidate,"本机候选版本已改变");
                if let Some(remote)=&active.message.peer_candidate{ensure!(message.candidate.as_ref()==Some(remote),"远端候选版本已改变");}
                active.remote_sequence=message.sequence;
                if message.stage==2&&profile.member.slot<peer.slot&&active.message.stage==1{
                    active.message.peer_candidate=message.candidate.clone();active.message.stage=3;
                    let context=Context::from_message(&profile.pair.network,&active.message,true)?;
                    let lease=active.lease.take().context("准备资源已转移")?;
                    active.prepared=Some(Prepared::create(&engine,lease,context,profile,&peer,message.candidate.as_ref().unwrap().endpoint.parse()?,&running.cancel).await?);
                    stamp(profile,&mut active.message,&mut sequence)?;post(http,&n.settings,profile,&active.message).await?;active.last_publish=Instant::now();
                }else if message.stage==3&&profile.member.slot>peer.slot&&active.message.stage==2{active.message.stage=3;}
                if active.message.stage==3&&!active.started{
                    let prepared=active.prepared.as_mut().context("捕获尚未准备")?;
                    let remaining=prepared.activate().await?;let pipe=prepared.pipe(remaining);active.path=Some(pipe.cancel.clone());active.started=true;
                    running.metrics.write().unwrap().managed=json!({"phase":"Nominating","attempt":active.message.attempt_id,"selected":false,"fullMtuQualified":true});
                    let server=engine.clone();let id=n.id.clone();let context=prepared.context.clone();let endpoint=prepared.peer();let revision=active.message.nomination_revision;
                    engine.tracker.spawn(async move{server.serve_managed(pipe,endpoint,id,context,revision,remaining).await;});
                }
            }
            if attempt.is_none()&&profile.member.slot<peer.slot&&Instant::now()>=retry&&!running.metrics.read().unwrap().connected{
                let lease=Lease::gather(&engine,&running,learning).await?;let message=response(profile,&peer,running.boot,remote.boot_id,lease.candidate.clone(),None,&mut sequence)?;post(http,&n.settings,profile,&message).await?;
                running.metrics.write().unwrap().managed=json!({"phase":"Offering","attempt":message.attempt_id,"selected":false});
                attempt=Some(Attempt{message,lease:Some(lease),prepared:None,began:Instant::now(),started:false,path:None,last_publish:Instant::now(),remote_sequence:0});
            }
            if let Some(active)=attempt.as_mut(){
                if active.last_publish.elapsed()>Duration::from_secs(10){if active.started&&running.metrics.read().unwrap().managed["selected"]==true{active.message.stage=5;}stamp(profile,&mut active.message,&mut sequence)?;post(http,&n.settings,profile,&active.message).await?;active.last_publish=Instant::now();}
            }
            Ok(())
        }.await;
        if let Err(error) = result {
            if next_error <= Instant::now() {
                let _ = engine.events.try_send(crate::runtime::Event::Log {
                    level: "WARN".into(),
                    text: format!("网络 {} 受管打洞暂未完成：{error}", n.name),
                });
                next_error = Instant::now() + Duration::from_secs(30);
            }
            if !running.metrics.read().unwrap().connected {
                if let Some(mut old) = attempt.take() {
                    if let Some(path) = old.path.take() {
                        path.cancel();
                    }
                    if let Some(prepared) = old.prepared.take() {
                        close_confirmed(prepared).await;
                    }
                }
                retry = Instant::now() + Duration::from_secs(5);
            }
        }
    }
    if let Some(mut old) = attempt.take() {
        if let Some(path) = old.path.take() {
            path.cancel();
        }
        if let Some(prepared) = old.prepared.take() {
            close_confirmed(prepared).await;
        }
    }
}
