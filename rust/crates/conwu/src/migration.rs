//! Explicit, read-only import. Never open the legacy ProfileStore (which can
//! migrate/overwrite files on read); all output belongs to a fresh Rust Store.
use crate::{
    model::{Configuration, Database, Network, Settings},
    store::Store,
};
use anyhow::{Context, Result, ensure};
use conwu_core::{crypto as c, identity::Profile, unix_seconds};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn read(path: &Path, entropy: &[u8]) -> Result<Value> {
    for parent in path.ancestors() {
        crate::store::reject_link(parent)?;
    }
    ensure!(
        std::fs::metadata(path)?.len() <= 4 * 1024 * 1024,
        "旧配置过大"
    );
    let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
    #[cfg(windows)]
    let bytes = if path
        .extension()
        .is_some_and(|s| s == "dpapi" || s == "protected")
    {
        zeroize::Zeroizing::new(crate::store::dpapi(&bytes, false, entropy)?)
    } else {
        bytes
    };
    #[cfg(not(windows))]
    let _ = entropy;
    Ok(serde_json::from_slice(&bytes)?)
}
fn profile_file(root: &Path) -> PathBuf {
    root.join(if cfg!(windows) {
        "profile.dpapi"
    } else {
        "profile.json"
    })
}
fn camel(value: &Value) -> Value {
    match value {
        Value::Object(v) => Value::Object(
            v.iter()
                .map(|(k, v)| {
                    let mut chars = k.chars();
                    let key = chars
                        .next()
                        .map(|c| c.to_ascii_lowercase().to_string() + chars.as_str())
                        .unwrap_or_default();
                    (key, camel(v))
                })
                .collect(),
        ),
        Value::Array(a) => json!(a.iter().map(camel).collect::<Vec<_>>()),
        _ => value.clone(),
    }
}
fn settings(v: &Value) -> Result<Settings> {
    let mut value = if v["SavedNetworkSettings"].is_object() {
        camel(&v["SavedNetworkSettings"])
    } else {
        camel(v)
    };
    if !value["service"].is_string() {
        value["service"] = v["CoordinationService"].as_str().unwrap_or("").into();
    }
    if let Some(learning) = v.get("TcpPeerReflexive").and_then(Value::as_bool) {
        value["tcpPeerReflexive"] = json!(learning);
    }
    for option in [
        "TcpSynObservation",
        "TcpPortCalibration",
        "TcpPortPrediction",
        "UdpExploration",
        "UdpIpv6",
        "FakeTcpIpv6",
        "QualityFeedback",
        "StandbyPaths",
        "PathDiagnostics",
        "LegacyEgressPacing",
    ] {
        ensure!(
            v[option] != true,
            "旧网络启用了尚未完成等价验证的研究选项 {option}；保留原版运行并先完成该项迁移"
        );
    }
    ensure!(
        v["ManagedEgressMbps"].as_u64().unwrap_or(0) == 0,
        "旧网络启用了受管出口整形，需先完成对应迁移验证"
    );
    if !value["certificatePin"].is_string() {
        value["certificatePin"] = v["CoordinationPin"].as_str().unwrap_or("").into();
    }
    if value["discoveryMode"] == "" || value["discoveryMode"].is_null() {
        value["discoveryMode"] = json!(if value["connectionSource"] == "existing" {
            "existing"
        } else if value["pkarrPublish"] == true {
            "pkarr"
        } else if value["service"].as_str().is_some_and(|s| !s.is_empty()) {
            "coordinator"
        } else {
            "direct"
        });
    }
    // DeviceProfile contains credentials and retired settings: never retain its
    // unknown properties in Settings.extra or expose them through /api/status.
    let allowed = serde_json::to_value(Settings::default())?;
    value
        .as_object_mut()
        .context("旧设置无效")?
        .retain(|k, _| allowed.get(k).is_some());
    for key in ["tcpStun", "udpStun", "pkarrGateways"] {
        if value[key].is_null() {
            value.as_object_mut().unwrap().remove(key);
        }
    }
    let s: Settings = serde_json::from_value(value)?;
    s.validate()?;
    Ok(s)
}
fn checkpoints(folder: &Path, all: &mut std::collections::BTreeMap<String, Value>) -> Result<()> {
    let file = folder.join("pkarr-checkpoints.protected");
    if !file.is_file() {
        return Ok(());
    }
    let value = read(&file, b"ConWU-private-document-v1")?;
    let values = value.as_array().context("旧PKARR检查点格式无效")?;
    ensure!(values.len() <= 4096, "旧PKARR检查点过多");
    for v in values {
        let key = v["Key"].as_str().context("旧PKARR检查点缺少公钥")?;
        crate::pkarr::source_key(&format!("pkarr://{key}"))?;
        let seq = v["Sequence"].as_i64().context("旧PKARR检查点缺少序号")?;
        let digest = v["Digest"]
            .as_str()
            .context("旧PKARR检查点缺少摘要")?
            .to_ascii_lowercase();
        ensure!(
            seq > 0 && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "旧PKARR检查点无效"
        );
        if let Some(old) = all.get(key) {
            ensure!(
                old["sequence"] != seq || old["digest"] == digest,
                "旧PKARR同序检查点冲突"
            );
        }
        if all
            .get(key)
            .is_none_or(|old| old["sequence"].as_i64().unwrap() < seq)
        {
            all.insert(key.into(), json!({"sequence":seq,"digest":digest}));
        }
    }
    ensure!(all.len() <= 4096, "合并后的PKARR检查点超过上限");
    Ok(())
}
pub fn import(from: &Path, to: &Store) -> Result<Value> {
    let from = from.canonicalize()?;
    let target = to.root.canonicalize()?;
    ensure!(
        !from.starts_with(&target) && !target.starts_with(&from),
        "导入与输出目录必须相互独立"
    );
    ensure!(
        !to.root.join("database.private.json").exists(),
        "导入只允许新的实验数据目录"
    );
    let device = read(&profile_file(&from), b"StreamLink-profile-v2")?;
    let mut pkarr_checkpoints = std::collections::BTreeMap::new();
    checkpoints(&from, &mut pkarr_checkpoints)?;
    let mut db = Database::default();
    db.device_name = device["DeviceName"].as_str().unwrap_or("ConWU").into();
    c::check_name(&db.device_name)?;
    if let Some(node) = device["NodeSigningPrivate"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        c::public(node)?;
        db.node_private = node.into();
    }
    db.log_level = device["LogLevel"].as_str().unwrap_or("info").into();
    if let Some(value) = device.get("RejoinCredential").filter(|v| v.is_object()) {
        let credential: conwu_core::rejoin::Credential = serde_json::from_value(value.clone())?;
        credential.validate()?;
        db.rejoin_credentials.push(credential);
    }
    // Preserve the intent; importing does not register a service, change startup
    // entries, start coordination, load a driver, or start a tunnel.
    db.device_settings["autoStart"] = json!(device["AutoStart"].as_bool().unwrap_or(false));
    if device["Coordinator"].is_object() {
        db.device_settings["coordinator"] = camel(&device["Coordinator"]);
    }
    if device["UuTakeover"].is_object() {
        db.device_settings["uuTakeover"] = camel(&device["UuTakeover"]);
    }
    let folder = from.join("networks");
    let mut inputs = vec![];
    if folder.is_dir() {
        crate::store::reject_link(&folder)?;
        for entry in std::fs::read_dir(&folder)?.take(1025) {
            let path = entry?.path();
            if path.is_dir()
                && path
                    .file_name()
                    .is_some_and(|s| conwu_core::valid_id(&s.to_string_lossy()))
            {
                inputs.push(path);
            }
        }
    }
    ensure!(inputs.len() <= 1024, "旧网络记录数量过多，请先核对归档");
    if device["Mesh"].is_object() {
        inputs.push(from.clone());
    }
    for folder in inputs {
        checkpoints(&folder, &mut pkarr_checkpoints)?;
        let info = if folder == from {
            json!({"Id":conwu_core::id(),"Name":"原网络"})
        } else {
            read(&folder.join("network-info.json"), &[])?
        };
        if info["Removed"] == true || info["PendingEnrollment"] == true {
            continue;
        }
        let v = if folder == from {
            device.clone()
        } else {
            read(&profile_file(&folder), b"StreamLink-profile-v2")?
        };
        if !v["Mesh"].is_object() {
            continue;
        }
        ensure!(db.networks.len() < 32, "有效旧网络数量超过32条");
        let p: Profile = serde_json::from_value(v["Mesh"].clone())?;
        p.validate()?;
        ensure!(
            p.directory
                .as_ref()
                .is_some_and(|d| d.pairwise && d.members.len() <= 2),
            "只导入主从双机网络，旧多成员身份保持原样"
        );
        ensure!(
            p.member.device == conwu_core::identity::network_id(&c::public(&db.node_private)?)?,
            "旧网络与持久设备身份不符"
        );
        let mut s = settings(&v)?;
        if let Some(value) = v.get("RejoinCredential").filter(|v| v.is_object()) {
            let credential: conwu_core::rejoin::Credential = serde_json::from_value(value.clone())?;
            credential.validate()?;
            if !db
                .rejoin_credentials
                .iter()
                .any(|c| c.network == credential.network)
            {
                db.rejoin_credentials.push(credential);
            }
        }
        // Saved policy contains the user's subscription, whereas runtime
        // entries may contain first-contact addresses or discovered bindings.
        let saved = &v["SavedNetworkSettings"];
        if !saved
            .get("ExistingEntries")
            .or_else(|| saved.get("existingEntries"))
            .is_some_and(Value::is_array)
        {
            s.existing_entries =
                serde_json::from_value(v["ExistingEntries"].clone()).unwrap_or(s.existing_entries);
        }
        for entry in &mut s.existing_entries {
            entry.peer_slot = if entry.peer_slot == 0 || entry.peer_slot == p.member.slot as i16 {
                0
            } else {
                -1
            };
        }
        s.validate()?;
        ensure!(s.mode()? == p.pair.mode, "旧网络身份与设置协议不一致");
        let cid = conwu_core::id();
        let id = info["Id"].as_str().context("旧网络编号缺失")?.to_owned();
        ensure!(
            conwu_core::valid_id(&id) && !db.networks.iter().any(|n| n.id == id),
            "旧网络编号重复或无效"
        );
        let name = info["Name"].as_str().unwrap_or("已导入网络").to_owned();
        if let Some(value) = v.get("RejoinHistory").filter(|v| v.is_array()) {
            let history: Vec<conwu_core::rejoin::History> = serde_json::from_value(value.clone())?;
            ensure!(history.len() <= 32, "旧重新加入记录超过上限");
            for h in &history {
                ensure!(h.network == p.pair.network, "旧重新加入记录跨网络");
                conwu_core::identity::validate_member(&h.network, &p.owner_key, &h.former)?;
            }
            db.rejoin_history.insert(id.clone(), history);
        }
        c::check_name(&name)?;
        db.configurations.push(Configuration {
            id: cid.clone(),
            name: name.clone(),
            revision: 1,
            settings: s.clone(),
        });
        let peer = p
            .directory
            .as_ref()
            .unwrap()
            .members
            .iter()
            .find(|m| m.slot != p.member.slot);
        let source = v["PkarrPeers"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|b| {
                peer.is_some_and(|m| {
                    b["Slot"] == m.slot
                        && b["Device"] == m.device
                        && b["SigningKey"] == m.signing_key
                })
            })
            .and_then(|b| b["Source"].as_str())
            .unwrap_or("")
            .to_owned();
        #[cfg(windows)]
        let legacy_adapter = {
            let owner = v["AdapterScope"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| v["Device"].as_str().filter(|s| !s.is_empty()))
                .unwrap_or(&p.member.device)
                .to_owned();
            ensure!(conwu_core::valid_id(&owner), "旧虚拟网卡所有权作用域无效");
            Some(crate::model::LegacyAdapter {
                owner,
                network: p.pair.network.clone(),
                slot: p.member.slot,
            })
        };
        #[cfg(not(windows))]
        let legacy_adapter = None;
        db.networks.push(Network {
            legacy_adapter,
            creation_operation: String::new(),
            creation_digest: String::new(),
            id,
            name,
            configuration_id: cid,
            settings: s,
            created_here: !p.owner_private.is_empty(),
            profile: Some(p),
            enabled: v["Enabled"].as_bool().unwrap_or(true),
            paused: v["ConnectionPaused"].as_bool().unwrap_or(false),
            created_at: v["NetworkEstablishedAt"].as_i64().unwrap_or(unix_seconds()),
            approved_settings: v
                .get("ReceivedNetworkSettings")
                .filter(|v| v.is_object())
                .cloned(),
            peer_name: String::new(),
            pkarr_seed: v["PkarrSeed"].as_str().unwrap_or("").into(),
            pkarr_sequence: v["PkarrSequence"].as_i64().unwrap_or(0),
            peer_pkarr: source,
            bootstrap: vec![],
        });
    }
    if db
        .networks
        .iter()
        .any(|n| n.created_here && n.settings.mode().ok() == Some("https"))
    {
        let encoded = read(
            &from.join("stream-tls.protected"),
            b"ConWU-private-document-v1",
        )?;
        let pfx =
            zeroize::Zeroizing::new(c::unb64(encoded.as_str().context("旧 TLS 身份文档无效")?)?);
        let pem = import_tls(&pfx)?;
        let key = rcgen::KeyPair::from_pem(&pem)?;
        let pin = hex::encode_upper(c::hash(key.public_key_der()));
        ensure!(
            db.networks
                .iter()
                .filter(|n| n.created_here && n.settings.mode().ok() == Some("https"))
                .all(|n| n
                    .profile
                    .as_ref()
                    .unwrap()
                    .pair
                    .transport_key_pin
                    .as_ref()
                    .is_some_and(|p| p.eq_ignore_ascii_case(&pin))),
            "旧 TLS 身份与获批公钥不符，拒绝替换已配对身份"
        );
        to.write_secret("stream-private.pem", pem.as_bytes(), false)?;
    }
    db.selected_network_id = db
        .networks
        .first()
        .map(|n| n.id.clone())
        .unwrap_or_default();
    let coordination = from.join("coordination");
    if coordination.is_dir() {
        crate::coordination_store::import_legacy(&coordination, to)?;
    }
    for (key, name) in [
        ("certificateFile", "coordinator-certificate.pem"),
        ("certificateKeyFile", "coordinator-private.pem"),
    ] {
        let source = db.device_settings["coordinator"][key]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let source = source.map(|s| Store::resolve_root(&s)).transpose()?;
        if let Some(source) = source.filter(|s| s.starts_with(&from) && s.is_file()) {
            for parent in source.ancestors() {
                crate::store::reject_link(parent)?;
            }
            ensure!(
                std::fs::metadata(&source)?.len() <= 1024 * 1024,
                "旧协调证书文件过大"
            );
            to.write(name, &std::fs::read(&source)?, false)?;
            db.device_settings["coordinator"][key] = json!(to.root.join(name));
        }
    }
    if !pkarr_checkpoints.is_empty() {
        to.write(
            "pkarr-checkpoints.json",
            &serde_json::to_vec(&pkarr_checkpoints)?,
            false,
        )?;
    }
    let remote = from.join("remote-admin.json");
    if remote.is_file() {
        let value = read(&remote, &[])?;
        to.write("remote-admin.json", &serde_json::to_vec(&value)?, false)?;
    }
    let ui_sid = from.join("ui-user.sid");
    if ui_sid.is_file() {
        crate::store::reject_link(&ui_sid)?;
        ensure!(std::fs::metadata(&ui_sid)?.len() <= 256, "旧UI授权文件过大");
        to.write("ui-user.sid", &std::fs::read(&ui_sid)?, false)?;
    }
    for name in ["conwu.log", "streamlink.log"] {
        let source = from.join("logs").join(name);
        if source.is_file() {
            for parent in source.ancestors() {
                crate::store::reject_link(parent)?;
            }
            ensure!(
                std::fs::metadata(&source)?.len() <= 16 * 1024 * 1024,
                "旧日志文件过大，请保留原日志目录并单独迁移"
            );
            to.write(&format!("legacy-{name}"), &std::fs::read(source)?, false)?;
        }
    }
    to.save(&db)?;
    let report = json!({"networks":db.networks.len(),"configurations":db.configurations.len(),"sourceModified":false,"started":false,"format":"ConWU Rust v1"});
    to.write(
        "migration-report.json",
        &serde_json::to_vec_pretty(&report)?,
        false,
    )?;
    Ok(report)
}
#[cfg(target_os = "linux")]
fn import_tls(pfx: &[u8]) -> Result<zeroize::Zeroizing<String>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut process = Command::new("openssl")
        .args(["pkcs12", "-nodes", "-nocerts", "-passin", "pass:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    process
        .stdin
        .take()
        .context("无法读取 TLS 输入管道")?
        .write_all(pfx)?;
    let output = process.wait_with_output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 32768,
        "旧 PFX 转换失败"
    );
    let pem = zeroize::Zeroizing::new(String::from_utf8(output.stdout)?);
    rcgen::KeyPair::from_pem(&pem)?;
    Ok(pem)
}
#[cfg(windows)]
fn import_tls(pfx: &[u8]) -> Result<zeroize::Zeroizing<String>> {
    use windows_sys::Win32::Security::Cryptography::*;
    // PFX keys are imported ephemerally and exported immediately; no system
    // certificate store or persisted machine key is changed during import.
    unsafe {
        let blob = CRYPT_INTEGER_BLOB {
            cbData: pfx.len() as u32,
            pbData: pfx.as_ptr().cast_mut(),
        };
        let certificates = PFXImportCertStore(
            &blob,
            std::ptr::null(),
            CRYPT_EXPORTABLE | PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP,
        );
        ensure!(!certificates.is_null(), "无法导入旧 PFX 身份");
        struct Certificates(HCERTSTORE);
        impl Drop for Certificates {
            fn drop(&mut self) {
                unsafe {
                    CertCloseStore(self.0, 0);
                }
            }
        }
        let _certificates = Certificates(certificates);
        let certificate = CertEnumCertificatesInStore(certificates, std::ptr::null());
        ensure!(!certificate.is_null(), "旧 PFX 中缺少证书");
        struct Certificate(*mut CERT_CONTEXT);
        impl Drop for Certificate {
            fn drop(&mut self) {
                unsafe {
                    CertFreeCertificateContext(self.0);
                }
            }
        }
        let _certificate = Certificate(certificate);
        let (mut handle, mut spec, mut owned) = (0usize, 0u32, 0i32);
        let mut size = std::mem::size_of::<usize>() as u32;
        if CertGetCertificateContextProperty(
            certificate,
            CERT_NCRYPT_KEY_HANDLE_PROP_ID,
            (&mut handle as *mut usize).cast(),
            &mut size,
        ) != 0
        {
            spec = CERT_NCRYPT_KEY_SPEC;
        } else {
            // NO_PERSIST_KEY attaches an ephemeral key context instead of a
            // named key container. AcquirePrivateKey alone cannot reopen it.
            let mut context: CERT_KEY_CONTEXT = std::mem::zeroed();
            let mut size = std::mem::size_of::<CERT_KEY_CONTEXT>() as u32;
            if CertGetCertificateContextProperty(
                certificate,
                CERT_KEY_CONTEXT_PROP_ID,
                (&mut context as *mut CERT_KEY_CONTEXT).cast(),
                &mut size,
            ) != 0
            {
                spec = context.dwKeySpec;
                handle = context.Anonymous.hNCryptKey;
            } else {
                ensure!(
                    CryptAcquireCertificatePrivateKey(
                        certificate,
                        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                        std::ptr::null(),
                        &mut handle,
                        &mut spec,
                        &mut owned
                    ) != 0,
                    "旧 TLS 私钥不可读：{}",
                    std::io::Error::last_os_error()
                );
            }
        }
        struct Key(usize, bool);
        impl Drop for Key {
            fn drop(&mut self) {
                if self.1 {
                    unsafe {
                        NCryptFreeObject(self.0);
                    }
                }
            }
        }
        let _key = Key(handle, owned != 0);
        ensure!(spec == CERT_NCRYPT_KEY_SPEC, "旧 TLS 私钥不是 CNG 密钥");
        // The source is already an exportable PFX. Change only this ephemeral
        // imported handle's policy; never a persisted production key container.
        let policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        let status = NCryptSetProperty(
            handle,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            policy.to_le_bytes().as_ptr(),
            4,
            0,
        );
        ensure!(status == 0, "临时 TLS 私钥导出策略失败：0x{status:08X}");
        let mut size = 0;
        let status = NCryptExportKey(
            handle,
            0,
            NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &mut size,
            0,
        );
        ensure!(
            status == 0 && size <= 32768,
            "旧 TLS 私钥不能导出：0x{status:08X}"
        );
        let mut bytes = zeroize::Zeroizing::new(vec![0u8; size as usize]);
        ensure!(
            NCryptExportKey(
                handle,
                0,
                NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                std::ptr::null(),
                bytes.as_mut_ptr(),
                size,
                &mut size,
                0
            ) == 0,
            "旧 TLS 私钥导出失败"
        );
        bytes.truncate(size as usize);
        let pem = zeroize::Zeroizing::new(format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            c::b64(&*bytes)
        ));
        rcgen::KeyPair::from_pem(&pem)?;
        Ok(pem)
    }
}
