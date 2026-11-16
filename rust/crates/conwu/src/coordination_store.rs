//! Offline, checksummed coordination snapshots. Membership high-water marks
//! are retained; a damaged registry is never replaced by an older one on boot.
use crate::store::Store;
use anyhow::{Context, Result, ensure};
use conwu_core::{
    crypto as c,
    identity::{self, Directory},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::Path,
};

const MAX: u64 = 64 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
pub struct Registration {
    #[serde(rename = "AuthHash", alias = "auth")]
    pub auth: String,
    #[serde(rename = "Directory", alias = "directory")]
    pub directory: Directory,
}
pub fn decode(bytes: &[u8]) -> Result<BTreeMap<String, Registration>> {
    ensure!(bytes.len() as u64 <= MAX, "协调记录超过上限");
    let values: UniqueMap<Registration> = serde_json::from_slice(bytes)?;
    ensure!(values.0.len() <= 2048, "协调网络超过上限");
    for (network, r) in &values.0 {
        ensure!(
            r.auth.len() == 64
                && r.auth
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'A'..=b'F')),
            "协调授权摘要无效"
        );
        identity::validate_directory(&r.directory, network, &r.directory.owner_key, 0)?;
        ensure!(
            identity::network_id(&r.directory.owner_key)? == *network,
            "协调根身份无效"
        );
    }
    Ok(values.0)
}
struct UniqueMap<T>(BTreeMap<String, T>);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for UniqueMap<T> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = UniqueMap<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("unique network registry")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, T>()? {
                    if values.len() >= 2048 || values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("协调记录重复或超出容量"));
                    }
                }
                Ok(UniqueMap(values))
            }
        }
        de.deserialize_map(Visitor(std::marker::PhantomData))
    }
}
fn checked(path: &Path) -> Result<()> {
    for p in path.ancestors().filter(|p| p.exists()) {
        crate::store::reject_link(p)?;
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    checked(path)?;
    ensure!(std::fs::metadata(path)?.len() <= MAX, "协调文件过大");
    Ok(std::fs::read(path)?)
}
pub fn import_legacy(from: &Path, to: &Store) -> Result<()> {
    if from.join("restore-in-progress.json").exists() {
        anyhow::bail!("旧协调恢复未完成，不能迁移混合代次");
    }
    let mesh = from.join("mesh-networks.json");
    if mesh.is_file() {
        let records = decode(&read(&mesh)?)?;
        to.write("coordinator.json", &serde_json::to_vec(&records)?, false)?;
    }
    let legacy = from.join("networks.json");
    if legacy.is_file() {
        let bytes = read(&legacy)?;
        validate("networks.json", &bytes)?;
        to.write("coordinator-legacy.json", &bytes, false)?;
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    name: String,
    length: usize,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Manifest {
    format: u8,
    created_at: String,
    files: Vec<Entry>,
}
fn validate(name: &str, data: &[u8]) -> Result<()> {
    if name == "mesh-networks.json" {
        decode(data)?;
    } else {
        ensure!(name == "networks.json", "协调备份含未知文件");
        let records: UniqueMap<Value> = serde_json::from_slice(data)?;
        for (n, r) in records.0 {
            ensure!(
                conwu_core::valid_id(&n)
                    && r["AuthHash"].as_str().is_some_and(|s| s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || matches!(b, b'A'..=b'F'))),
                "旧协调身份无效"
            );
            for key in ["One", "Two"] {
                ensure!(
                    r[key]
                        .as_str()
                        .is_some_and(|s| s.is_empty() || conwu_core::valid_id(s)),
                    "旧协调成员无效"
                );
            }
        }
    }
    Ok(())
}
pub(crate) fn timestamp(seconds: i64) -> String {
    let mut days = seconds / 86400;
    let mut year = 1970;
    let leap = |y: i64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    while days >= if leap(year) { 366 } else { 365 } {
        days -= if leap(year) { 366 } else { 365 };
        year += 1;
    }
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    while days >= lengths[month] {
        days -= lengths[month];
        month += 1;
    }
    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        month + 1,
        days + 1,
        seconds % 86400 / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}
pub fn backup(store: &Store, path: &Path, verify: bool) -> Result<Value> {
    let mut files = BTreeMap::new();
    for (local, name) in [
        ("coordinator.json", "mesh-networks.json"),
        ("coordinator-legacy.json", "networks.json"),
    ] {
        let file = store.checked_file(local)?;
        if file.is_file() {
            let bytes = read(&file)?;
            if verify {
                validate(name, &bytes)?;
            }
            files.insert(name.to_owned(), bytes);
        }
    }
    let manifest = Manifest {
        format: 1,
        created_at: timestamp(conwu_core::unix_seconds()),
        files: files
            .iter()
            .map(|(name, bytes)| Entry {
                name: name.clone(),
                length: bytes.len(),
                sha256: hex::encode_upper(c::hash(bytes)),
            })
            .collect(),
    };
    checked(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o600);
    zip.start_file("manifest.json", options)?;
    zip.write_all(&serde_json::to_vec(&manifest)?)?;
    for (name, bytes) in files {
        zip.start_file(name, options)?;
        zip.write_all(&bytes)?;
    }
    zip.finish()?.sync_all()?;
    Ok(serde_json::to_value(manifest)?)
}
fn open(path: &Path) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    checked(path)?;
    ensure!(
        std::fs::metadata(path)?.len() <= MAX * 2 + 1024 * 1024,
        "协调备份过大"
    );
    let mut zip = zip::ZipArchive::new(File::open(path)?)?;
    ensure!((1..=3).contains(&zip.len()), "协调备份清单无效");
    let mut names = std::collections::HashSet::new();
    for i in 0..zip.len() {
        ensure!(
            names.insert(zip.by_index(i)?.name().to_owned()),
            "协调备份包含重复文件"
        );
    }
    let mut manifest = zip.by_name("manifest.json")?;
    ensure!(manifest.size() <= 8192, "备份清单过大");
    let mut bytes = vec![];
    manifest.read_to_end(&mut bytes)?;
    drop(manifest);
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.format == 1 && manifest.files.len() <= 2 && zip.len() == manifest.files.len() + 1,
        "协调备份格式无效"
    );
    let mut files = BTreeMap::new();
    for entry in &manifest.files {
        ensure!(
            (2..=MAX as usize).contains(&entry.length) && !files.contains_key(&entry.name),
            "备份文件长度或名字无效"
        );
        let mut file = zip.by_name(&entry.name)?;
        ensure!(file.size() == entry.length as u64, "备份长度不符");
        let mut bytes = Vec::with_capacity(entry.length);
        file.read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == entry.length && hex::encode_upper(c::hash(&bytes)) == entry.sha256,
            "备份校验失败"
        );
        validate(&entry.name, &bytes)?;
        files.insert(entry.name.clone(), bytes);
    }
    Ok((manifest, files))
}
pub fn inspect(path: &Path) -> Result<Value> {
    Ok(serde_json::to_value(open(path)?.0)?)
}
pub fn restore(store: &Store, path: &Path, confirm: bool) -> Result<Value> {
    ensure!(
        confirm,
        "恢复可能回滚审批和撤销；请明确添加 --confirm-rollback"
    );
    let (_, files) = open(path)?;
    let marker = store.checked_file("coordinator-restore.json")?;
    let previous = if marker.is_file() {
        let record: Value = serde_json::from_slice(&read(&marker)?)?;
        record["previous"]
            .as_str()
            .context("协调恢复记录不完整")?
            .to_owned()
    } else {
        // Keep exactly one completed predecessor. A failed restore keeps its
        // marker and the same predecessor until recovery is explicitly retried.
        let previous = "before-restore.slcoord".to_owned();
        let next = store.checked_file("before-restore.next.slcoord")?;
        if next.exists() {
            std::fs::remove_file(&next)?;
        }
        backup(store, &next, false)?;
        store.write(&previous, &read(&next)?, false)?;
        std::fs::remove_file(next)?;
        store.write(
            "coordinator-restore.json",
            &serde_json::to_vec(&json!({"previous":previous}))?,
            false,
        )?;
        previous
    };
    for (local, name) in [
        ("coordinator.json", "mesh-networks.json"),
        ("coordinator-legacy.json", "networks.json"),
    ] {
        if let Some(bytes) = files.get(name) {
            store.write(local, bytes, false)?;
        } else {
            let file = store.checked_file(local)?;
            if file.exists() {
                std::fs::remove_file(file)?;
            }
        }
    }
    std::fs::remove_file(marker)?;
    Ok(json!({"previousSnapshot":store.root.join(previous),"dataDirectory":store.root}))
}
