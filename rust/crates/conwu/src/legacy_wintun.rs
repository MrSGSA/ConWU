//! Share the original protected Wintun lease and generation journal for an
//! imported network. The old installer can then safely recover its own adapter
//! after a failed first Rust upgrade, without loading the old runtime here.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{File, OpenOptions},
    io::Write,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Scope {
    network: String,
    slot: u8,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Journal {
    schema: u32,
    scope: Uuid,
    generations: Vec<Uuid>,
    #[serde(default)]
    legacy: Option<Vec<Scope>>,
    #[serde(default)]
    last_closed_at: i64,
    #[serde(default)]
    failed_create: bool,
}
pub struct Guard {
    _leases: Vec<File>,
    path: PathBuf,
    name: String,
    journal: Journal,
    identities: BTreeMap<Uuid, String>,
    issued: HashSet<Uuid>,
}
pub fn identity(network: &str, slot: u8) -> Result<(Uuid, String)> {
    ensure!(
        conwu_core::valid_id(network) && (1..=254).contains(&slot),
        "旧网卡作用域无效"
    );
    let hash = conwu_core::crypto::hash(format!("streamlink-wintun-v4/{network}/{slot}"));
    let id = Uuid::from_bytes_le(hash[..16].try_into()?);
    Ok((id, format!("StreamLink-{}-{slot}", &network[..8])))
}
fn protected_root(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut *mut std::ffi::c_void,
            size: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateDirectoryW(path: *const u16, attributes: *const SECURITY_ATTRIBUTES) -> i32;
    }
    let text = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } != 0,
        "无法创建旧网卡作用域权限"
    );
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
    let error = std::io::Error::last_os_error();
    unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
    ensure!(
        created != 0 || error.raw_os_error() == Some(183),
        "创建旧网卡作用域失败：{error}"
    );
    crate::store::reject_link(path)?;
    Ok(())
}
impl Guard {
    pub fn open(scope: &crate::model::LegacyAdapter) -> Result<Self> {
        let (owner, name) = identity(&scope.owner, 1)?;
        let (mesh, mesh_name) = identity(&scope.network, scope.slot)?;
        let root = PathBuf::from(std::env::var_os("ProgramData").context("缺少ProgramData目录")?)
            .join("StreamLink-Wintun");
        for parent in root.ancestors() {
            crate::store::reject_link(parent)?;
        }
        protected_root(&root)?;
        let mut leases = vec![];
        for id in if owner == mesh {
            vec![owner]
        } else {
            vec![owner, mesh]
        } {
            let path = root.join(format!("{}.lock", id.simple()));
            crate::store::reject_link(&path)?;
            leases.push(
                OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .read(true)
                    .write(true)
                    .share_mode(0)
                    .open(path)
                    .context("原版仍持有本网卡，请先停止原后台")?,
            );
        }
        let path = root.join(format!("{}-adapters.json", owner.simple()));
        crate::store::reject_link(&path)?;
        let journal: Journal = if path.is_file() {
            ensure!(
                std::fs::metadata(&path)?.len() <= 131072,
                "旧网卡代次记录过大"
            );
            serde_json::from_slice(&std::fs::read(&path)?)?
        } else {
            Journal {
                schema: 1,
                scope: owner,
                generations: vec![],
                legacy: None,
                last_closed_at: 0,
                failed_create: false,
            }
        };
        let unique: HashSet<_> = journal.generations.iter().copied().collect();
        ensure!(
            journal.schema == 1
                && journal.scope == owner
                && journal.generations.len() <= 512
                && unique.len() == journal.generations.len()
                && journal
                    .generations
                    .iter()
                    .all(|id| !id.is_nil() && *id != owner)
                && journal.legacy.as_ref().is_none_or(|s| s.len() <= 512),
            "旧网卡代次记录身份不符"
        );
        let mut identities = BTreeMap::from([(owner, name.clone()), (mesh, mesh_name)]);
        for id in &journal.generations {
            identities.insert(*id, format!("{name}-{}", id.simple()));
        }
        for old in journal.legacy.as_deref().unwrap_or_default() {
            let (id, name) = identity(&old.network, old.slot)?;
            if let Some(prior) = identities.insert(id, name.clone()) {
                ensure!(prior.eq_ignore_ascii_case(&name), "旧网卡名称作用域冲突");
            }
        }
        Ok(Self {
            _leases: leases,
            path,
            name,
            journal,
            identities,
            issued: HashSet::new(),
        })
    }
    pub fn identities(&self) -> &BTreeMap<Uuid, String> {
        &self.identities
    }
    pub fn name(&self, id: Uuid) -> String {
        format!("{}-{}", self.name, id.simple())
    }
    pub fn expected_name(&self, id: Uuid) -> String {
        self.identities
            .get(&id)
            .cloned()
            .unwrap_or_else(|| self.name(id))
    }
    pub fn closed_at(&self) -> i64 {
        self.journal.last_closed_at
    }
    pub fn failed_create(&self) -> bool {
        self.journal.failed_create
    }
    pub fn record(&mut self, id: Uuid, retained: &HashSet<Uuid>) -> Result<()> {
        self.journal
            .generations
            .retain(|g| retained.contains(g) || self.issued.contains(g));
        if !self.journal.generations.contains(&id) {
            self.journal.generations.push(id);
        }
        self.issued.insert(id);
        self.identities.insert(id, self.name(id));
        ensure!(
            self.journal.generations.len() <= 512,
            "旧网卡代次记录达到上限"
        );
        if let Some(scopes) = self.journal.legacy.as_mut() {
            scopes.retain(|s| {
                identity(&s.network, s.slot).is_ok_and(|(id, _)| retained.contains(&id))
            });
        }
        self.journal.failed_create = false;
        self.save()
    }
    pub fn closed(&mut self, failed: bool) -> Result<()> {
        self.journal.last_closed_at = conwu_core::unix_seconds() * 1000;
        self.journal.failed_create = failed;
        self.save()
    }
    fn save(&self) -> Result<()> {
        crate::store::reject_link(&self.path)?;
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", Uuid::new_v4().simple()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&serde_json::to_vec(&self.journal)?)?;
            file.sync_all()?;
            drop(file);
            if self.path.exists() {
                crate::store::replace_windows(&temporary, &self.path)?;
            } else {
                std::fs::rename(&temporary, &self.path)?;
            }
            Ok(())
        })();
        if temporary.exists() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dotnet_scope_guid_keeps_little_endian_guid_fields() -> Result<()> {
        let (id, name) = identity("0123456789abcdef0123456789abcdef", 7)?;
        ensure!(id.to_string() == "073ab14a-eb40-7933-6957-1143db491293");
        ensure!(name == "StreamLink-01234567-7");
        ensure!(identity("bad", 1).is_err() && identity(&"a".repeat(32), 0).is_err());
        Ok(())
    }
}
