//! Bounded, link-free snapshots. Runtime leases, download caches and older
//! snapshots are excluded; identities, certificates and all saved settings
//! (including nested legacy network records) are copied byte for byte.
use anyhow::{Result, ensure};
use std::path::Path;

pub fn copy(source: &Path, destination: &Path, settings: bool) -> Result<()> {
    let source = crate::store::Store::resolve_root(source)?;
    let destination = crate::store::Store::resolve_root(destination)?;
    ensure!(
        source != destination && !source.starts_with(&destination),
        "快照路径重叠"
    );
    let mut budget = (0usize, 0u64);
    tree(&source, &destination, settings, true, &mut budget)
}
fn tree(
    source: &Path,
    destination: &Path,
    settings: bool,
    root: bool,
    budget: &mut (usize, u64),
) -> Result<()> {
    crate::store::reject_link(source)?;
    if destination.exists() {
        crate::store::reject_link(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let path = entry?.path();
        crate::store::reject_link(&path)?;
        let name = path.file_name().unwrap();
        let text = name.to_string_lossy();
        if settings
            && root
            && matches!(
                text.as_ref(),
                "instance.lock"
                    | "panel.private.json"
                    | "lab-session.private.json"
                    | "updates"
                    | "update-rollback"
                    | "maintenance"
                    | "logs"
            )
        {
            continue;
        }
        if settings && root && (text.starts_with("msi-authorization-") || text.ends_with(".tmp")) {
            continue;
        }
        let target = destination.join(name);
        // When maintenance lives in the data store, never copy the snapshot
        // recursively into itself, even if a custom directory name is used.
        if destination.starts_with(&path) {
            continue;
        }
        budget.0 += 1;
        ensure!(budget.0 <= 16384, "快照文件数量超过限制");
        let metadata = std::fs::metadata(&path)?;
        if metadata.is_dir() {
            tree(&path, &target, settings, false, budget)?;
        } else {
            ensure!(metadata.is_file(), "快照含非普通文件");
            budget.1 += metadata.len();
            ensure!(budget.1 <= 2 * 1024 * 1024 * 1024, "快照大小超过限制");
            if target.exists() {
                crate::store::reject_link(&target)?;
            }
            let mut output = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            let mut input = std::fs::File::open(&path)?;
            std::io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            #[cfg(unix)]
            std::fs::set_permissions(&target, metadata.permissions())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_keeps_nested_identities_without_copying_itself() -> Result<()> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()?
            .join("out/lab")
            .join(conwu_core::id());
        let store = crate::store::Store::open(&root)?;
        std::fs::create_dir(store.root.join("networks"))?;
        std::fs::write(store.root.join("networks/member.dpapi"), b"private fixture")?;
        std::fs::create_dir(store.root.join("updates"))?;
        std::fs::write(store.root.join("updates/unused"), b"cache")?;
        let snapshot = store.root.join("maintenance/pending/settings");
        copy(&store.root, &snapshot, true)?;
        ensure!(
            std::fs::read(snapshot.join("networks/member.dpapi"))? == b"private fixture",
            "完整保留嵌套配置"
        );
        ensure!(
            !snapshot.join("updates").exists()
                && !snapshot.join("instance.lock").exists()
                && !snapshot.join("maintenance").exists(),
            "快照不得递归复制自身或运行锁"
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&store.root, store.root.join("foreign"))?;
            ensure!(
                copy(&store.root, &store.root.join("linked-copy"), true).is_err(),
                "拒绝链接"
            );
        }
        Ok(())
    }
}
