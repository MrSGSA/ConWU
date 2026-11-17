use crate::{backend::App, model::VERSION};
use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
fn read_result(store: &crate::store::Store) -> Result<Value> {
    let last = store.checked_file("last-update.json")?;
    let mut previous = if last.is_file() {
        ensure!(std::fs::metadata(&last)?.len() <= 65536, "更新记录过大");
        serde_json::from_slice::<Value>(&std::fs::read(last)?)?
    } else {
        Value::Null
    };
    if !previous.is_null() {
        ensure!(previous.is_object(), "更新记录无效");
        let receipt = crate::backend::revision(&previous);
        previous["receiptId"] = json!(receipt);
        let acknowledged = store.checked_file("update-notice-ack.json")?;
        previous["acknowledged"] = json!(acknowledged.is_file()
            && std::fs::metadata(&acknowledged)?.len() <= 4096
            && serde_json::from_slice::<Value>(&std::fs::read(acknowledged)?)?["receiptId"] == receipt);
        previous["supported"] = json!(true);
    }
    Ok(previous)
}
pub fn restore(store: &crate::store::Store) -> Result<Value> {
    let previous = read_result(store)?;
    if !store.checked_file("update-ready.private.json")?.is_file() {
        return Ok(previous);
    }
    let ready: Value = serde_json::from_slice(&store.read_secret("update-ready.private.json")?)?;
    if matches!(previous["state"].as_str(), Some("Installing" | "Installed" | "Error"))
        && previous["version"] == ready["version"] {
        return Ok(previous);
    }
    let path = crate::store::Store::resolve_root(std::path::Path::new(
        ready["package"].as_str().context("更新安装包路径缺失")?,
    ))?;
    ensure!(
        path.parent() == Some(store.root.join("updates").as_path()),
        "更新包不在独立下载目录"
    );
    ensure!(
        ready["version"].is_string()
            && ready["ticket"]
                .as_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
        "更新确认记录无效"
    );
    let digest = ready["sha256"].as_str().context("更新包校验值缺失")?;
    ensure!(
        std::fs::metadata(&path)?.len() <= 512 * 1024 * 1024
            && crate::updater::hash_file(&path)?.eq_ignore_ascii_case(digest),
        "已下载的安装包已改变或丢失"
    );
    Ok(
        json!({"supported":true,"state":"Ready","message":"已恢复校验过的 Rust 安装包",
        "canInstall":cfg!(feature="local-install"),"version":ready["version"],"ticket":ready["ticket"]}),
    )
}
pub fn status(app: &App) -> Value {
    let busy = app.update_busy.load(std::sync::atomic::Ordering::Acquire);
    let mut current = app.local_update.write().unwrap();
    // The worker writes its result after the new backend is already running.
    // Refresh that small receipt, without hashing the installer on every poll
    // or overwriting a new download/ready task with an older result.
    if !busy && (current.is_null()
        || matches!(current["state"].as_str(), Some("Installing" | "Installed" | "Error"))
            && current["receiptId"].is_string()) {
        if let Ok(result) = read_result(&app.store) {
            if !result.is_null() && (current.is_null() || result["version"] == current["version"]) {
                *current = result;
            }
        }
    }
    let mut value = current.clone();
    if value.is_object() { value["busy"] = json!(busy); }
    value
}
pub fn dismiss(app: &App, receipt: &str) -> Result<Value> {
    use std::sync::atomic::Ordering;
    ensure!(app.update_busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok(), "更新任务正在进行");
    struct Busy<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for Busy<'_> { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }
    let _busy = Busy(&app.update_busy);
    let result = read_result(&app.store)?;
    ensure!(matches!(result["state"].as_str(), Some("Installed" | "Error"))
        && !receipt.is_empty() && result["receiptId"] == receipt, "更新结果已改变，请刷新");
    let mut current = app.local_update.write().unwrap();
    ensure!(current["receiptId"] == result["receiptId"]
        && current["state"] == result["state"], "更新任务已改变，请刷新");
    app.store.write("update-notice-ack.json", &serde_json::to_vec(&json!({"receiptId":receipt}))?, false)?;
    *current = result;
    current["acknowledged"] = json!(true);
    Ok(Value::Null)
}
pub async fn check(source: &str) -> Result<Value> {
    ensure!(
        matches!(source, "github" | "gitee"),
        "请选择 GitHub 或 Gitee"
    );
    // Keep one canonical version/hash manifest. Gitee provides the same MSI
    // through its attachment API, which does not expose GitHub's digest field.
    let feed = "https://api.github.com/repos/MrSGSA/ConWU/releases/latest";
    let response = crate::discovery::http_client()?
        .get(feed)
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response.content_length().is_none_or(|n| n <= 262144),
        "发布元数据过大"
    );
    let mut bytes = vec![];
    let mut stream = response.bytes_stream();
    while let Some(part) = stream.next().await {
        bytes.extend_from_slice(&part?);
        ensure!(bytes.len() <= 262144, "发布元数据过大");
    }
    let release: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        release["draft"] != true && release["prerelease"] != true,
        "不接受预览发布"
    );
    let tag = release["tag_name"].as_str().context("缺少发布标签")?;
    let version = release["tag_name"]
        .as_str()
        .context("缺少版本号")?
        .trim_start_matches('v');
    let (latest, stable) = version_key(version)?;
    ensure!(stable, "更新源没有返回正式版本");
    let (current, current_stable) = version_key(VERSION)?;
    let newer = latest > current || latest == current && !current_stable;
    ensure!(
        release["html_url"] == format!("https://github.com/MrSGSA/ConWU/releases/tag/{tag}"),
        "非官方发布页面"
    );
    let expected = if cfg!(feature = "production") {
        if cfg!(windows) {
            format!("ConWU-{version}-x64.msi")
        } else {
            format!("ConWU-{version}-linux-x64.tar.gz")
        }
    } else {
        format!(
            "conwu-rust-{version}-{}-x86_64{}",
            std::env::consts::OS,
            if cfg!(windows) { ".msi" } else { ".tar.gz" }
        )
    };
    let assets = release["assets"]
        .as_array()
        .or_else(|| release["assets"]["links"].as_array());
    let asset = assets.and_then(|v| {
        v.iter()
            .find(|a| a["name"].as_str().is_some_and(|s| s == expected))
    });
    let mut package = asset
        .cloned()
        .map(|mut a| {
            if a["browser_download_url"].is_null() {
                a["browser_download_url"] = a["direct_asset_url"]
                    .as_str()
                    .or_else(|| a["url"].as_str())
                    .map(|s| json!(s))
                    .unwrap_or(Value::Null);
            }
            a["url"] = a["browser_download_url"].clone();
            a
        })
        .unwrap_or(Value::Null);
    let compatible = !package.is_null();
    if compatible {
        ensure!(
            package["browser_download_url"]
                == format!("https://github.com/MrSGSA/ConWU/releases/download/{tag}/{expected}"),
            "安装附件不属于官方发布"
        );
        if source == "gitee" && newer {
            let mirror = public_json(&format!(
                "https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/tags/{tag}"
            ))
            .await?;
            ensure!(
                mirror["tag_name"] == tag && mirror["prerelease"] != true,
                "Gitee尚未同步本版本"
            );
            let id = mirror["id"]
                .as_u64()
                .filter(|id| *id > 0)
                .context("Gitee发布身份无效")?;
            let files=public_json(&format!("https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/{id}/attach_files?per_page=100")).await?;
            let files = files.as_array().context("Gitee附件列表无效")?;
            ensure!(files.len() <= 128, "Gitee附件过多");
            let matches = files
                .iter()
                .filter(|file| file["name"] == expected)
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1,
                "Gitee尚未同步对应安装包，请选择GitHub或访问Gitee下载"
            );
            let file = matches[0];
            let attachment = file["id"]
                .as_u64()
                .filter(|id| *id > 0)
                .context("Gitee附件身份无效")?;
            ensure!(
                file["size"]
                    .as_u64()
                    .is_none_or(|size| Some(size) == package["size"].as_u64()),
                "Gitee安装包长度与正式版不符"
            );
            let direct =
                format!("https://gitee.com/space4sgsa/ConWU/releases/download/{tag}/{expected}");
            let url = if file["browser_download_url"] == direct {
                direct
            } else {
                format!(
                    "https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/{id}/attach_files/{attachment}/download"
                )
            };
            package["browser_download_url"] = json!(url);
            package["url"] = package["browser_download_url"].clone();
        }
    }
    Ok(
        json!({"currentVersion":VERSION,"platform":std::env::consts::OS,"state":if compatible&&newer{"Available"}else{"UpToDate"},"message":if compatible&&newer{"发现新版本"}else{"暂无适用的更高正式版本"},"latestVersion":version,"releaseUrl":release["html_url"],"notes":release["body"],"updateAvailable":compatible&&newer,"checkedAt":conwu_core::unix_seconds(),"package":package,"downloadSource":source}),
    )
}
fn version_key(version: &str) -> Result<([u32; 3], bool)> {
    ensure!(version.len() <= 64, "版本号过长");
    let value = version
        .strip_prefix('v')
        .unwrap_or(version)
        .split('+')
        .next()
        .unwrap();
    let (core, stable) = value
        .split_once('-')
        .map_or((value, true), |(core, _)| (core, false));
    let parts = core.split('.').collect::<Vec<_>>();
    ensure!(parts.len() == 3, "版本号格式无效");
    let mut result = [0; 3];
    for (i, part) in parts.iter().enumerate() {
        ensure!(
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && !(part.len() > 1 && part.starts_with('0')),
            "版本号格式无效"
        );
        result[i] = part.parse()?;
    }
    Ok((result, stable))
}
async fn public_json(url: &str) -> Result<Value> {
    let response = crate::discovery::http_client()?
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response.content_length().is_none_or(|size| size <= 262144),
        "官方更新元数据过大"
    );
    let mut bytes = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        bytes.extend_from_slice(&chunk?);
        ensure!(bytes.len() <= 262144, "官方更新元数据过大");
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn official_download(url: &url::Url) -> bool {
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.host_str() {
        Some("github.com") => url.path().starts_with("/MrSGSA/ConWU/releases/download/"),
        Some("gitee.com") => {
            if url
                .path()
                .starts_with("/space4sgsa/ConWU/releases/download/")
            {
                return true;
            }
            let parts = url
                .path()
                .trim_end_matches('/')
                .split('/')
                .collect::<Vec<_>>();
            parts.len() == 11
                && parts[..7] == ["", "api", "v5", "repos", "space4sgsa", "ConWU", "releases"]
                && parts[7].parse::<u64>().is_ok_and(|id| id > 0)
                && parts[8] == "attach_files"
                && parts[9].parse::<u64>().is_ok_and(|id| id > 0)
                && parts[10] == "download"
        }
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_update_sources_and_versions_reject_downgrades_and_foreign_assets() -> Result<()> {
        assert!(version_key("1.10.0")?.0 > version_key("1.9.9")?.0);
        assert!(version_key("1.4.5")?.0 < version_key("1.5.0")?.0);
        assert!(!version_key("1.5.0-rc.1")?.1);
        assert!(version_key("1.05.0").is_err());
        for url in [
            "https://github.com/MrSGSA/ConWU/releases/download/v1.5.0/ConWU-1.5.0-x64.msi",
            "https://gitee.com/space4sgsa/ConWU/releases/download/v1.5.0/ConWU-1.5.0-x64.msi",
            "https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/17/attach_files/42/download",
        ] {
            assert!(official_download(&url::Url::parse(url)?));
        }
        for url in [
            "https://gitee.com/api/v5/repos/other/ConWU/releases/17/attach_files/42/download",
            "https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/0/attach_files/42/download",
            "https://gitee.com/space4sgsa/ConWU/releases/download/file?token=untrusted",
            "https://github.com:8443/MrSGSA/ConWU/releases/download/file",
            "https://gitee.com.evil.example/space4sgsa/ConWU/releases/download/file",
        ] {
            assert!(!official_download(&url::Url::parse(url)?));
        }
        Ok(())
    }
}
pub async fn command(app: &App, action: Value) -> Result<Value> {
    use std::sync::atomic::Ordering;
    ensure!(
        app.update_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        "另一个本地更新任务正在进行"
    );
    struct Busy<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for Busy<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _busy = Busy(&app.update_busy);
    let operation = action["action"].as_str().unwrap_or("download");
    if operation == "install" {
        ensure!(
            cfg!(feature = "local-install"),
            "当前实验构建仅校验下载，不执行安装"
        );
        let ready: Value =
            serde_json::from_slice(&app.store.read_secret("update-ready.private.json")?)?;
        ensure!(
            ready["ticket"] == action["ticket"] && ready["version"] == action["version"],
            "本地更新确认已变化，请重新检查"
        );
        let package = std::path::PathBuf::from(ready["package"].as_str().context("安装包缺失")?);
        crate::updater::prepare(
            app,
            &package,
            ready["sha256"].as_str().context("校验值缺失")?,
            ready["version"].as_str().context("版本缺失")?,
        )?;
        return Ok(Value::Null);
    }
    ensure!(operation == "download", "更新操作无效");
    let mut release = app.update.read().unwrap().clone();
    let source = action["source"].as_str().unwrap_or("github");
    if release["downloadSource"] != source {
        release = check(source).await?;
    }
    ensure!(
        release["updateAvailable"] == true,
        "没有已校验的 Rust 兼容更新"
    );
    let package = &release["package"];
    let name = package["name"].as_str().context("缺少安装包名")?;
    ensure!(
        (name.starts_with("conwu-rust-")
            || cfg!(feature = "production") && name.starts_with("ConWU-"))
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "安装包名称无效"
    );
    let url = package["browser_download_url"]
        .as_str()
        .context("缺少官方地址")?;
    let parsed = url::Url::parse(url)?;
    ensure!(official_download(&parsed), "非官方安装包地址");
    let digest = package["digest"]
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .context("缺少可信 SHA-256")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "校验值无效"
    );
    let size = package["size"].as_u64().context("缺少安装包大小")?;
    ensure!((1024..=512 * 1024 * 1024).contains(&size), "安装包大小无效");
    let directory = app.store.root.join("updates");
    if directory.exists() {
        crate::store::reject_link(&directory)?;
    }
    std::fs::create_dir_all(&directory)?;
    let temp = directory.join("download.part");
    if temp.exists() {
        crate::store::reject_link(&temp)?;
    }
    struct Download(std::path::PathBuf);
    impl Drop for Download {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Download(temp.clone());
    let mut file = tokio::fs::File::create(&temp).await?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::limited(3))
        .timeout(std::time::Duration::from_secs(1800))
        .build()?;
    let mut stream = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes_stream();
    let (mut total, mut hash) = (0u64, Sha256::new());
    use tokio::io::AsyncWriteExt;
    while let Some(chunk) = tokio::select! {_=app.engine.cancel.cancelled()=>anyhow::bail!("下载已取消"),r=stream.next()=>r}
    {
        let chunk = chunk?;
        total += chunk.len() as u64;
        ensure!(total <= size, "安装包超出声明长度");
        hash.update(&chunk);
        file.write_all(&chunk).await?;
        *app.local_update.write().unwrap() = json!({"supported":true,"state":"Downloading","downloadedBytes":total,"totalBytes":size,"canInstall":false});
    }
    file.sync_all().await?;
    drop(file);
    ensure!(
        total == size && hex::encode(hash.finalize()).eq_ignore_ascii_case(digest),
        "安装包校验失败"
    );
    let final_path = directory.join(name);
    if final_path.exists() {
        crate::store::reject_link(&final_path)?;
        tokio::fs::remove_file(&final_path).await?;
    }
    tokio::fs::rename(&temp, &final_path).await?;
    let ticket = hex::encode(conwu_core::crypto::random::<32>());
    app.store.write_secret("update-ready.private.json",&serde_json::to_vec(&json!({"package":final_path,"sha256":digest,"version":release["latestVersion"],"ticket":ticket}))?,false)?;
    *app.local_update.write().unwrap() = json!({"supported":true,"state":"Ready","message":if cfg!(feature="local-install"){"Rust 安装包已校验，等待确认"}else{"Rust 安装包已校验；当前实验构建不执行安装"},"downloadedBytes":size,"totalBytes":size,"canInstall":cfg!(feature="local-install"),"ticket":ticket,"version":release["latestVersion"]});
    Ok(Value::Null)
}
