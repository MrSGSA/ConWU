use crate::{backend::App, model::VERSION};
use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
pub fn restore(store: &crate::store::Store) -> Result<Value> {
    let last = store.checked_file("last-update.json")?;
    let previous = if last.is_file() {
        ensure!(std::fs::metadata(&last)?.len() <= 65536, "更新记录过大");
        serde_json::from_slice::<Value>(&std::fs::read(last)?)?
    } else {
        Value::Null
    };
    if !store.checked_file("update-ready.private.json")?.is_file() {
        return Ok(previous);
    }
    let ready: Value = serde_json::from_slice(&store.read_secret("update-ready.private.json")?)?;
    if previous["state"] == "Installed" && previous["version"] == ready["version"] {
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
pub async fn check(source: &str) -> Result<Value> {
    ensure!(
        matches!(source, "github" | "gitee"),
        "请选择 GitHub 或 Gitee"
    );
    let feed = if source == "github" {
        "https://api.github.com/repos/MrSGSA/ConWU/releases/latest"
    } else {
        "https://gitee.com/api/v5/repos/space4sgsa/ConWU/releases/latest"
    };
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
    let version = release["tag_name"]
        .as_str()
        .context("缺少版本号")?
        .trim_start_matches('v');
    let assets = release["assets"]
        .as_array()
        .or_else(|| release["assets"]["links"].as_array());
    let asset = assets.and_then(|v| {
        v.iter().find(|a| {
            a["name"].as_str().is_some_and(|s| {
                s.contains("rust")
                    && s.contains(std::env::consts::ARCH)
                    && s.ends_with(if cfg!(windows) { ".msi" } else { ".tar.gz" })
            })
        })
    });
    let package = asset
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
    Ok(
        json!({"currentVersion":VERSION,"platform":std::env::consts::OS,"state":if compatible{"Available"}else{"UpToDate"},"message":if compatible{"发现 Rust 兼容更新"}else{"Rust 实验分支尚无兼容发布"},"latestVersion":version,"releaseUrl":release["html_url"],"notes":release["body"],"updateAvailable":compatible&&version!=VERSION,"checkedAt":conwu_core::unix_seconds(),"package":package,"downloadSource":source}),
    )
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
        name.contains("rust")
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
    ensure!(
        parsed.scheme() == "https"
            && matches!(parsed.host_str(), Some("github.com" | "gitee.com"))
            && parsed
                .path()
                .starts_with(if parsed.host_str() == Some("github.com") {
                    "/MrSGSA/ConWU/releases/download/"
                } else {
                    "/space4sgsa/ConWU/releases/download/"
                }),
        "非官方安装包地址"
    );
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
