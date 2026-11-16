use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
pub fn default_data() -> PathBuf {
    if cfg!(windows) {
        let root = PathBuf::from(
            std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()),
        );
        if let Some(id) = crate::instance::validation() {
            return root.join("ConWU-Validation").join(id);
        }
        if cfg!(feature = "production") {
            return root.join("ConWU");
        }
    }
    std::env::var_os("CONWU_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(windows) {
                PathBuf::from(
                    std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()),
                )
                .join("ConWU/Rust")
            } else {
                PathBuf::from("/var/lib/conwu")
            }
        })
}
pub fn normalize_args(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    let mut args = args.into_iter().collect::<Vec<_>>();
    if args.get(1).is_some_and(|a| a == "--data") && args.len() >= 4 {
        let data = args.drain(1..3).collect::<Vec<_>>();
        args.extend(data);
    }
    args
}
pub struct Client {
    root: PathBuf,
    origin: String,
    secret: Value,
    http: reqwest::Client,
    ipc: bool,
}
impl Client {
    #[cfg(target_os = "linux")]
    pub async fn shutdown(&self) -> Result<()> {
        self.http
            .post(format!("{}/api/stop", self.origin))
            .header("Origin", &self.origin)
            .json(&json!({"secret":self.secret}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
    pub fn open(root: &Path) -> Result<Self> {
        #[cfg(windows)]
        if std::fs::read(root.join("panel.private.json")).is_err() {
            return Ok(Self {
                root: root.into(),
                origin: String::new(),
                secret: Value::Null,
                http: crate::discovery::http_client()?,
                ipc: true,
            });
        }
        let path = crate::store::Store::resolve_root(root)?.join("panel.private.json");
        crate::store::reject_link(&path)?;
        ensure!(std::fs::metadata(&path)?.len() <= 8192, "面板记录过大");
        let info: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let origin = info["origin"].as_str().context("面板地址缺失")?.to_owned();
        let url = url::Url::parse(&origin)?;
        ensure!(
            url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1")
                && url.port().is_some()
                && url.path() == "/"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "非法后台地址"
        );
        Ok(Self {
            root: root.into(),
            origin,
            secret: info["secret"].clone(),
            http: crate::discovery::http_client()?,
            ipc: false,
        })
    }
    pub async fn call(&self, command: Value) -> Result<Value> {
        #[cfg(windows)]
        if self.ipc {
            return crate::control::call(&self.root, &command).await;
        }
        let result: Value = self
            .http
            .post(format!("{}/api/local", self.origin))
            .header("Origin", &self.origin)
            .json(&json!({"secret":self.secret,"command":command}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ensure!(
            result["ok"] == true,
            "{}",
            result["error"].as_str().unwrap_or("后台请求失败")
        );
        Ok(result)
    }
    pub async fn mutate(&self, mut command: Value) -> Result<Value> {
        let id = uuid::Uuid::new_v4().to_string();
        command["operationId"] = json!(id);
        let mut result = self.call(command).await?;
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(150);
        while result["operation"]["completed"] != true {
            ensure!(
                tokio::time::Instant::now() < until,
                "操作仍在后台执行，可用 status 查询"
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            result = self
                .call(json!({"method":"status","operationId":id}))
                .await?;
        }
        ensure!(
            result["operation"]["error"]
                .as_str()
                .unwrap_or("")
                .is_empty(),
            "{}",
            result["operation"]["error"]
        );
        Ok(result)
    }
}
fn print(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn camel(value: Value) -> Value {
    match value {
        Value::Object(o) => Value::Object(
            o.into_iter()
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
        Value::Array(a) => Value::Array(a.into_iter().map(camel).collect()),
        v => v,
    }
}
fn file(path: &str) -> Result<Value> {
    let p = Path::new(path);
    ensure!(std::fs::metadata(p)?.len() <= 262144, "配置文件过大");
    Ok(camel(serde_json::from_slice(&std::fs::read(p)?)?))
}
pub async fn execute(mut args: Vec<String>) -> Result<()> {
    let mut root = default_data();
    if let Some(at) = args.iter().position(|a| a == "--data") {
        root = PathBuf::from(args.get(at + 1).context("--data 缺少目录")?);
        args.drain(at..at + 2);
    }
    if args
        .first()
        .is_none_or(|s| matches!(s.as_str(), "help" | "--help"))
    {
        println!(
            "ConWU Windows / Linux\n  run [--data 目录] [--no-open]   运行后台\n  status | web                  查询状态或获取面板地址\n  config show|apply <JSON>       本机设置\n  profiles                      连接配置列表\n  profile show|export|create|update|copy|assign|apply|delete\n  network list|status|create|join|invite|approve|reject|cancel|leave|withdraw|close|resume|rename|remove\n  start|stop|retry <网络ID>       启动、暂停或重连\n  update check                  检查官方更新\n  coordinator status|backup|inspect|restore <文件.slcoord> [--confirm-rollback]\n  remote-admin set <HTTPS来源> | disable\n所有管理命令支持 --data 目录。密码通过标准输入提供。"
        );
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "remote-admin") {
        return crate::remote_admin::configure(&root, &args[1..]);
    }
    if args.get(0).map(String::as_str) == Some("coordinator")
        && args.get(1).map(String::as_str) == Some("inspect")
    {
        return print(&crate::coordination_store::inspect(Path::new(
            args.get(2).context("缺少备份路径")?,
        ))?);
    }
    let client = Client::open(&root)?;
    let state = client.call(json!({"method":"status"})).await?["status"].clone();
    let first = args[0].as_str();
    if first == "web" {
        let result = client.call(json!({"method":"open"})).await?;
        println!("{}", result["url"].as_str().context("缺少面板地址")?);
        return Ok(());
    }
    if first == "status" {
        return print(&state);
    }
    if first == "profiles" {
        return print(&state["configurations"]);
    }
    if first == "update" && args.get(1).is_some_and(|a| a == "check") {
        return print(&crate::updates::check("github").await?);
    }
    if first == "coordinator" {
        let action = args.get(1).context("缺少协调操作")?;
        if action == "status" {
            return print(&state["coordinator"]);
        }
        let path = args.get(2).context("缺少备份路径")?;
        return print(&client.mutate(json!({"method":"coordinator-maintenance","maintenance":{"action":action,"path":std::path::absolute(path)?,"confirmRollback":args.iter().any(|a|a=="--confirm-rollback")}})).await?);
    }
    if first == "config" {
        if args.get(1).is_some_and(|a| a == "show") {
            return print(
                &json!({"deviceName":state["deviceName"],"logLevel":state["logLevel"],"autoStart":state["desktop"]["autoStart"],"coordinator":state["deviceSettings"]["coordinator"]}),
            );
        }
        ensure!(
            args.get(1).is_some_and(|a| a == "apply"),
            "用法：config show 或 config apply <JSON>"
        );
        let input = file(args.get(2).context("缺少配置文件")?)?;
        for key in input.as_object().context("本机配置需为对象")?.keys() {
            ensure!(
                ["deviceName", "logLevel", "autoStart", "coordinator"].contains(&key.as_str()),
                "未知本机配置字段：{key}"
            );
        }
        let mut action = json!({"patch":{},"settings":{}});
        for key in ["deviceName", "logLevel"] {
            if let Some(v) = input.get(key) {
                action["patch"][key] = v.clone();
            }
        }
        if let Some(v) = input.get("autoStart") {
            action["autoStart"] = v.clone();
        }
        if let Some(v) = input.get("coordinator") {
            let mut combined = state["deviceSettings"]["coordinator"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            for (k, v) in v.as_object().context("协调设置需为对象")? {
                combined.insert(k.clone(), v.clone());
            }
            action["settings"]["coordinator"] = json!(combined);
        }
        return print(
            &client
                .mutate(json!({"method":"save-settings","settingsBatch":{"device":action}}))
                .await?,
        );
    }
    let value = |index: usize| {
        args.get(index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("命令参数不足"))
    };
    if first == "profile" {
        let verb = value(1)?;
        let id = if verb == "create" {
            String::new()
        } else {
            value(2)?
        };
        let config = state["configurations"]
            .as_array()
            .context("配置列表缺失")?
            .iter()
            .find(|c| c["id"] == id);
        if verb != "create" {
            ensure!(config.is_some(), "未找到配置");
        }
        if verb == "show" {
            return print(config.unwrap());
        }
        if verb == "export" {
            return print(&config.unwrap()["settings"]);
        }
        let mut action = json!({"action":if matches!(verb.as_str(),"create"|"update"){"save"}else{&verb},"id":id,"name":config.map(|c|c["name"].clone()).unwrap_or_else(||json!("新配置")),"expectedRevision":config.map(|c|c["revision"].clone()).unwrap_or_else(||json!(0)),"confirmReconnect":args.iter().any(|a|a=="--reconnect")});
        if verb == "create" {
            action["name"] = json!(value(2)?);
            action["settings"] = file(&value(3)?)?;
        }
        if verb == "update" {
            action["settings"] = file(&value(3)?)?;
        }
        if verb == "copy" {
            action["name"] = json!(value(3)?);
        }
        return print(&client.mutate(json!({"method":"configuration","networkId":if verb=="assign"{value(3)?}else{String::new()},"configuration":action})).await?);
    }
    if ["start", "stop", "retry"].contains(&first) {
        let id = value(1)?;
        let action = if first == "stop" {
            "pause-network"
        } else {
            "reconnect"
        };
        return print(
            &client
                .mutate(json!({"method":"network","networkId":id,"network":{"action":action}}))
                .await?,
        );
    }
    ensure!(first == "network", "未知命令，运行 conwu help 查看用法");
    let verb = value(1)?;
    if verb == "list" {
        return print(&state["networks"]);
    }
    let ip = args
        .iter()
        .position(|a| a == "--ip")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_default();
    if matches!(verb.as_str(), "join" | "join-code") {
        return print(&client.mutate(json!({"method":"network","network":{"action":"join-compact","code":value(2)?,"requestedVirtualIp":ip}})).await?);
    }
    if verb == "create" {
        return print(&client.mutate(json!({"method":"network","network":{"action":"create-direct","configurationId":value(2)?,"name":args.get(3).filter(|v|!v.starts_with("--")).map(String::as_str).unwrap_or("新网络"),"requestedVirtualIp":ip}})).await?);
    }
    let id = value(2)?;
    let selected = state["networks"]
        .as_array()
        .context("网络列表缺失")?
        .iter()
        .find(|n| n["id"] == id)
        .context("未找到网络")?;
    if verb == "status" {
        return print(&selected["status"]);
    }
    let action = match verb.as_str() {
        "invite" => "invite-compact",
        "poll" => "pair-poll",
        "approve" => "approve",
        "reject" => "reject",
        "cancel" => "pair-cancel",
        "leave" => "forget-network",
        "withdraw" => "leave",
        "close" => "delete-network",
        "resume" => "reconnect",
        "rename" => "rename-network",
        "remove-config" => "remove-network",
        "remove" => "revoke",
        _ => anyhow::bail!("未知网络操作"),
    };
    let pairing = &selected["status"]["pairing"];
    if verb == "approve" {
        ensure!(
            pairing["verification"] == value(3)?,
            "校验码不匹配，请先核对双方显示"
        );
    }
    print(&client.mutate(json!({"method":"network","networkId":id,"network":{"action":action,"confirmReplace":true,"expectedNetwork":selected["status"]["networkId"],"verification":pairing["verification"],"candidate":pairing["candidate"],"name":args.get(3).map(String::as_str).unwrap_or(""),"peerSlot":if verb=="remove"{value(3)?.parse::<u8>()?}else{0}}})).await?)
}
