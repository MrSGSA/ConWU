use anyhow::{Result, ensure};
use conwu_core::crypto as c;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    num::NonZeroU32,
    path::Path,
};
const WORK: u32 = 600_000;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub origin: String,
    salt: String,
    password_hash: String,
    iterations: u32,
}
impl Config {
    fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.origin)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some_and(|h| h != "localhost"
                    && h.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .map_or(true, |i| !i.is_loopback()))
                && url.origin().ascii_serialization() == self.origin
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "远程管理需填写无路径的 HTTPS 来源"
        );
        ensure!(
            self.iterations == WORK
                && c::unb64(&self.salt)?.len() == 32
                && c::unb64(&self.password_hash)?.len() == 32,
            "远程管理凭据无效"
        );
        Ok(())
    }
    pub fn create(origin: &str, password: &str) -> Result<Self> {
        ensure!(
            (16..=256).contains(&password.chars().count())
                && !password.chars().any(char::is_control),
            "密码需为16–256个非控制字符"
        );
        let salt = c::random::<32>();
        let mut hash = [0; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(WORK).unwrap(),
            &salt,
            password.as_bytes(),
            &mut hash,
        );
        let url = url::Url::parse(origin)?;
        ensure!(
            url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none(),
            "远程管理来源不能含路径、查询或用户信息"
        );
        let origin = url.origin().ascii_serialization();
        let config = Self {
            origin,
            salt: c::b64(salt),
            password_hash: c::b64(hash),
            iterations: WORK,
        };
        config.validate()?;
        Ok(config)
    }
    pub fn verify(&self, password: &str) -> bool {
        if password.chars().count() > 256 || self.validate().is_err() {
            return false;
        }
        ring::pbkdf2::verify(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(WORK).unwrap(),
            &c::unb64(&self.salt).unwrap(),
            password.as_bytes(),
            &c::unb64(&self.password_hash).unwrap(),
        )
        .is_ok()
    }
    pub fn load(root: &Path) -> Result<Option<Self>> {
        let path = root.join("remote-admin.json");
        if !path.exists() {
            return Ok(None);
        }
        for p in path.ancestors() {
            crate::store::reject_link(p)?;
        }
        ensure!(std::fs::metadata(&path)?.len() <= 4096, "远程管理配置过大");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                std::fs::metadata(&path)?.permissions().mode() & 0o077 == 0,
                "远程管理凭据权限需为0600"
            );
        }
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        config.validate()?;
        Ok(Some(config))
    }
}
pub fn configure(root: &Path, args: &[String]) -> Result<()> {
    let root = crate::store::Store::resolve_root(root)?;
    std::fs::create_dir_all(&root)?;
    crate::store::private_directory(&root)?;
    let path = root.join("remote-admin.json");
    if path.exists() {
        crate::store::reject_link(&path)?;
    }
    if args == ["disable"] {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        println!("远程管理已关闭，重启后台生效。");
        return Ok(());
    }
    ensure!(
        args.len() == 2 && args[0] == "set",
        "用法：remote-admin set <HTTPS来源> 或 disable"
    );
    use std::io::IsTerminal;
    ensure!(
        !std::io::stdin().is_terminal(),
        "请从标准输入提供密码，不要放到命令参数中"
    );
    let mut password = zeroize::Zeroizing::new(String::new());
    std::io::stdin().take(2049).read_to_string(&mut password)?;
    ensure!(password.len() <= 2048, "密码输入过长");
    let config = Config::create(&args[1], password.trim_end_matches(['\r', '\n']))?;
    if !root.join(".conwu-rust-owned").exists() {
        ensure!(
            std::fs::read_dir(&root)?.next().is_none(),
            "请使用 ConWU 数据目录"
        );
        std::fs::write(root.join(".conwu-rust-owned"), b"ConWU Rust data v1\n")?;
    }
    let temp = root.join(format!("remote-admin-{}.tmp", conwu_core::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(&serde_json::to_vec(&config)?)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    std::fs::rename(temp, path)?;
    println!(
        "远程管理已配置，重启后台后通过 {}/admin/ 访问。",
        config.origin
    );
    Ok(())
}
