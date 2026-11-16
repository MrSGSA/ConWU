//! Explicit installation identities. Validation MSIs have their own SCM/data
//! namespace, so testing an upgrade cannot stop the installed daily service.
use anyhow::{Result, ensure};
use std::{ffi::OsString, sync::OnceLock};
static VALIDATION: OnceLock<String> = OnceLock::new();
pub fn validation() -> Option<&'static str> {
    VALIDATION.get().map(String::as_str)
}
pub fn arguments(args: impl IntoIterator<Item = OsString>) -> Result<Vec<OsString>> {
    let mut args = args.into_iter().collect::<Vec<_>>();
    if let Some(at) = args.iter().position(|a| a == "--validation-instance") {
        let value = args
            .get(at + 1)
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("缺少隔离安装编号"))?;
        let id = uuid::Uuid::parse_str(value)?;
        ensure!(
            !id.is_nil() && id.simple().to_string() == value,
            "隔离安装编号需为规范GUID"
        );
        if let Some(current) = VALIDATION.get() {
            ensure!(current == value, "隔离安装编号不能改变");
        } else {
            VALIDATION
                .set(value.to_owned())
                .map_err(|_| anyhow::anyhow!("隔离安装编号不能重复"))?;
        }
        args.drain(at..at + 2);
        ensure!(
            !args.iter().any(|a| a == "--validation-instance"),
            "隔离安装编号不能重复"
        );
    }
    if args.get(1).is_some_and(|s| s == "--startup") {
        args.splice(1..2, ["tray".into(), "--no-open".into()]);
    }
    if let Some(action) = args
        .get(1)
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("--msi-"))
        .map(str::to_owned)
    {
        ensure!(
            ["snapshot", "configure", "rollback", "commit", "ready"].contains(&action.as_str()),
            "未知安装操作"
        );
        args.splice(1..2, ["msi".into(), action.into()]);
    }
    Ok(args)
}
pub fn service_name() -> String {
    if let Some(id) = validation() {
        format!("StreamLink-Validation-{id}")
    } else if cfg!(feature = "production") {
        "StreamLink-PersonalFeature".into()
    } else {
        "ConWURustExperiment".into()
    }
}
pub fn linux_unit() -> &'static str {
    if cfg!(feature = "production") {
        "streamlink.service"
    } else {
        "conwu-rust-experiment.service"
    }
}
pub fn product() -> String {
    if let Some(id) = validation() {
        format!("{{{}}}", uuid::Uuid::parse_str(id).unwrap().hyphenated()).to_ascii_uppercase()
    } else if cfg!(feature = "production") {
        "{AD076018-A9B8-47F5-B098-97479A363416}".into()
    } else {
        "{2B716DCB-5CD7-4EEC-91E4-749BC09027A1}".into()
    }
}
pub fn product_name() -> String {
    if let Some(id) = validation() {
        format!("ConWU Validation {}", &id[..8])
    } else if cfg!(feature = "production") {
        "ConWU".into()
    } else {
        "ConWU Rust Experiment".into()
    }
}
