//! Local Windows service broker. Interactive users can open the panel without
//! gaining read access to the service's identities or DPAPI documents.
#[cfg(windows)]
mod windows {
    use anyhow::{Context, Result, ensure};
    use serde_json::{Value, json};
    use std::{os::windows::io::AsRawHandle, path::Path, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
    };
    pub fn name(data: &Path) -> Result<String> {
        let path = std::path::absolute(data)?
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .replace('/', "\\")
            .to_ascii_lowercase();
        Ok(format!(
            r"\\.\pipe\ConWU.Rust.Control.{}",
            &hex::encode(conwu_core::crypto::hash(path.as_bytes()))[..24]
        ))
    }
    fn server(name: &str, sid: &str, first: bool) -> Result<NamedPipeServer> {
        ensure!(
            sid.starts_with("S-1-")
                && sid.len() <= 192
                && sid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-')),
            "交互用户SID无效"
        );
        use windows_sys::Win32::{Foundation::LocalFree, Security::SECURITY_ATTRIBUTES};
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                s: *const u16,
                rev: u32,
                out: *mut *mut std::ffi::c_void,
                size: *mut u32,
            ) -> i32;
        }
        let text = format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut sd = std::ptr::null_mut();
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            } != 0,
            "无法设置本机控制管道权限"
        );
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let result = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .max_instances(16)
                .create_with_security_attributes_raw(
                    name,
                    (&attributes as *const SECURITY_ATTRIBUTES)
                        .cast_mut()
                        .cast(),
                )
        };
        unsafe { LocalFree(sd) };
        Ok(result?)
    }
    pub fn start(panel: Arc<crate::web::Panel>) -> Result<()> {
        let path = panel.app.store.checked_file("ui-user.sid")?;
        let sid = if path.exists() {
            ensure!(std::fs::metadata(&path)?.len() <= 256, "授权SID文件过大");
            std::fs::read_to_string(path)?.trim().to_owned()
        } else {
            crate::store::current_sid()?
        };
        let pipe_name = name(&panel.app.store.root)?;
        let mut listener = server(&pipe_name, &sid, true)?;
        let tracker = panel.app.engine.tracker.clone();
        let tasks = tracker.clone();
        let cancel = panel.app.engine.cancel.clone();
        tracker.spawn(async move {
            let gate = Arc::new(tokio::sync::Semaphore::new(8));
            loop {
                if tokio::select! {_=cancel.cancelled()=>false,r=listener.connect()=>r.is_ok()}
                    == false
                {
                    break;
                }
                let next = match server(&pipe_name, &sid, false) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                let mut io = std::mem::replace(&mut listener, next);
                let panel = panel.clone();
                let gate = gate.clone();
                tasks.spawn(async move {
                    let Ok(_permit) = gate.try_acquire_owned() else {
                        return;
                    };
                    let task = async {
                        let size = io.read_u32_le().await? as usize;
                        ensure!(size <= 262144, "本机命令过大");
                        let mut bytes = vec![0; size];
                        io.read_exact(&mut bytes).await?;
                        let input: Value = serde_json::from_slice(&bytes)?;
                        let result = if input["method"] == "open" {
                            Ok(json!({"ok":true,"url":panel.link()}))
                        } else if input["method"] == "status" {
                            Ok(panel.app.reply(
                                input["networkId"].as_str().unwrap_or(""),
                                input["operationId"].as_str(),
                            ))
                        } else {
                            panel.app.submit(input)
                        };
                        let result =
                            result.unwrap_or_else(|e| json!({"ok":false,"error":e.to_string()}));
                        let reply = serde_json::to_vec(&result)?;
                        io.write_u32_le(reply.len() as u32).await?;
                        io.write_all(&reply).await?;
                        Ok::<_, anyhow::Error>(())
                    };
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
                });
            }
        });
        Ok(())
    }
    pub async fn call(data: &Path, request: &Value) -> Result<Value> {
        let pipe_name = name(data)?;
        let mut io = ClientOptions::new()
            .open(&pipe_name)
            .context("未找到本机 ConWU 服务控制通道")?;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetNamedPipeServerProcessId(pipe: *mut std::ffi::c_void, pid: *mut u32) -> i32;
        }
        let mut actual = 0;
        ensure!(
            unsafe { GetNamedPipeServerProcessId(io.as_raw_handle(), &mut actual) } != 0,
            "无法验证后台服务进程"
        );
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service =
            manager.open_service(crate::instance::service_name(), ServiceAccess::QUERY_STATUS)?;
        ensure!(
            service.query_status()?.process_id == Some(actual),
            "控制管道不属于已安装的 ConWU 服务"
        );
        let task = async {
            let bytes = serde_json::to_vec(request)?;
            ensure!(bytes.len() <= 262144, "本机命令过大");
            io.write_u32_le(bytes.len() as u32).await?;
            io.write_all(&bytes).await?;
            let size = io.read_u32_le().await? as usize;
            ensure!(size <= 8 * 1024 * 1024, "后台回复过大");
            let mut bytes = vec![0; size];
            io.read_exact(&mut bytes).await?;
            Ok::<Value, anyhow::Error>(serde_json::from_slice(&bytes)?)
        };
        tokio::time::timeout(std::time::Duration::from_secs(6), task).await?
    }
}
#[cfg(windows)]
pub use windows::*;
