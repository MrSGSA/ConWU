#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::{error::Error, io::Read, path::PathBuf};

use tauri::{Url, WebviewUrl, WebviewWindowBuilder};

#[cfg(windows)]
use tauri::Manager;

#[cfg(windows)]
mod projection;

#[cfg(windows)]
#[path = "../../windows_window_lease.rs"]
mod window_lease;

fn panel_url(input: &str) -> Option<Url> {
    let url = Url::parse(input.trim()).ok()?;
    let ticket = url.fragment()?;
    (url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some_and(|port| port >= 1024)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && ticket.len() == 64
        && ticket.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(url)
}

fn panel_input() -> Result<Url, Box<dyn Error>> {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new("--panel")) {
        return Err("请从 ConWU 托盘打开桌面窗口".into());
    }
    let mut input = String::new();
    std::io::stdin().take(1024).read_to_string(&mut input)?;
    Ok(panel_url(&input).ok_or("ConWU 本机面板入口无效")?)
}

#[cfg(windows)]
fn open_in_browser(url: &Url) -> std::io::Result<()> {
    use std::{os::windows::process::CommandExt, process::Command};
    Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", url.as_str()])
        .creation_flags(0x08000000)
        .spawn()?;
    Ok(())
}

fn is_release_link(url: &Url) -> bool {
    url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && match url.host_str() {
            Some("github.com") => url.path().starts_with("/MrSGSA/ConWU/releases/"),
            Some("gitee.com") => url.path().starts_with("/space4sgsa/ConWU/releases/"),
            _ => false,
        }
}

#[cfg(windows)]
fn focus_existing(class: &str) -> Result<(), Box<dyn Error>> {
    use std::{ptr, thread, time::Duration};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, FlashWindow, IsIconic, SW_RESTORE, SetForegroundWindow, ShowWindowAsync,
    };
    let class = window_lease::wide(class)?;
    for _ in 0..50 {
        // A second launch may arrive while the first process is initializing WebView2.
        let window = unsafe { FindWindowW(class.as_ptr(), ptr::null()) };
        if !window.is_null() {
            unsafe {
                if IsIconic(window) != 0 {
                    ShowWindowAsync(window, SW_RESTORE);
                }
                if SetForegroundWindow(window) == 0 {
                    FlashWindow(window, 1);
                }
            }
            break;
        }
        thread::sleep(Duration::from_millis(40));
    }
    Ok(())
}

fn launch(url: Url) -> Result<(), Box<dyn Error>> {
    let origin = url.origin();
    #[cfg(windows)]
    let surface_origin = origin.ascii_serialization();
    let profile = std::env::var_os("CONWU_DESKTOP_PROFILE").map(PathBuf::from);
    if profile.as_ref().is_some_and(|path| !path.is_absolute()) {
        return Err("ConWU 桌面窗口配置目录需要使用绝对路径".into());
    }
    #[cfg(windows)]
    let (class, _lease) = {
        let class = format!("ConWU.Desktop.{}", url.port().unwrap());
        let Some(lease) = window_lease::WindowLease::acquire(&format!(r"Local\{class}"))? else {
            return focus_existing(&class);
        };
        (class, lease)
    };
    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder.invoke_handler(tauri::generate_handler![projection::projection_surface]);
    let app = builder.build(tauri::generate_context!())?;
    let mut window = WebviewWindowBuilder::new(&app, "conwu", WebviewUrl::External(url))
        .title("ConWU")
        .inner_size(1120.0, 760.0)
        .min_inner_size(760.0, 540.0)
        .on_navigation(move |target| target.origin() == origin)
        .on_new_window(|target, _| {
            #[cfg(windows)]
            if is_release_link(&target) {
                let _ = open_in_browser(&target);
            }
            tauri::webview::NewWindowResponse::Deny
        });
    #[cfg(windows)]
    {
        window = window.disable_drag_drop_handler().window_classname(class).initialization_script(format!(
            r#"if (location.origin === "{}") {{
                Object.defineProperty(window, "conwuProjectionSurface", {{
                    value: (placement, closeEnded = false, fullscreen = null, toggleStats = false) =>
                        window.__TAURI_INTERNALS__.invoke("projection_surface", {{placement, closeEnded, fullscreen, toggleStats}})
                }});
            }}"#,
            surface_origin
        ));
    }
    if let Some(profile) = profile {
        window = window.data_directory(profile);
    }
    let window = window.build()?;
    #[cfg(windows)]
    {
        app.manage(projection::Surface::new(&window, surface_origin)?);
        let handle = app.handle().clone();
        window.on_window_event(move |event| {
            if let tauri::WindowEvent::Focused(focused) = event {
                handle.state::<projection::Surface>().focus_changed(*focused);
            }
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                handle.state::<projection::Surface>().close();
            }
        });
    }
    app.run(|_, _| {});
    Ok(())
}

fn open() -> Result<(), Box<dyn Error>> {
    let url = panel_input()?;
    if let Err(error) = launch(url.clone()) {
        #[cfg(windows)]
        {
            if std::env::args_os().nth(2).is_some_and(|argument| argument == "--desktop-only") {
                return Err(error);
            }
            eprintln!("ConWU 桌面窗口启动失败 · {error}");
            open_in_browser(&url)?;
        }
        #[cfg(not(windows))]
        return Err(error);
    }
    Ok(())
}

fn main() {
    if let Err(error) = open() {
        eprintln!("ConWU 桌面窗口启动失败 · {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_loopback_ticket_shape_can_open_the_window() {
        let token = "A".repeat(64);
        assert!(panel_url(&format!("http://127.0.0.1:4747/#{token}")).is_some());
        for url in [
            format!("https://127.0.0.1:4747/#{token}"),
            format!("http://127.0.0.1.example:4747/#{token}"),
            format!("http://127.0.0.1:4747/?x=1#{token}"),
            format!("http://user@127.0.0.1:4747/#{token}"),
            "http://127.0.0.1:4747/#missing-ticket".into(),
        ] {
            assert!(panel_url(&url).is_none(), "unexpected navigation: {url}");
        }
    }

    #[test]
    fn release_links_open_in_the_system_browser() {
        for (url, expected) in [
            ("https://github.com/MrSGSA/ConWU/releases/tag/v1.5.1", true),
            (
                "https://gitee.com/space4sgsa/ConWU/releases/tag/v1.5.1",
                true,
            ),
            (
                "https://github.com/another/ConWU/releases/tag/v1.5.1",
                false,
            ),
            (
                "https://github.com.example/MrSGSA/ConWU/releases/tag/v1.5.1",
                false,
            ),
            (
                "https://u@github.com/MrSGSA/ConWU/releases/tag/v1.5.1",
                false,
            ),
        ] {
            assert_eq!(is_release_link(&Url::parse(url).unwrap()), expected);
        }
    }
}
