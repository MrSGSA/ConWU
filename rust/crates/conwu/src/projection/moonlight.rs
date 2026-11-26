use std::{
    io,
    net::Ipv4Addr,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Child,
    sync::{mpsc, watch},
};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, HWND, INVALID_HANDLE_VALUE},
    Globalization::{CP_ACP, MultiByteToWideChar},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
    UI::WindowsAndMessaging::{
        FindWindowExW, GetPropW, GetWindowThreadProcessId, IsWindow, PostMessageW, WM_CLOSE,
    },
};

use super::{companion, display::DisplayMode, process::DesktopJob};
use crate::model::{ProjectionResolution, ProjectionVideo};

pub(crate) const DESKTOP_PLAYER: &str = "ConWU-Moonlight.exe";
const RESPONSE_LIMIT: usize = 32 * 1024;
// GameStream's RTP, FEC and UDP headers also have to fit inside the 1280-byte tunnel MTU.
const VIDEO_PACKET_SIZE: &str = "1120";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Target {
    pub record: String,
    #[serde(default)]
    pub carrier: String,
    pub device: String,
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
    pub interface: u32,
    pub port: u16,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Stage {
    #[default]
    Starting,
    Playing,
    Stopping,
}

#[derive(Default, Deserialize, Serialize)]
pub(crate) struct Report {
    pub available: bool,
    pub target: Option<Target>,
    #[serde(default)]
    pub stage: Stage,
    pub error: Option<String>,
}

fn player_running() -> Result<bool> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    ensure!(
        snapshot != INVALID_HANDLE_VALUE,
        "无法检查 Projection 播放进程"
    );
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    ensure!(
        unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0,
        "无法读取 Windows 进程列表"
    );
    loop {
        let end = entry
            .szExeFile
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
        if name.eq_ignore_ascii_case(DESKTOP_PLAYER) {
            return Ok(true);
        }
        if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            let error = io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32),
                "无法检查 Projection 播放进程：{error}"
            );
            return Ok(false);
        }
    }
}

fn app_names(output: &[u8]) -> Result<String> {
    if let Ok(text) = std::str::from_utf8(output) {
        return Ok(text.to_owned());
    }
    let count = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            0,
            output.as_ptr(),
            output.len() as i32,
            std::ptr::null_mut(),
            0,
        )
    };
    ensure!(count > 0, "无法读取 Moonlight 应用列表编码");
    let mut chars = vec![0u16; count as usize];
    ensure!(
        unsafe {
            MultiByteToWideChar(
                CP_ACP,
                0,
                output.as_ptr(),
                output.len() as i32,
                chars.as_mut_ptr(),
                count,
            )
        } == count,
        "Moonlight 应用列表转码失败"
    );
    Ok(String::from_utf16_lossy(&chars))
}

fn desktop_app(names: &str) -> Result<&str> {
    let valid = |name: &&str| {
        !name.starts_with('-') && name.len() <= 256 && !name.chars().any(char::is_control)
    };
    let names = || names.lines().map(str::trim).filter(valid);
    if let Some(name) = names().find(|name| name.eq_ignore_ascii_case("Desktop") || *name == "桌面")
    {
        return Ok(name);
    }
    let mut desktops = names().filter(|name| {
        name.contains("桌面")
            || name
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .any(|part| part.eq_ignore_ascii_case("desktop"))
    });
    let name = desktops
        .next()
        .context("请在 Sunshine 中发布一个桌面应用")?;
    ensure!(
        desktops.next().is_none(),
        "有多个桌面应用，请在 Sunshine 中使用 Desktop 或桌面作为默认应用名"
    );
    Ok(name)
}

async fn list_apps(
    job: &DesktopJob,
    program: &Path,
    directory: &Path,
    address: &str,
) -> Result<Option<String>> {
    let mut command = job.spawn(program, directory, &["list", address], Stdio::piped(), &[])?;
    let mut output = Vec::new();
    command
        .stdout
        .take()
        .context("无法读取 Moonlight 应用列表")?
        .take(RESPONSE_LIMIT as u64 + 1)
        .read_to_end(&mut output)
        .await?;
    ensure!(output.len() <= RESPONSE_LIMIT, "Moonlight 应用列表过大");
    let status = command.wait().await?;
    if status.code() == Some(-1) {
        return Ok(None); // Unpaired. Our deadline precedes Moonlight's 30 s discovery timeout.
    }
    ensure!(status.success(), "Moonlight 未能读取应用列表");
    Ok(Some(app_names(&output)?))
}

pub(crate) fn surface_open(surface: usize) -> bool {
    unsafe { IsWindow(surface as HWND) != 0 }
}

fn embedded_window(surface: usize, pid: u32) -> Option<usize> {
    let property: Vec<u16> = "ConWU.Projection.Moonlight".encode_utf16().chain(Some(0)).collect();
    let mut child = std::ptr::null_mut();
    loop {
        child = unsafe { FindWindowExW(surface as HWND, child, std::ptr::null(), std::ptr::null()) };
        if child.is_null() {
            return None;
        }
        let mut owner = 0;
        unsafe { GetWindowThreadProcessId(child, &mut owner) };
        if owner == pid && unsafe { !GetPropW(child, property.as_ptr()).is_null() } {
            return Some(child as usize);
        }
    }
}

async fn close_player(child: &mut Child, pid: u32, surface: usize) {
    if let Some(window) = embedded_window(surface, pid) {
        unsafe { PostMessageW(window as HWND, WM_CLOSE, 0, 0) };
        // Keep the final frame alive while Moonlight drains teardown and the
        // desktop panel acknowledges the frozen window.
        let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    }
}

fn window_flag(window: usize, property: &str) -> bool {
    let property: Vec<u16> = property.encode_utf16().chain(Some(0)).collect();
    unsafe { !GetPropW(window as HWND, property.as_ptr()).is_null() }
}

async fn connect_first_time(
    job: &DesktopJob,
    program: &Path,
    directory: &Path,
    address: &str,
    route: &companion::Route,
) -> Result<()> {
    let mut child = job.spawn(
        program,
        directory,
        &["pair", address],
        Stdio::piped(),
        &[("CONWU_PROJECTION_PAIR", "1")],
    )?;
    let output = child.stdout.take().context("无法读取 Projection 自动连接结果")?;
    let mut output = BufReader::new(output.take(24));
    let mut line = zeroize::Zeroizing::new(String::new());
    tokio::time::timeout(Duration::from_secs(16), output.read_line(&mut line))
        .await
        .context("等待对端自动连接握手超时")??;
    let pin = line.trim_end().strip_prefix("PIN ")
        .filter(|pin| pin.len() == 4 && pin.bytes().all(|digit| digit.is_ascii_digit()))
        .context("Projection 未返回有效的自动连接握手")?;
    companion::approve(route, pin.to_owned()).await.context("Projection 自动连接未能完成")?;
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .context("Projection 自动连接握手超时")??;
    ensure!(status.success(), "Projection 自动连接未能完成，请检查两端授权");
    Ok(())
}

pub(crate) async fn play(
    program: PathBuf,
    directory: PathBuf,
    target: Target,
    video: ProjectionVideo,
    surface: usize,
    progress: watch::Sender<Stage>,
    stop: CancellationToken,
    companion: companion::Route,
    drops: mpsc::Sender<(Target, companion::DroppedFiles)>,
) -> Result<()> {
    ensure!(program.file_name().is_some_and(|name| name == DESKTOP_PLAYER), "当前安装缺少支持同窗播放的 Projection 组件");
    ensure!(surface_open(surface), "ConWU 桌面播放区已关闭");
    ensure!(!player_running()?, "请先结束当前 Projection 串流");
    video.validate()?;
    let directory = directory.as_path();
    super::write_state(directory, "portable.dat", b"")?;
    let job = DesktopJob::new()?;
    let address = format!("{}:{}", target.remote, target.port);
    let applications = || async {
        tokio::time::timeout(Duration::from_secs(12), async {
            super::sunshine::game_stream_busy(target.local, target.remote, target.port).await?;
            list_apps(&job, &program, directory, &address).await
        })
        .await
        .context("等待 Projection 对端响应超时")?
    };
    let mut names = tokio::select! {
        biased;
        _ = stop.cancelled() => return Ok(()),
        result = applications() => result?,
    };
    if names.is_none() {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(()),
            result = connect_first_time(&job, &program, directory, &address, &companion) => result?,
        }
        names = tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(()),
            result = applications() => result?,
        };
    }
    let names = names.context("对端未确认 Projection 自动连接，请检查两端授权")?;
    let app = desktop_app(&names)?;
    if stop.is_cancelled() {
        return Ok(());
    }
    let display = DisplayMode::read(Some(surface));
    let (width, height) = match video.resolution_mode {
        ProjectionResolution::Local => display.as_ref().map_err(|error| anyhow::anyhow!("{error}"))?.stream_size()?,
        ProjectionResolution::Peer => companion::display(&companion).await?.stream_size()?,
        ProjectionResolution::Custom => (video.width, video.height),
    };
    let resolution = format!("{width}x{height}");
    let fps = video.fps.to_string();
    let bitrate = video.bitrate_kbps(width, height).to_string();
    let mut arguments = vec![
        "stream",
        &address,
        app,
        "--resolution",
        &resolution,
        "--fps",
        &fps,
        "--bitrate",
        &bitrate,
        "--performance-overlay",
        "--packet-size",
        VIDEO_PACKET_SIZE,
        "--video-codec",
        "auto",
        "--display-mode",
        "windowed",
        "--capture-system-keys",
        "fullscreen",
    ];
    if display.is_ok_and(|display| {
        display.refresh_hz > 1 && u32::from(video.fps) <= display.refresh_hz + 1
    }) {
        arguments.extend(["--vsync", "--frame-pacing"]);
    }
    ensure!(surface_open(surface), "ConWU 桌面播放区已关闭");
    let carrier = match target.carrier.as_str() {
        "faketcp" => "FakeTCP", "mimic" => "Mimic", "phantun" => "Phantun",
        "tcpraw" => "TCPRAW", "tcp" => "TCP", "https" => "HTTPS", "udp" => "UDP", _ => "Unknown",
    };
    let mut player = job.spawn(
        &program, directory, &arguments, Stdio::piped(),
        &[("CONWU_PROJECTION_SURFACE", &surface.to_string()), ("CONWU_PROJECTION_CARRIER", carrier)],
    )?;
    let pid = player.id().context("Projection 播放进程未启动")?;
    if let Some(output) = player.stdout.take() {
        tokio::spawn(read_file_drops(output, target.clone(), drops));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(16);
    let mut window_check = tokio::time::interval(Duration::from_millis(100));
    window_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut started = false;
    let mut ending = false;
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => {
                progress.send_replace(Stage::Stopping);
                close_player(&mut player, pid, surface).await;
                return Ok(());
            }
            status = player.wait() => {
                if !status?.success() {
                    bail!("Projection 串流已退出，请检查对端状态");
                }
                return Ok(());
            }
            _ = window_check.tick(), if !ending => {
                if let Some(window) = embedded_window(surface, pid) {
                    if window_flag(window, "ConWU.Projection.Stopping") {
                        ending = true;
                        progress.send_replace(Stage::Stopping);
                    } else if !started && !window_flag(window, "ConWU.Projection.WaitForFrame") {
                        started = true;
                        progress.send_replace(Stage::Playing);
                    }
                }
                if !started && !ending && tokio::time::Instant::now() >= deadline {
                    close_player(&mut player, pid, surface).await;
                    bail!("远控播放窗口未能打开，请重新连接");
                }
            }
        }
    }
}

async fn read_file_drops(output: tokio::process::ChildStdout, target: Target, drops: mpsc::Sender<(Target, companion::DroppedFiles)>) {
    const LIMIT: u64 = 128 * 1024;
    let mut reader = BufReader::new(output);
    let mut line = Vec::new();
    loop {
        line.clear();
        let Ok(length) = (&mut reader).take(LIMIT + 1).read_until(b'\n', &mut line).await else { break };
        if length == 0 || length as u64 > LIMIT {
            break;
        }
        let Some(payload) = line.strip_prefix(b"CONWU_FILES ") else { continue };
        let Ok(batch) = serde_json::from_slice::<companion::DroppedFiles>(payload) else { continue };
        if (1..=64).contains(&batch.files.len()) && batch.files.iter().all(|path| path.is_absolute()) {
            let _ = drops.try_send((target.clone(), batch));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_selection_prefers_the_named_desktop_and_rejects_an_ambiguous_list() {
        assert_eq!(
            desktop_app("Steam\nAkane-Desktop\n").unwrap(),
            "Akane-Desktop"
        );
        assert_eq!(
            desktop_app("Gaming Desktop\nDesktop\r\n").unwrap(),
            "Desktop"
        );
        assert_eq!(desktop_app("桌面\r\nSteam\n").unwrap(), "桌面");
        assert!(desktop_app("-Desktop\nSteam Desktop\nRemote Desktop\n").is_err());
        assert!(desktop_app("Steam\n").is_err());
    }
}
