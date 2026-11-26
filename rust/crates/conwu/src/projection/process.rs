use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    process::Stdio,
};

use anyhow::{Context, Result, ensure};
use tokio::process::{Child, Command};
use windows_sys::Win32::{
    Foundation::{HANDLE, HWND, LPARAM},
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
        Threading::CREATE_NO_WINDOW,
    },
    UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId, PostMessageW, WM_ENDSESSION,
    },
};

pub(super) struct DesktopJob(OwnedHandle);

impl DesktopJob {
    pub(super) fn new() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        ensure!(
            !handle.is_null(),
            "无法创建 Projection 进程组：{}",
            io::Error::last_os_error()
        );
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        ensure!(
            unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of_val(&limits) as u32,
                )
            } != 0,
            "无法启用 Projection 进程退出清理：{}",
            io::Error::last_os_error()
        );
        Ok(job)
    }

    pub(super) fn spawn(
        &self,
        program: &Path,
        directory: &Path,
        args: &[&str],
        stdout: Stdio,
        environment: &[(&str, &str)],
    ) -> Result<Child> {
        let child = Command::new(program)
            .args(args)
            .env_remove("CONWU_PROJECTION_PAIR")
            .env_remove("CONWU_PROJECTION_SURFACE")
            .envs(environment.iter().copied())
            .current_dir(directory)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("无法启动 {}", program.display()))?;
        let handle = child.raw_handle().context("Projection 进程已退出")? as HANDLE;
        ensure!(
            unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), handle) } != 0,
            "无法管理 Projection 进程：{}",
            io::Error::last_os_error()
        );
        Ok(child)
    }
}

pub(super) fn close_sunshine_monitor(pid: u32) {
    unsafe extern "system" fn close(window: HWND, parameter: LPARAM) -> i32 {
        let mut owner = 0;
        unsafe {
            GetWindowThreadProcessId(window, &mut owner);
            if owner != parameter as u32 {
                return 1;
            }
            let mut class = [0u16; 64];
            let count = GetClassNameW(window, class.as_mut_ptr(), class.len() as i32);
            if count > 0
                && String::from_utf16_lossy(&class[..count as usize]) == "SunshineSessionMonitorClass"
            {
                PostMessageW(window, WM_ENDSESSION, 1, 0);
                return 0;
            }
        }
        1
    }
    unsafe { EnumWindows(Some(close), pid as LPARAM) };
}
