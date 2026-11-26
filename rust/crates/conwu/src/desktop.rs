//! Windows desktop lifetime and startup registration, independent of the backend.
use std::{ffi::c_void, io, ptr};
use windows_sys::Win32::Foundation::HANDLE;

#[path = "../../../windows_window_lease.rs"]
mod window_lease;
pub use window_lease::WindowLease as TrayLease;
use window_lease::wide;

const MACHINE: HANDLE = -2147483646isize as HANDLE;
const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegCreateKeyExW(
        root: HANDLE,
        path: *const u16,
        reserved: u32,
        class: *mut u16,
        options: u32,
        access: u32,
        security: *const c_void,
        key: *mut HANDLE,
        disposition: *mut u32,
    ) -> i32;
    fn RegGetValueW(
        key: HANDLE,
        subkey: *const u16,
        name: *const u16,
        flags: u32,
        kind: *mut u32,
        value: *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        key: HANDLE,
        name: *const u16,
        reserved: u32,
        kind: u32,
        value: *const u8,
        size: u32,
    ) -> i32;
    fn RegDeleteValueW(key: HANDLE, name: *const u16) -> i32;
    fn RegCloseKey(key: HANDLE) -> i32;
}
struct RunKey(HANDLE);
impl RunKey {
    fn open(root: HANDLE, path: &str) -> io::Result<Self> {
        let path = wide(path)?;
        let mut key = ptr::null_mut();
        // KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY. Never grant users
        // extra access or alter the shared Run key's security descriptor.
        let error = unsafe {
            RegCreateKeyExW(
                root,
                path.as_ptr(),
                0,
                ptr::null_mut(),
                0,
                0x103,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(Self(key))
    }
    fn read(&self, name: &str) -> io::Result<Option<String>> {
        let name = wide(name)?;
        let mut size = 0;
        let error = unsafe {
            RegGetValueW(
                self.0,
                ptr::null(),
                name.as_ptr(),
                2,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut size,
            )
        };
        if error == 2 {
            return Ok(None);
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        if size > 65536 || size % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "开机启动项长度无效",
            ));
        }
        let mut value = vec![0u16; size as usize / 2];
        let error = unsafe {
            RegGetValueW(
                self.0,
                ptr::null(),
                name.as_ptr(),
                2,
                ptr::null_mut(),
                value.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        value.truncate(size as usize / 2);
        if value.last() == Some(&0) {
            value.pop();
        }
        String::from_utf16(&value)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
    fn write(&self, name: &str, command: Option<&str>) -> io::Result<()> {
        let name = wide(name)?;
        let error = if let Some(command) = command {
            let value = wide(command)?;
            unsafe {
                RegSetValueExW(
                    self.0,
                    name.as_ptr(),
                    0,
                    1,
                    value.as_ptr().cast(),
                    (value.len() * 2) as u32,
                )
            }
        } else {
            unsafe { RegDeleteValueW(self.0, name.as_ptr()) }
        };
        if error == 0 || (command.is_none() && error == 2) {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(error))
        }
    }
    fn update(
        &self,
        name: &str,
        command: Option<&str>,
        service: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let previous = self.read(name)?;
        self.write(name, command)?;
        if let Err(error) = service() {
            self.write(name, previous.as_deref()).map_err(|rollback| {
                io::Error::other(format!(
                    "服务启动设置失败：{error}；开机项恢复失败：{rollback}"
                ))
            })?;
            return Err(error);
        }
        Ok(())
    }
}
impl Drop for RunKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
pub fn update_startup(
    name: &str,
    command: Option<&str>,
    service: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    RunKey::open(MACHINE, RUN)?.update(name, command, service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::process::CommandExt,
        process::Command,
        sync::{Arc, Barrier},
    };
    fn unique() -> String {
        format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
    #[test]
    fn concurrent_tray_claims_have_one_owner_before_window_creation() {
        let name = Arc::new(format!(r"Local\ConWU.Tray.Test.{}", unique()));
        let barrier = Arc::new(Barrier::new(6));
        let winners = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..6)
                .map(|_| {
                    let name = name.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        let lease = TrayLease::acquire(&name).unwrap();
                        barrier.wait();
                        lease.is_some()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| usize::from(w.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(winners, 1);
        assert!(TrayLease::acquire(&name).unwrap().is_some());
    }
    #[test]
    fn mutex_child() {
        let Ok(name) = std::env::var("CONWU_TRAY_TEST_MUTEX") else {
            return;
        };
        assert_eq!(
            TrayLease::acquire(&name).unwrap().is_some(),
            std::env::var("CONWU_TRAY_TEST_FREE").unwrap() == "true"
        );
    }
    #[test]
    fn tray_claim_spans_processes_and_releases_on_exit() {
        let name = format!(r"Local\ConWU.Tray.Test.{}", unique());
        let lease = TrayLease::acquire(&name).unwrap().unwrap();
        let test = format!(
            "{}::mutex_child",
            module_path!().split_once("::").unwrap().1
        );
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env("CONWU_TRAY_TEST_MUTEX", &name)
            .env("CONWU_TRAY_TEST_FREE", "false")
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            TrayLease::acquire(&(name.clone() + ".independent"))
                .unwrap()
                .is_some()
        );
        drop(lease);
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env("CONWU_TRAY_TEST_MUTEX", name)
            .env("CONWU_TRAY_TEST_FREE", "true")
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    struct TestKey {
        key: Option<RunKey>,
        path: String,
    }
    impl TestKey {
        fn new() -> Self {
            let path = format!(r"Software\ConWU\DesktopTests\{}", unique());
            let key = RunKey::open(-2147483647isize as HANDLE, &path).unwrap();
            Self {
                key: Some(key),
                path,
            }
        }
        fn key(&self) -> &RunKey {
            self.key.as_ref().unwrap()
        }
    }
    impl Drop for TestKey {
        fn drop(&mut self) {
            self.key.take();
            #[link(name = "advapi32")]
            unsafe extern "system" {
                fn RegDeleteTreeW(root: HANDLE, path: *const u16) -> i32;
            }
            let path = wide(&self.path).unwrap();
            unsafe { RegDeleteTreeW(-2147483647isize as HANDLE, path.as_ptr()) };
        }
    }
    #[test]
    fn disabling_startup_removes_only_the_instance_entry() {
        let test = TestKey::new();
        let key = test.key();
        key.write("unrelated", Some("keep")).unwrap();
        let command = r#""D:\测试目录\ConWU.exe" --startup"#;
        key.update("ConWU", Some(command), || Ok(())).unwrap();
        assert_eq!(key.read("ConWU").unwrap().as_deref(), Some(command));
        key.update("ConWU", None, || Ok(())).unwrap();
        key.update("ConWU", None, || Ok(())).unwrap();
        assert_eq!(key.read("ConWU").unwrap(), None);
        assert_eq!(key.read("unrelated").unwrap().as_deref(), Some("keep"));
    }
    #[test]
    fn failed_service_change_restores_previous_startup_entry() {
        let test = TestKey::new();
        let key = test.key();
        key.write("ConWU", Some("previous")).unwrap();
        assert!(
            key.update("ConWU", None, || Err(io::Error::other("service denied")))
                .is_err()
        );
        assert_eq!(key.read("ConWU").unwrap().as_deref(), Some("previous"));
        key.write("ConWU", None).unwrap();
        assert!(
            key.update("ConWU", Some("new"), || Err(io::Error::other(
                "service denied"
            )))
            .is_err()
        );
        assert_eq!(key.read("ConWU").unwrap(), None);
    }
}
