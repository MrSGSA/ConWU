use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString, c_void},
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::Arc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE, WAIT_TIMEOUT},
    Security::{
        Cryptography::{CERT_NAME_ATTR_TYPE, CertGetNameStringW},
        WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
            WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
        },
    },
    Storage::FileSystem::{
        FILE_SHARE_READ, FILE_VER_GET_NEUTRAL, GetFileVersionInfoExW, GetFileVersionInfoSizeExW,
        VerQueryValueW,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            QueryFullProcessImageNameW, WaitForSingleObject,
        },
    },
};

fn executable_name(name: &str) -> Option<&'static str> {
    ["GameViewer.exe", "GameViewerServer.exe"]
        .into_iter()
        .find(|expected| name.eq_ignore_ascii_case(expected))
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

fn version_value<'a>(info: &'a [u8], key: &str, unit: usize) -> Option<&'a [u8]> {
    let key = wide(OsStr::new(key));
    let mut value = null_mut();
    let mut len = 0;
    if unsafe { VerQueryValueW(info.as_ptr().cast(), key.as_ptr(), &mut value, &mut len) } == 0 {
        return None;
    }
    let offset = (value as usize).checked_sub(info.as_ptr() as usize)?;
    let size = (len as usize).checked_mul(unit)?;
    info.get(offset..offset.checked_add(size)?)
}

fn signed_original_name(path: &[u16], expected: &str) -> bool {
    let size =
        unsafe { GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, path.as_ptr(), null_mut()) };
    if !(1..=65536).contains(&size) {
        return false;
    }
    let mut info = vec![0; size as usize];
    if unsafe {
        GetFileVersionInfoExW(
            FILE_VER_GET_NEUTRAL,
            path.as_ptr(),
            0,
            size,
            info.as_mut_ptr().cast(),
        )
    } == 0
    {
        return false;
    }
    let Some(translations) = version_value(&info, r"\VarFileInfo\Translation", 1) else {
        return false;
    };
    translations.chunks_exact(4).any(|entry| {
        let language = u16::from_le_bytes([entry[0], entry[1]]);
        let codepage = u16::from_le_bytes([entry[2], entry[3]]);
        let key = format!(r"\StringFileInfo\{language:04x}{codepage:04x}\OriginalFilename");
        version_value(&info, &key, 2).is_some_and(|value| {
            let value = value
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|&ch| ch != 0)
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&value).eq_ignore_ascii_case(expected)
        })
    })
}

fn signed_by_netease(path: &[u16], file: &File) -> bool {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: null_mut(),
    };
    let mut trust = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let verified = unsafe {
        if WinVerifyTrust(null_mut(), &mut action, (&raw mut trust).cast::<c_void>()) == 0 {
            // Use the file signer selected by the successful Authenticode policy.
            let provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
            let signer = if provider.is_null() {
                null_mut()
            } else {
                WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
            };
            let cert = if signer.is_null() {
                null_mut()
            } else {
                WTHelperGetProvCertFromChain(signer, 0)
            };
            cert.as_ref()
                .filter(|cert| !cert.pCert.is_null())
                .is_some_and(|cert| {
                    let mut name = [0u16; 128];
                    let size = CertGetNameStringW(
                        cert.pCert,
                        CERT_NAME_ATTR_TYPE,
                        0,
                        c"2.5.4.10".as_ptr().cast(),
                        name.as_mut_ptr(),
                        name.len() as u32,
                    ) as usize;
                    size > 1
                        && size < name.len()
                        && String::from_utf16_lossy(&name[..size - 1])
                            .eq_ignore_ascii_case("NetEase (Hangzhou) Network Co., Ltd")
                })
        } else {
            false
        }
    };
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(null_mut(), &mut action, (&raw mut trust).cast::<c_void>()) };
    verified
}

fn verified_image(path: &Path) -> bool {
    let Some(expected) = path
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(executable_name)
    else {
        return false;
    };
    // Keep the image stable between the signature and version-resource reads.
    let Ok(file) = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
    else {
        return false;
    };
    let path = wide(path.as_os_str());
    signed_by_netease(&path, &file) && signed_original_name(&path, expected)
}

#[derive(Clone)]
pub(super) struct Process {
    pub pid: u32,
    handle: Arc<OwnedHandle>,
}

impl Process {
    fn open(pid: u32) -> Option<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return None;
        }
        Some(Self {
            pid,
            handle: Arc::new(unsafe { OwnedHandle::from_raw_handle(handle) }),
        })
    }

    pub fn running(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) == WAIT_TIMEOUT }
    }

    fn image_path(&self) -> Option<PathBuf> {
        let mut image = vec![0u16; 32768];
        let mut n = image.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(self.handle.as_raw_handle(), 0, image.as_mut_ptr(), &mut n)
        } == 0
        {
            return None;
        }
        Some(PathBuf::from(OsString::from_wide(&image[..n as usize])))
    }
}

struct Observation {
    process: Process,
    verified: bool,
    checked: Instant,
}

#[derive(Default)]
pub(super) struct Scanner {
    images: HashMap<u32, Observation>,
}

impl Scanner {
    pub fn poll(&mut self) -> Result<Vec<Process>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        ensure!(snapshot != INVALID_HANDLE_VALUE, "无法枚举 UU 进程");
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        ensure!(
            unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0,
            "无法读取进程列表"
        );
        let mut candidates = vec![];
        loop {
            let length = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            if executable_name(&String::from_utf16_lossy(&entry.szExeFile[..length])).is_some() {
                candidates.push(entry.th32ProcessID);
            }
            if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
                let error = io::Error::last_os_error();
                ensure!(
                    error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32),
                    "进程列表读取失败：{error}"
                );
                break;
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        self.images.retain(|pid, observation| {
            candidates.binary_search(pid).is_ok()
                && observation.process.running()
                && (observation.verified || observation.checked.elapsed() < Duration::from_secs(15))
        });
        for pid in candidates {
            if let std::collections::hash_map::Entry::Vacant(entry) = self.images.entry(pid) {
                let Some(process) = Process::open(pid) else {
                    continue;
                };
                let verified = process
                    .image_path()
                    .is_some_and(|path| verified_image(&path));
                entry.insert(Observation {
                    process,
                    verified,
                    checked: Instant::now(),
                });
            }
        }
        let mut recognized = self
            .images
            .values()
            .filter(|entry| entry.verified && entry.process.running())
            .map(|entry| entry.process.clone())
            .collect::<Vec<_>>();
        recognized.sort_unstable_by_key(|process| process.pid);
        Ok(recognized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires installed official UU binaries and local file fixtures"]
    fn official_executables_are_verified_at_nondefault_paths() {
        let path = PathBuf::from(std::env::var_os("CONWU_UU_IDENTITY_FIXTURES").unwrap());
        for exe in ["GameViewer.exe", "GameViewerServer.exe"] {
            assert!(verified_image(&path.join("relocated").join(exe)), "{exe}");
        }
        assert!(!verified_image(
            &path.join("foreign").join("GameViewer.exe")
        ));
        assert!(!verified_image(
            &path.join("wrong-role").join("GameViewer.exe")
        ));
        assert!(!verified_image(
            &path.join("tampered").join("GameViewer.exe")
        ));
    }

    #[test]
    #[ignore = "requires running official UU processes"]
    fn identifies_existing_uu_processes_without_opening_a_rule() -> Result<()> {
        let pids = std::env::var("CONWU_UU_EXPECTED_PIDS")?;
        let expected = pids
            .split(',')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()?;
        let mut scanner = Scanner::default();
        for _ in 0..2 {
            let found = scanner
                .poll()?
                .into_iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>();
            assert!(expected.iter().all(|pid| found.contains(pid)), "{found:?}");
        }
        Ok(())
    }
}
