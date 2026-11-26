use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, SetLastError},
    System::Threading::{CreateMutexExW, SYNCHRONIZATION_SYNCHRONIZE},
};

pub(crate) fn wide(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows 名称包含空字符",
        ));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

/// Reserve a window identity before creating its HWND. A Local\ name scopes it
/// to the current interactive session.
pub struct WindowLease(HANDLE);

impl WindowLease {
    pub fn acquire(name: &str) -> io::Result<Option<Self>> {
        let name = wide(name)?;
        // SYNCHRONIZE also lets a filtered user see a reservation created by an
        // elevated process without requesting MUTEX_ALL_ACCESS.
        let (handle, error) = unsafe {
            SetLastError(0);
            let handle = CreateMutexExW(ptr::null(), name.as_ptr(), 0, SYNCHRONIZATION_SYNCHRONIZE);
            (handle, GetLastError())
        };
        if handle.is_null() {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        if error == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Ok(None);
        }
        Ok(Some(Self(handle)))
    }
}

impl Drop for WindowLease {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
