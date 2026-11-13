use std::io;
use tokio::sync::oneshot;

pub fn input_stop() -> io::Result<oneshot::Receiver<()>> {
    let (sender, receiver) = oneshot::channel();
    std::thread::Builder::new()
        .name("phantun-stop".into())
        .spawn(move || {
            use std::io::Read;
            // Only the parent holds this inherited pipe's writer. A command or EOF
            // cancels the runtime, which drops sockets and sends Phantun resets.
            let mut byte = [0u8; 1];
            for _ in 0..16 {
                match io::stdin().read(&mut byte) {
                    Ok(1) if byte[0] != b'\n' => {}
                    _ => break,
                }
            }
            let _ = sender.send(());
        })?;
    Ok(receiver)
}

pub fn watch(owner: u32) -> io::Result<oneshot::Receiver<()>> {
    let (sender, receiver) = oneshot::channel();
    #[cfg(target_os = "windows")]
    {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
            fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        let handle = unsafe { OpenProcess(0x00100000, 0, owner) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // Move the numeric handle, not a non-Send raw pointer, into the monitor.
        let value = handle as usize;
        if let Err(error) = std::thread::Builder::new()
            .name("phantun-parent".into())
            .spawn(move || {
                let handle = value as *mut c_void;
                unsafe {
                    WaitForSingleObject(handle, u32::MAX);
                    CloseHandle(handle);
                }
                let _ = sender.send(());
            })
        {
            unsafe {
                CloseHandle(handle);
            }
            return Err(error);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // The actual parent is checked on both sides of installing PDEATHSIG.
        if unsafe { libc::getppid() } as u32 != owner {
            return Err(io::Error::other("Phantun parent mismatch"));
        }
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::getppid() } as u32 != owner {
            return Err(io::Error::other("Phantun parent disappeared"));
        }
        std::thread::Builder::new()
            .name("phantun-parent".into())
            .spawn(move || {
                loop {
                    if unsafe { libc::getppid() } as u32 != owner {
                        let _ = sender.send(());
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            })?;
    }
    Ok(receiver)
}
