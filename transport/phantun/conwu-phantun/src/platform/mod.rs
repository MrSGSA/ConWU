use crate::Config;
use fake_tcp::tun::TunDevice;
use std::{io, sync::Arc};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

pub fn open(config: &Config) -> io::Result<Arc<dyn TunDevice>> {
    #[cfg(target_os = "windows")]
    {
        Ok(Arc::new(windows::Device::open(config)?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(linux::Device::open(config)?))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "platform unsupported",
        ))
    }
}
