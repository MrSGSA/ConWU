use crate::Config;
use fake_tcp::tun::TunDevice;
use std::{io, sync::Arc};
#[cfg(target_os = "windows")]
mod windows;
// The Linux device is the shared, MIT/Apache raw IP I/O layer only; none of
// Phantun's handshake or data stack participates in either new wire protocol.
#[cfg(target_os = "linux")]
#[path = "../../../conwu-phantun/src/platform/linux.rs"]
mod linux;
pub fn open(config: &Config) -> io::Result<Arc<dyn TunDevice>> {
    #[cfg(target_os = "windows")]
    {
        Ok(Arc::new(windows::Device::open(config)?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(linux::Device::open(config)?))
    }
}
