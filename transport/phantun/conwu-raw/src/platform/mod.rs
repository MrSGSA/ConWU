use crate::Config;
use fake_tcp::tun::TunDevice;
use std::{io, sync::Arc};
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
mod xdp;
#[cfg(target_os = "windows")]
pub fn xdp_probe(index: u32) -> io::Result<u32> {
    xdp::probe(index)
}
// The Linux device is the shared, MIT/Apache raw IP I/O layer only; none of
// Phantun's handshake or data stack participates in either new wire protocol.
#[cfg(target_os = "linux")]
#[path = "../../../conwu-phantun/src/platform/linux.rs"]
mod linux;
pub fn open(config: &Config) -> io::Result<Arc<dyn TunDevice>> {
    #[cfg(target_os = "windows")]
    {
        if config.carrier == crate::Carrier::Mimic {
            // Generic XDP queue binding has repeatedly failed on the AX211
            // WLAN adapter. Use WinDivert for normal operation; keep XDP as
            // an explicit development option, with observable startup fallback.
            if std::env::var("CONWU_MIMIC_IO").as_deref() == Ok("xdp") {
                match xdp::Device::open(config) {
                    Ok(device) => return Ok(Arc::new(device)),
                    Err(error) => crate::event(serde_json::json!({"event":"backend-fallback","from":"xdp","to":"windivert","reason":error.to_string()})),
                }
            }
            Ok(Arc::new(windows::Device::open(config)?))
        } else {
            Ok(Arc::new(windows::Device::open(config)?))
        }
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(linux::Device::open(config)?))
    }
}
