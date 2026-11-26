use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Graphics::Gdi::{
    DEVMODEW, ENUM_CURRENT_SETTINGS, EnumDisplaySettingsW, GetMonitorInfoW,
    MONITOR_DEFAULTTONEAREST, MONITORINFOEXW, MonitorFromWindow,
};

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(super) struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u32,
}

impl DisplayMode {
    pub fn read(surface: Option<usize>) -> Result<Self> {
        let mut info = MONITORINFOEXW::default();
        let device = if let Some(surface) = surface {
            let monitor = unsafe { MonitorFromWindow(surface as _, MONITOR_DEFAULTTONEAREST) };
            info.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
            ensure!(
                !monitor.is_null()
                    && unsafe { GetMonitorInfoW(monitor, &mut info.monitorInfo) } != 0,
                "无法读取播放窗口所在显示器"
            );
            info.szDevice.as_ptr()
        } else {
            std::ptr::null()
        };
        let mut mode = DEVMODEW {
            dmSize: size_of::<DEVMODEW>() as u16,
            ..Default::default()
        };
        ensure!(
            unsafe { EnumDisplaySettingsW(device, ENUM_CURRENT_SETTINGS, &mut mode) } != 0,
            "无法读取显示器分辨率"
        );
        Ok(Self {
            width: mode.dmPelsWidth,
            height: mode.dmPelsHeight,
            refresh_hz: mode.dmDisplayFrequency,
        })
    }

    pub fn stream_size(self) -> Result<(u16, u16)> {
        ensure!(
            self.width >= 640 && self.height >= 360,
            "显示器分辨率低于 640×360"
        );
        let scale = (7680.0 / f64::from(self.width))
            .min(4320.0 / f64::from(self.height))
            .min(1.0);
        let width = (f64::from(self.width) * scale) as u16 & !1;
        let height = (f64::from(self.height) * scale) as u16 & !1;
        ensure!(width >= 640 && height >= 360, "显示器宽高比超出串流范围");
        Ok((width, height))
    }
}
