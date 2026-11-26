use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Graphics::Gdi::*,
    UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN},
};

#[derive(Serialize, Deserialize)]
pub(crate) struct Preview {
    pub image: String,
}

pub(super) fn preview(detailed: bool) -> Result<Preview> {
    let _dpi = super::drop_target::DpiScope::physical_pixels();
    let mut info = BITMAPINFO::default();
    let bytes = unsafe {
        let (sw, sh) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        ensure!(sw > 0 && sh > 0, "当前桌面不可用");
        let (width, height) = if detailed { (768.0, 432.0) } else { (192.0, 108.0) };
        let scale = (width / f64::from(sw)).min(height / f64::from(sh)).min(1.0);
        let (w, h) = (
            ((f64::from(sw) * scale) as i32).max(1),
            ((f64::from(sh) * scale) as i32).max(1),
        );
        let length = ((w * 3 + 3) & !3) * h;
        info.bmiHeader = BITMAPINFOHEADER {
            biSize: 40,
            biWidth: w,
            biHeight: h,
            biPlanes: 1,
            biBitCount: 24,
            biSizeImage: length as u32,
            ..Default::default()
        };
        let screen = GetDC(std::ptr::null_mut());
        ensure!(!screen.is_null(), "无法读取桌面");
        let memory = CreateCompatibleDC(screen);
        let mut pixels = std::ptr::null_mut();
        let bitmap = CreateDIBSection(
            screen,
            &info,
            DIB_RGB_COLORS,
            &mut pixels,
            std::ptr::null_mut(),
            0,
        );
        let result = (|| -> Result<Vec<u8>> {
            ensure!(
                !memory.is_null() && !bitmap.is_null() && !pixels.is_null(),
                "无法创建桌面缩略图"
            );
            let old = SelectObject(memory, bitmap);
            ensure!(!old.is_null(), "无法选择缩略图画布");
            SetStretchBltMode(memory, HALFTONE);
            let copied = StretchBlt(memory, 0, 0, w, h, screen, 0, 0, sw, sh, SRCCOPY);
            GdiFlush();
            SelectObject(memory, old);
            ensure!(copied != 0, "当前桌面不可捕获");
            let pixels = std::slice::from_raw_parts(pixels.cast::<u8>(), length as usize);
            if detailed {
                let stride = ((w * 3 + 3) & !3) as usize;
                let bgr: Vec<u8> = pixels.chunks_exact(stride).rev()
                    .flat_map(|row| row[..w as usize * 3].iter().copied()).collect();
                for quality in [78, 55, 35, 15, 5] {
                    let mut jpeg = Vec::new();
                    jpeg_encoder::Encoder::new(&mut jpeg, quality).encode(
                        &bgr, w as u16, h as u16, jpeg_encoder::ColorType::Bgr,
                    )?;
                    if jpeg.len() <= 72 * 1024 { return Ok(jpeg); }
                }
                anyhow::bail!("桌面缩略图超过大小限制");
            }
            let mut bmp = Vec::with_capacity(54 + length as usize);
            bmp.extend_from_slice(b"BM");
            bmp.extend_from_slice(&(54u32 + length as u32).to_le_bytes());
            bmp.extend_from_slice(&[0; 4]);
            bmp.extend_from_slice(&54u32.to_le_bytes());
            bmp.extend_from_slice(std::slice::from_raw_parts(
                (&info.bmiHeader as *const BITMAPINFOHEADER).cast::<u8>(),
                40,
            ));
            bmp.extend_from_slice(pixels);
            Ok(bmp)
        })();
        if !bitmap.is_null() {
            DeleteObject(bitmap);
        }
        if !memory.is_null() {
            DeleteDC(memory);
        }
        ReleaseDC(std::ptr::null_mut(), screen);
        result?
    };
    Ok(Preview {
        image: STANDARD.encode(bytes),
    })
}
