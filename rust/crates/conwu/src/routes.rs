//! Match the original overlay conflict policy before creating an OS adapter.
//! A broad VPN/private route is a warning; an address in our /24 or a matching
//! /24-or-more-specific route blocks creation. No foreign route is removed.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::net::Ipv4Addr;

fn overlap(a: Ipv4Addr, abits: u8, b: Ipv4Addr, bbits: u8) -> bool {
    let bits = abits.min(bbits);
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(a) & mask == u32::from(b) & mask
}
fn evaluate(
    overlay: Ipv4Addr,
    address: Ipv4Addr,
    bits: u8,
    local: bool,
    interface: String,
) -> Option<Value> {
    if bits > 32 || !local && bits == 0 || !overlap(overlay, 24, address, bits) {
        return None;
    }
    let block = if local {
        overlap(overlay, 24, address, 32)
    } else {
        bits >= 24
    };
    Some(
        json!({"severity":if block{"Block"}else{"Warning"},"reason":if local{"LocalAddressPrefixOverlap"}else{"RoutePrefixOverlap"},"interface":interface,"prefix":format!("{address}/{bits}")}),
    )
}
fn finish(rows: Vec<Value>) -> Result<Vec<Value>> {
    ensure!(
        !rows.iter().any(|r| r["severity"] == "Block"),
        "虚拟网段与本机已有地址或路由冲突，请选择不同网段；其他网卡和路由未修改"
    );
    Ok(rows)
}
#[cfg(windows)]
pub fn inspect(ip: Ipv4Addr, ignored: &[u64]) -> Result<Vec<Value>> {
    use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::AF_INET};
    let mut result = Vec::new();
    unsafe {
        let mut addresses = std::ptr::null_mut();
        ensure!(
            GetUnicastIpAddressTable(AF_INET, &mut addresses) == 0,
            "无法核实本机IPv4地址"
        );
        struct Table(*mut std::ffi::c_void);
        impl Drop for Table {
            fn drop(&mut self) {
                unsafe { FreeMibTable(self.0) }
            }
        }
        let _addresses = Table(addresses.cast());
        let count = (*addresses).NumEntries as usize;
        ensure!(count <= 65536, "本机地址表过大");
        for row in std::slice::from_raw_parts(
            std::ptr::addr_of!((*addresses).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
            count,
        ) {
            if ignored.contains(&row.InterfaceLuid.Value) {
                continue;
            }
            let address = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            if let Some(conflict) = evaluate(
                ip,
                address,
                row.OnLinkPrefixLength,
                true,
                format!("WindowsInterface:{:016X}", row.InterfaceLuid.Value),
            ) {
                result.push(conflict);
            }
        }
        let mut routes = std::ptr::null_mut();
        ensure!(
            GetIpForwardTable2(AF_INET, &mut routes) == 0,
            "无法核实本机IPv4路由"
        );
        let _routes = Table(routes.cast());
        let count = (*routes).NumEntries as usize;
        ensure!(count <= 65536, "本机路由表过大");
        for row in std::slice::from_raw_parts(
            std::ptr::addr_of!((*routes).Table).cast::<MIB_IPFORWARD_ROW2>(),
            count,
        ) {
            if ignored.contains(&row.InterfaceLuid.Value) {
                continue;
            }
            let address = Ipv4Addr::from(
                row.DestinationPrefix
                    .Prefix
                    .Ipv4
                    .sin_addr
                    .S_un
                    .S_addr
                    .to_ne_bytes(),
            );
            if let Some(conflict) = evaluate(
                ip,
                address,
                row.DestinationPrefix.PrefixLength,
                false,
                format!("WindowsInterface:{:016X}", row.InterfaceLuid.Value),
            ) {
                result.push(conflict);
            }
        }
    }
    finish(result)
}
#[cfg(target_os = "linux")]
pub fn inspect(ip: Ipv4Addr, _: &[u64]) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for (args, local) in [
        (&["-j", "-4", "address", "show"][..], true),
        (&["-j", "-4", "route", "show", "table", "all"][..], false),
    ] {
        let output = std::process::Command::new("ip").args(args).output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= 16 * 1024 * 1024,
            "无法核实本机IPv4地址或路由"
        );
        let rows: Vec<Value> = serde_json::from_slice(&output.stdout)?;
        for row in rows {
            if local {
                for value in row["addr_info"].as_array().into_iter().flatten() {
                    if let (Some(address), Some(bits)) = (
                        value["local"].as_str().and_then(|s| s.parse().ok()),
                        value["prefixlen"].as_u64().filter(|b| *b <= 32),
                    ) {
                        if let Some(c) = evaluate(
                            ip,
                            address,
                            bits as u8,
                            true,
                            row["ifname"].as_str().unwrap_or("").into(),
                        ) {
                            result.push(c);
                        }
                    }
                }
            } else if let Some(dst) = row["dst"].as_str().filter(|s| *s != "default") {
                let (address, bits) = dst.split_once('/').unwrap_or((dst, "32"));
                if let (Ok(address), Ok(bits)) = (address.parse(), bits.parse()) {
                    if let Some(c) = evaluate(
                        ip,
                        address,
                        bits,
                        false,
                        row["dev"].as_str().unwrap_or("").into(),
                    ) {
                        result.push(c);
                    }
                }
            }
        }
    }
    finish(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conflicts_do_not_block_broad_routes_but_reject_local_or_specific_overlap() {
        let overlay = "10.203.198.1".parse().unwrap();
        let row = |address: &str, bits, local| {
            evaluate(
                overlay,
                address.parse().unwrap(),
                bits,
                local,
                "fixture".into(),
            )
        };
        assert!(row("0.0.0.0", 0, false).is_none());
        assert!(finish(vec![row("10.0.0.0", 8, false).unwrap()]).is_ok());
        assert!(finish(vec![row("10.203.198.0", 24, false).unwrap()]).is_err());
        assert!(finish(vec![row("10.203.198.44", 16, true).unwrap()]).is_err());
        assert!(finish(vec![row("10.203.1.44", 16, true).unwrap()]).is_ok());
        assert!(row("192.168.1.2", 24, true).is_none());
    }
}
