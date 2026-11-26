use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf, ptr::NonNull};

use anyhow::{Context, Result};
use windows::{
    Win32::{
        Foundation::VARIANT_TRUE,
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
            NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_PROFILE2_ALL,
            NET_FW_RULE_DIR_IN, NetFwPolicy2, NetFwRule,
        },
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            Ole::{SafeArrayCreateVector, SafeArrayPutElement},
            Variant::{VARENUM, VARIANT, VT_ARRAY, VT_BSTR, VT_VARIANT, VariantClear},
        },
    },
    core::BSTR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Scope {
    pub program: PathBuf,
    pub interface: String,
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
    pub ports: Vec<u16>,
    pub udp: bool,
    pub block: bool,
}

pub(super) fn interface_alias(index: u32) -> Option<String> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return None;
    }
    let end = row.Alias.iter().position(|&unit| unit == 0)?;
    String::from_utf16(&row.Alias[..end])
        .ok()
        .filter(|alias| !alias.is_empty())
}

struct Apartment;

impl Apartment {
    fn initialize() -> Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[derive(Default)]
struct AutomationValue(VARIANT);

impl Drop for AutomationValue {
    fn drop(&mut self) {
        let _ = unsafe { VariantClear(&mut self.0) };
    }
}

fn set_interface(rule: &INetFwRule, alias: &str) -> Result<()> {
    let mut interfaces = AutomationValue::default();
    let mut name = AutomationValue::default();
    unsafe {
        let item = &mut *name.0.Anonymous.Anonymous;
        item.vt = VT_BSTR;
        item.Anonymous.bstrVal = std::mem::ManuallyDrop::new(BSTR::from(alias));
        let array = NonNull::new(SafeArrayCreateVector(VT_VARIANT, 0, 1))
            .context("无法分配 Projection 防火墙网卡列表")?;
        let list = &mut *interfaces.0.Anonymous.Anonymous;
        list.vt = VARENUM(VT_ARRAY.0 | VT_VARIANT.0);
        list.Anonymous.parray = array.as_ptr();
        SafeArrayPutElement(array.as_ptr(), &0, (&name.0 as *const VARIANT).cast())?;
        rule.SetInterfaces(&interfaces.0)?;
    }
    Ok(())
}

fn configured_rule(name: &str, scope: &Scope) -> Result<INetFwRule> {
    let program = scope.program.to_string_lossy();
    let program = program.strip_prefix(r"\\?\").unwrap_or(&program);
    let name = BSTR::from(name);
    unsafe {
        let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        rule.SetName(&name)?;
        rule.SetGrouping(&BSTR::from("ConWU Projection"))?;
        rule.SetApplicationName(&BSTR::from(program))?;
        let protocol = if scope.udp {
            NET_FW_IP_PROTOCOL_UDP
        } else {
            NET_FW_IP_PROTOCOL_TCP
        };
        rule.SetProtocol(protocol.0)?;
        let ports = scope
            .ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        rule.SetLocalPorts(&BSTR::from(ports))?;
        rule.SetLocalAddresses(&BSTR::from(scope.local.to_string()))?;
        rule.SetRemoteAddresses(&BSTR::from(scope.remote.to_string()))?;
        set_interface(&rule, &scope.interface)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
        rule.SetDirection(NET_FW_RULE_DIR_IN)?;
        rule.SetAction(if scope.block {
            NET_FW_ACTION_BLOCK
        } else {
            NET_FW_ACTION_ALLOW
        })?;
        rule.SetEnabled(VARIANT_TRUE)?;
        Ok(rule)
    }
}

#[derive(Default)]
pub(super) struct Rules {
    applied: BTreeMap<String, Scope>,
    warning: Option<String>,
}

impl Rules {
    pub(super) fn is_current(&self, desired: &BTreeMap<String, Scope>) -> bool {
        self.applied == *desired
    }

    pub(super) fn apply(&mut self, desired: BTreeMap<String, Scope>) {
        match self.reconcile(&desired) {
            Ok(()) => self.warning = None,
            Err(error) => {
                let message = format!("{error:#}");
                if self.warning.as_deref() != Some(&message) {
                    tracing::warn!("Projection 防火墙规则更新失败：{message}");
                    self.warning = Some(message);
                }
            }
        }
    }

    fn reconcile(&mut self, desired: &BTreeMap<String, Scope>) -> Result<()> {
        let _apartment = Apartment::initialize()?;
        let rules: INetFwRules = unsafe {
            let policy: INetFwPolicy2 =
                CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
            policy.Rules()?
        };
        let mut failure = None;
        for name in self
            .applied
            .keys()
            .filter(|name| !desired.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>()
        {
            match unsafe { rules.Remove(&BSTR::from(&name)) } {
                Ok(()) => {
                    self.applied.remove(&name);
                }
                Err(error) => {
                    failure.get_or_insert_with(|| anyhow::Error::from(error));
                }
            }
        }
        for (name, scope) in desired {
            if self.applied.get(name) != Some(scope) {
                let install = (|| -> Result<()> {
                    let rule = configured_rule(name, scope)?;
                    // Reclaim the same name after a restart, including a stale Wintun binding.
                    unsafe { rules.Remove(&BSTR::from(name))? };
                    self.applied.remove(name);
                    unsafe { rules.Add(&rule)? };
                    Ok(())
                })();
                match install {
                    Ok(()) => {
                        self.applied.insert(name.clone(), scope.clone());
                    }
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
