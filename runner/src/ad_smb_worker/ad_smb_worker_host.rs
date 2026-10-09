//! Local premises only, not host enrollment or remote authentication evidence.

#[cfg(target_os = "windows")]
#[path = "ad_smb_worker_host_ffi.rs"]
mod ffi;
#[cfg(test)]
#[path = "ad_smb_worker_host_tests.rs"]
mod tests;
#[cfg(target_os = "windows")]
#[path = "ad_smb_worker_host_windows.rs"]
mod windows;

use super::{wire::Packet, Code, Result};
#[cfg(any(target_os = "windows", test))]
use serde_json::Value;
#[cfg(any(target_os = "windows", test))]
use std::collections::BTreeSet;

#[cfg(any(target_os = "windows", test))]
const MAX_VALUES: usize = 64;
#[cfg(any(target_os = "windows", test))]
const MAX_NAME: usize = 512;
#[cfg(any(target_os = "windows", test))]
const MAX_DATA: usize = 1024;

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Eq, PartialEq)]
struct PolicyValue {
    name: String,
    kind: u32,
    data: Vec<u8>,
}

#[cfg(any(target_os = "windows", test))]
struct Facts {
    fqdn: String,
    domain_dns: String,
    domain_sid: String,
    process_machine: u16,
    native_machine: u16,
    version: [u32; 4],
    product_type: u8,
    policy: Vec<PolicyValue>,
}

pub(super) fn verify(packet: &Packet) -> Result<()> {
    packet.current()?;
    #[cfg(target_os = "windows")]
    {
        let role = packet.value["host_role"]
            .as_str()
            .ok_or(Code::PreconditionFailed)?;
        let facts = windows::observe(packet, role == "client")?;
        matches(&packet.request()["scope"], role, &facts)?;
        packet.current()
    }
    #[cfg(not(target_os = "windows"))]
    Err(Code::NativeUnavailable)
}

#[cfg(any(target_os = "windows", test))]
fn matches(scope: &Value, role: &str, facts: &Facts) -> Result<()> {
    let host = &scope["hosts"][role];
    let version = facts.version.map(|part| part.to_string()).join(".");
    let product = match role {
        "member" => facts.product_type == 3 && facts.version[2] == 20_348,
        "client" => facts.product_type == 1,
        _ => false,
    };
    require(
        product
            && facts.version[..2] == [10, 0]
            && host["architecture"] == "x86_64"
            && host["os_build"] == version
            && facts.process_machine == 0
            && facts.native_machine == 0x8664
            && canonical_dns(&facts.fqdn).as_deref() == host["fqdn"].as_str()
            && canonical_dns(&facts.domain_dns).as_deref() == scope["domain"]["dns"].as_str()
            && facts.domain_sid == scope["domain"]["sid"],
    )?;
    if role == "client" {
        policy(
            &facts.policy,
            scope["share"]["unc"]
                .as_str()
                .ok_or(Code::PreconditionFailed)?,
        )?;
    }
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn canonical_dns(value: &str) -> Option<String> {
    if value.len() > 253 || !value.contains('.') || !server(value) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

#[cfg(any(target_os = "windows", test))]
fn server(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

#[cfg(any(target_os = "windows", test))]
fn unc(value: &str) -> Result<(String, String)> {
    require(value.is_ascii() && value.len() <= MAX_NAME)?;
    let mut parts = value
        .strip_prefix("\\\\")
        .ok_or(Code::PreconditionFailed)?
        .split('\\');
    let host = parts.next().ok_or(Code::PreconditionFailed)?;
    let share = parts.next().ok_or(Code::PreconditionFailed)?;
    require(
        parts.next().is_none()
            && (host == "*" || server(host))
            && (share == "*"
                || (!share.is_empty()
                    && share.len() <= 80
                    && share
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.$-".contains(&c)))),
    )?;
    Ok((host.to_ascii_lowercase(), share.to_ascii_lowercase()))
}

#[cfg(any(target_os = "windows", test))]
fn policy(rows: &[PolicyValue], target: &str) -> Result<()> {
    require(!rows.is_empty() && rows.len() <= MAX_VALUES)?;
    let target = unc(target)?;
    require(target.0 != "*" && target.1 != "*")?;
    let mut names = BTreeSet::new();
    let mut selected = None;
    let mut total = 0_usize;
    for row in rows {
        require(row.name.len() <= MAX_NAME && row.data.len() <= MAX_DATA)?;
        total = total
            .checked_add(row.data.len())
            .ok_or(Code::PreconditionFailed)?;
        require(total <= MAX_VALUES * MAX_DATA && names.insert(row.name.to_ascii_lowercase()))?;
        // Unsupported shapes are refused, not interpreted with guessed wildcard precedence.
        let pattern = unc(&row.name)?;
        if (pattern.0 == "*" || pattern.0 == target.0)
            && (pattern.1 == "*" || pattern.1 == target.1)
        {
            require(pattern == target && selected.is_none())?;
            selected = Some(row);
        }
    }
    let row = selected.ok_or(Code::PreconditionFailed)?;
    require(row.kind == 1 && row.data.len() >= 2 && row.data.len() % 2 == 0)?;
    let units = row
        .data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    require(units.last() == Some(&0) && !units[..units.len() - 1].contains(&0))?;
    let text =
        String::from_utf16(&units[..units.len() - 1]).map_err(|_| Code::PreconditionFailed)?;
    require(text.is_ascii())?;
    let mut fields = BTreeSet::new();
    for part in text.split(',') {
        let (name, value) = part
            .trim_matches(' ')
            .split_once('=')
            .ok_or(Code::PreconditionFailed)?;
        require(value == "1" && fields.insert(name.to_ascii_lowercase()))?;
    }
    require(
        fields
            == BTreeSet::from([
                "requiremutualauthentication".to_owned(),
                "requireintegrity".to_owned(),
                "requireprivacy".to_owned(),
            ]),
    )
}

#[cfg(any(target_os = "windows", test))]
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Code::PreconditionFailed)
    }
}
