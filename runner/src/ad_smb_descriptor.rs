//! Bounded native descriptor inspection, not share authority or effective-access proof.

use serde::Serialize;
#[cfg(target_os = "windows")]
use sha2::{Digest, Sha256};
use std::ops::Range;

#[cfg(target_os = "windows")]
mod ffi;
#[cfg(target_os = "windows")]
mod windows;

pub const MAX_DESCRIPTOR_BYTES: usize = 65_536;
// Exact finite file-rights masks. SMB cmdlet classification is a separate live gate.
pub const SUPPORTED_READ_MASK: u32 = 0x0012_00a9;
pub const SUPPORTED_FULL_MASK: u32 = 0x001f_01ff;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AceProjection {
    pub ace_type: &'static str,
    pub flags: u8,
    pub trustee_sid: String,
    pub smb_right: &'static str,
    pub raw_ace_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaclProjection {
    pub revision: u8,
    pub aces: Vec<AceProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DescriptorProjection {
    pub binary_b64: String,
    pub sha256: String,
    pub revision: u8,
    pub control: u16,
    pub owner_sid: String,
    pub group_sid: String,
    pub dacl: DaclProjection,
    pub sacl: Option<()>,
}

pub struct Descriptor {
    bytes: Vec<u8>,
    projection: DescriptorProjection,
}

impl Descriptor {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let frame = frame(bytes)?;
        #[cfg(target_os = "windows")]
        return windows::inspect(bytes, frame);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (
                frame.control,
                frame.owner,
                frame.group,
                frame.acl,
                frame.aces,
            );
            Err("native Windows descriptor inspection is unavailable".into())
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn projection(&self) -> &DescriptorProjection {
        &self.projection
    }

    pub fn propose_probe_removal(
        &self,
        probe: &str,
        legitimate: &str,
        controller: &str,
    ) -> Result<Self, String> {
        let domain = domain_user(probe)?;
        if domain_user(legitimate)? != domain
            || domain_user(controller)? != domain
            || probe == legitimate
            || probe == controller
            || legitimate == controller
            || self.projection.owner_sid == probe
            || self.projection.owner_sid == legitimate
        {
            return Err("descriptor principals differ from the finite domain-user recipe".into());
        }
        let aces = &self.projection.dacl.aces;
        if aces.len() != 3
            || [(probe, "Read"), (legitimate, "Read"), (controller, "Full")]
                .iter()
                .any(|(sid, right)| {
                    aces.iter()
                        .filter(|ace| ace.trustee_sid == *sid && ace.smb_right == *right)
                        .count()
                        != 1
                })
        {
            return Err("descriptor must contain exactly the three reviewed allow entries".into());
        }
        #[cfg(target_os = "windows")]
        return windows::remove(self, probe);
        #[cfg(not(target_os = "windows"))]
        Err("native Windows descriptor inspection is unavailable".into())
    }

    /// Diagnostic conversion only; arbitrary SDDL text is never an authority input.
    pub fn diagnostic_sddl(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        return windows::sddl(self);
        #[cfg(not(target_os = "windows"))]
        Err("native Windows descriptor inspection is unavailable".into())
    }
}

fn canonical_sid(sid: &str) -> Result<(), String> {
    if sid.len() > 192 {
        return Err("SID text exceeds its bound".into());
    }
    let parts: Vec<_> = sid.split('-').collect();
    if !(4..=18).contains(&parts.len()) || parts[..2] != ["S", "1"] {
        return Err("SID text is not canonical numeric notation".into());
    }
    let authority = parts[2]
        .parse::<u64>()
        .map_err(|_| "invalid SID authority")?;
    if authority >= (1_u64 << 48) || authority.to_string() != parts[2] {
        return Err("SID authority is outside canonical bounds".into());
    }
    for part in &parts[3..] {
        let number = part.parse::<u32>().map_err(|_| "invalid SID component")?;
        if number.to_string() != *part {
            return Err("SID components must be canonical".into());
        }
    }
    Ok(())
}

fn domain_user(sid: &str) -> Result<&str, String> {
    canonical_sid(sid)?;
    let parts: Vec<_> = sid.split('-').collect();
    if parts.len() != 8 || parts[..4] != ["S", "1", "5", "21"] {
        return Err("principal is not a numeric domain-user SID".into());
    }
    if parts[7].parse::<u32>().map_err(|_| "invalid RID")? < 1000 {
        return Err("domain-user RID is outside the supported recipe".into());
    }
    Ok(sid.rsplit_once('-').ok_or("missing RID")?.0)
}

#[derive(Debug)]
struct Frame {
    control: u16,
    owner: Range<usize>,
    group: Range<usize>,
    acl: Range<usize>,
    aces: Vec<Range<usize>>,
}

fn word(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes.get(offset..offset + 2).ok_or("truncated word")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn dword(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes.get(offset..offset + 4).ok_or("truncated dword")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn sid_range(bytes: &[u8], offset: usize, bound: usize) -> Result<Range<usize>, String> {
    if offset > bound.saturating_sub(8) {
        return Err("SID is outside the descriptor".into());
    }
    let header = bytes.get(offset..offset + 8).ok_or("truncated SID")?;
    let end = offset + 8 + usize::from(header[1]) * 4;
    if offset < 20
        || offset % 4 != 0
        || header[0] != 1
        || !(1..=15).contains(&header[1])
        || end > bound
    {
        return Err("invalid bounded SID framing".into());
    }
    Ok(offset..end)
}

// Validate every pointer-bearing offset before passing hostile bytes to Win32 APIs.
fn frame(bytes: &[u8]) -> Result<Frame, String> {
    if !(20..=MAX_DESCRIPTOR_BYTES).contains(&bytes.len()) || bytes[0..2] != [1, 0] {
        return Err("unsupported descriptor length or revision".into());
    }
    let control = word(bytes, 2)?;
    if ![0x8004, 0x9004].contains(&control) || dword(bytes, 12)? != 0 {
        return Err("unsupported descriptor control or SACL".into());
    }
    let owner = sid_range(bytes, dword(bytes, 4)? as usize, bytes.len())?;
    let group = sid_range(bytes, dword(bytes, 8)? as usize, bytes.len())?;
    let start = dword(bytes, 16)? as usize;
    if start > bytes.len().saturating_sub(8) {
        return Err("DACL is outside the descriptor".into());
    }
    let header = bytes.get(start..start + 8).ok_or("truncated DACL")?;
    let end = start + usize::from(word(bytes, start + 2)?);
    let count = word(bytes, start + 4)?;
    if start < 20
        || start % 4 != 0
        || header[0..2] != [2, 0]
        || word(bytes, start + 6)? != 0
        || end > bytes.len()
        || end < start + 8
        || !(2..=3).contains(&count)
    {
        return Err("unsupported bounded DACL framing".into());
    }
    let mut offset = start + 8;
    let mut aces = Vec::new();
    for _ in 0..count {
        let header = bytes.get(offset..offset + 8).ok_or("truncated ACE")?;
        let ace_end = offset + usize::from(word(bytes, offset + 2)?);
        if header[0..2] != [0, 0]
            || ace_end > end
            || ace_end < offset + 16
            || ace_end % 4 != 0
            || ![SUPPORTED_READ_MASK, SUPPORTED_FULL_MASK].contains(&dword(bytes, offset + 4)?)
            || sid_range(bytes, offset + 8, ace_end)?.end != ace_end
        {
            return Err("unsupported ACE type, flags, mask or framing".into());
        }
        aces.push(offset..ace_end);
        offset = ace_end;
    }
    if bytes[offset..end].iter().any(|byte| *byte != 0) {
        return Err("DACL contains unaccounted nonzero data".into());
    }
    let mut regions = [owner.clone(), group.clone(), start..end];
    regions.sort_by_key(|range| range.start);
    let mut cursor = 20;
    for region in regions {
        if region.start < cursor || bytes[cursor..region.start].iter().any(|byte| *byte != 0) {
            return Err("descriptor regions overlap or contain unaccounted data".into());
        }
        cursor = region.end;
    }
    if cursor != bytes.len() {
        return Err("descriptor has trailing bytes".into());
    }
    Ok(Frame {
        control,
        owner,
        group,
        acl: start..end,
        aces,
    })
}

#[cfg(target_os = "windows")]
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(target_os = "windows")]
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        result.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::canonical_sid;

    #[test]
    fn sid_text_matches_the_saved_numeric_contract_without_normalization() {
        for sid in ["S-1-5-32-544", "S-1-281474976710655-4294967295", "S-1-0-0"] {
            assert!(canonical_sid(sid).is_ok());
        }
        for sid in [
            "S-1-0x100000000-1",
            "S-1-281474976710656-1",
            "S-1-5-4294967296",
            "S-1-05-1",
            "S-1-5-01",
            "S-1-+5-1",
            "S-1-5-+1",
            "S-1-5--1",
            "S-1-5",
            "S-2-5-1",
            "BA",
            "S-1-5-1 ",
            "S-1-5-1\0",
        ] {
            assert!(canonical_sid(sid).is_err(), "accepted {sid:?}");
        }
        assert!(canonical_sid(&format!("S-1-5{}", "-1".repeat(16))).is_err());
    }
}
