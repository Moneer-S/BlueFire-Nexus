use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::sync::atomic::{compiler_fence, Ordering};

use super::json::text;
use super::{wire::Packet, Code, Result, MAX_BEGIN};

pub(super) fn read(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    input
        .read_exact(&mut prefix)
        .map_err(|_| Code::BeginInvalid)?;
    let size = u32::from_le_bytes(prefix) as usize;
    if size == 0 || size > maximum {
        return Err(Code::BeginInvalid);
    }
    let mut bytes = SecretBytes(vec![0; size]);
    input
        .read_exact(&mut bytes.0)
        .map_err(|_| Code::BeginInvalid)?;
    Ok(std::mem::take(&mut bytes.0))
}

pub(super) fn write(output: &mut impl Write, value: &Value, maximum: usize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Code::NativeFailed)?;
    if bytes.len() > maximum {
        return Err(Code::ResultBoundExceeded);
    }
    output
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|_| output.write_all(&bytes))
        .and_then(|_| output.flush())
        .map_err(|_| Code::NativeFailed)
}

pub(super) struct SecretBytes(pub Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
pub(super) struct SecretUnits(pub Vec<u16>);
impl Drop for SecretUnits {
    fn drop(&mut self) {
        for unit in &mut self.0 {
            unsafe { std::ptr::write_volatile(unit, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
pub(super) enum Begin {
    Member,
    Client {
        upn: SecretBytes,
        password: SecretUnits,
    },
}

pub(super) fn begin(input: &mut impl Read, packet: &Packet) -> Result<Begin> {
    let raw = SecretBytes(read(input, MAX_BEGIN)?);
    let mut trailing = SecretBytes(vec![0u8; 1]);
    if input
        .read(&mut trailing.0)
        .map_err(|_| Code::BeginInvalid)?
        != 0
    {
        return Err(Code::BeginInvalid);
    }
    parse_begin(&raw.0, packet)
}

fn parse_begin(raw: &[u8], packet: &Packet) -> Result<Begin> {
    if raw.len() < 73
        || &raw[..8] != b"BFADBEG1"
        || hex::encode(&raw[8..40]) != text(&packet.value["challenge"])?
        || format!("sha256:{}", hex::encode(&raw[40..72])) != packet.digest
    {
        return Err(Code::BeginInvalid);
    }
    if packet.value["host_role"] == "member" {
        return if raw.len() == 73 && raw[72] == 0 {
            Ok(Begin::Member)
        } else {
            Err(Code::BeginInvalid)
        };
    }
    if raw[72] != 1 || raw.len() < 77 {
        return Err(Code::BeginInvalid);
    }
    let length = u16::from_le_bytes([raw[73], raw[74]]) as usize;
    if !(1..=318).contains(&length) || raw.len() < 77 + length {
        return Err(Code::BeginInvalid);
    }
    let value = std::str::from_utf8(&raw[75..75 + length]).map_err(|_| Code::BeginInvalid)?;
    if format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
        != text(&packet.value["expected_upn_sha256"])?
    {
        return Err(Code::BeginInvalid);
    }
    let offset = 75 + length;
    let count = u16::from_le_bytes([raw[offset], raw[offset + 1]]) as usize;
    if !(1..=256).contains(&count) || raw.len() != offset + 2 + count * 2 {
        return Err(Code::BeginInvalid);
    }
    let password = SecretUnits(
        raw[offset + 2..]
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect(),
    );
    // Reuse the native credential grammar; the temporary owns and erases all copies.
    let checked = crate::ad_smb_read::SecretCredential::new(value, &password.0)
        .map_err(|_| Code::BeginInvalid)?;
    drop(checked);
    Ok(Begin::Client {
        upn: SecretBytes(value.as_bytes().to_vec()),
        password,
    })
}
