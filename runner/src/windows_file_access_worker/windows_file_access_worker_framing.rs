use super::{wire, Code, Result, MAX_BEGIN};
use serde_json::Value;
use std::io::{Read, Write};
use std::sync::atomic::{compiler_fence, Ordering};

const PREFIX: usize = 124;

#[cfg(test)]
std::thread_local! {
    static ERASURES: std::cell::RefCell<Vec<(&'static str, usize, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(test)]
pub(super) fn take_erasures() -> Vec<(&'static str, usize, bool)> {
    ERASURES.with(|rows| std::mem::take(&mut *rows.borrow_mut()))
}

struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
        #[cfg(test)]
        ERASURES.with(|rows| {
            rows.borrow_mut()
                .push(("bytes", self.0.len(), self.0.iter().all(|v| *v == 0)))
        });
    }
}
// Never Debug/Clone/Serialize. The native reader makes its own separately erased
// credential buffer; source frame and these decoded units are owned and erased.
pub(super) struct SecretUnits(pub Vec<u16>);
impl Drop for SecretUnits {
    fn drop(&mut self) {
        for unit in &mut self.0 {
            unsafe { std::ptr::write_volatile(unit, 0) };
        }
        compiler_fence(Ordering::SeqCst);
        #[cfg(test)]
        ERASURES.with(|rows| {
            rows.borrow_mut()
                .push(("units", self.0.len(), self.0.iter().all(|v| *v == 0)))
        });
    }
}
pub(super) fn read(input: &mut impl Read, maximum: usize, failure: Code) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    input.read_exact(&mut prefix).map_err(|_| failure)?;
    let size = u32::from_le_bytes(prefix) as usize;
    if size == 0 || size > maximum {
        return Err(failure);
    }
    let mut buffer = SecretBytes(vec![0; size]);
    input.read_exact(&mut buffer.0).map_err(|_| failure)?;
    Ok(std::mem::take(&mut buffer.0))
}
pub(super) fn write(
    output: &mut impl Write,
    value: &Value,
    maximum: usize,
    remaining: &mut usize,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Code::NativeFailed)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Code::ResultBoundExceeded);
    }
    let framed = bytes
        .len()
        .checked_add(4)
        .ok_or(Code::ResultBoundExceeded)?;
    // Preflight and debit the whole frame before emitting its prefix. A sealed
    // stdout bound applies to aggregate Ready+terminal, including both prefixes.
    *remaining = remaining
        .checked_sub(framed)
        .ok_or(Code::ResultBoundExceeded)?;
    output
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|_| output.write_all(&bytes))
        .and_then(|_| output.flush())
        .map_err(|_| Code::OutputFailed)
}
#[derive(Default)]
pub(super) struct BeginReader {
    consumed: bool,
}
impl BeginReader {
    pub(super) fn consume(
        &mut self,
        input: &mut impl Read,
        packet: &wire::Packet,
    ) -> Result<SecretUnits> {
        if self.consumed {
            return Err(Code::BeginConsumed);
        }
        // Consume before I/O/validation, including malformed or interrupted Begin.
        self.consumed = true;
        let bytes = SecretBytes(read(input, MAX_BEGIN, Code::BeginInvalid)?);
        let mut trailing = SecretBytes(vec![0; 1]);
        if input
            .read(&mut trailing.0)
            .map_err(|_| Code::BeginInvalid)?
            != 0
        {
            return Err(Code::BeginInvalid);
        }
        parse(&bytes.0, packet)
    }
}
fn parse(raw: &[u8], packet: &wire::Packet) -> Result<SecretUnits> {
    if raw.len() < PREFIX + 2 || &raw[..8] != packet.protocol.begin_magic() {
        return Err(Code::BeginInvalid);
    }
    let request = packet.request();
    let revision = u32::from_le_bytes(raw[88..92].try_into().map_err(|_| Code::BeginInvalid)?);
    let matches = hex::encode(&raw[8..40]) == wire::text(&packet.value["challenge"])?
        && format!("sha256:{}", hex::encode(&raw[40..72])) == packet.digest
        && hex::encode(&raw[72..88]) == wire::text(&request["generation"])?
        && u64::from(revision) == wire::number(&request["control_revision"], 1, i32::MAX as u64)?
        && format!("sha256:{}", hex::encode(&raw[92..124]))
            == wire::text(&request["credential_binding_digest"])?;
    if !matches {
        return Err(Code::BeginInvalid);
    }
    let count = u16::from_le_bytes([raw[PREFIX], raw[PREFIX + 1]]) as usize;
    if !(1..=256).contains(&count) || raw.len() != PREFIX + 2 + count * 2 {
        return Err(Code::BeginInvalid);
    }
    let units = SecretUnits(
        raw[PREFIX + 2..]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect(),
    );
    if units.0.contains(&0) || std::char::decode_utf16(units.0.iter().copied()).any(|v| v.is_err())
    {
        return Err(Code::BeginInvalid);
    }
    Ok(units)
}
