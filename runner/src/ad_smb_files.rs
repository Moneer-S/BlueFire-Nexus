//! Finite member-local observations, not enrollment or effective-access proof.
//!
//! No action registers this component. Synchronous OS calls still need an owned
//! disposable-process deadline. Held handles and pre/post checks are not a CAS
//! or an exclusive-writer guarantee. Only OWNER/GROUP/DACL are requested.

use crate::ad_smb_descriptor::DescriptorProjection;
use crate::ad_smb_share::LocalShareTarget;
use serde::Serialize;
#[cfg(any(target_os = "windows", test))]
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "windows", test))]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
mod ffi;
#[cfg(test)]
#[path = "ad_smb_files/ad_smb_files_tests.rs"]
mod tests;
#[cfg(target_os = "windows")]
mod windows;

pub const MAX_CONTENT_BYTES: u64 = 65_536;
pub const SELECTED_SECURITY_INFORMATION: u32 = 7;
#[cfg(any(target_os = "windows", test))]
const MAX_ELAPSED: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedSecurity {
    pub security_information: u32,
    pub binary_hex: String,
    pub sha256: String,
    pub finite_descriptor: Option<DescriptorProjection>,
    pub sacl_observed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObjectFacts {
    pub final_path: String,
    pub volume_serial: String,
    pub file_id: String,
    pub directory: bool,
    pub size: u64,
    pub links: u32,
    pub attributes: u32,
    pub reparse_tag: u32,
    pub creation_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub ntfs: bool,
    pub disk_file: bool,
    pub delete_pending: bool,
    pub selected_security: SelectedSecurity,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileDigest {
    pub name: &'static str,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct LocalFilesObservation {
    pub schema_version: &'static str,
    pub share_name: String,
    pub local_path: String,
    /// Drive, BlueFire, AD, generated root, records, health; all held together.
    pub objects: Vec<ObjectFacts>,
    pub files: Vec<FileDigest>,
    pub selected_facts_unchanged: bool,
    pub authenticated_member_identity: bool,
    pub effective_access_proved: bool,
}

#[derive(Debug, Serialize)]
pub struct LocalFilesAttempt {
    pub observation: Option<LocalFilesObservation>,
    pub issue: Option<String>,
    pub owned_handles_closed: bool,
}

pub fn observe_generated(target: &LocalShareTarget) -> LocalFilesAttempt {
    #[cfg(target_os = "windows")]
    return observe_with(target, &mut windows::WindowsBackend::default());
    #[cfg(not(target_os = "windows"))]
    {
        let _ = target;
        LocalFilesAttempt {
            observation: None,
            issue: Some("native Windows local file observation is unavailable".into()),
            owned_handles_closed: true,
        }
    }
}

#[cfg(any(target_os = "windows", test))]
trait Backend {
    fn fixed_drive(&mut self, drive: &str) -> Result<(), String>;
    fn open(&mut self, path: &str, directory: bool) -> Result<(), String>;
    fn facts(&mut self, index: usize) -> Result<ObjectFacts, String>;
    fn read(&mut self, index: usize, output: &mut [u8]) -> Result<usize, String>;
    fn close(&mut self) -> bool;
}

#[cfg(any(target_os = "windows", test))]
fn recipe(target: &LocalShareTarget) -> [String; 6] {
    let drive = &target.path()[..2];
    [
        format!("{drive}\\"),
        format!("{drive}\\BlueFire"),
        format!("{drive}\\BlueFire\\AD"),
        target.path().to_owned(),
        format!("{}\\records.jsonl", target.path()),
        format!("{}\\health.jsonl", target.path()),
    ]
}

#[cfg(any(target_os = "windows", test))]
fn observe_with(target: &LocalShareTarget, backend: &mut impl Backend) -> LocalFilesAttempt {
    let result = inspect(target, backend);
    let closed = backend.close();
    LocalFilesAttempt {
        observation: result.as_ref().ok().map(|value| LocalFilesObservation {
            schema_version: "bluefire.ad-smb-local-files.v1",
            share_name: target.name().to_owned(),
            local_path: target.path().to_owned(),
            objects: value.0.clone(),
            files: value.1.clone(),
            selected_facts_unchanged: true,
            authenticated_member_identity: false,
            effective_access_proved: false,
        }),
        issue: result
            .err()
            .or_else(|| (!closed).then(|| "owned_handle_cleanup_unknown".into())),
        owned_handles_closed: closed,
    }
}

#[cfg(any(target_os = "windows", test))]
fn current(start: Instant) -> Result<(), String> {
    if start.elapsed() > MAX_ELAPSED {
        return Err("local file observation deadline exceeded".into());
    }
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn inspect(
    target: &LocalShareTarget,
    backend: &mut impl Backend,
) -> Result<(Vec<ObjectFacts>, Vec<FileDigest>), String> {
    let start = Instant::now();
    let paths = recipe(target);
    backend.fixed_drive(&paths[0])?;
    let mut before = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        current(start)?;
        backend.open(path, index < 4)?;
        let facts = backend.facts(index)?;
        validate(&facts, path, index)?;
        if before.iter().any(|row: &ObjectFacts| {
            row.volume_serial != facts.volume_serial || row.file_id == facts.file_id
        }) {
            return Err("generated objects changed volume or alias an existing identity".into());
        }
        before.push(facts);
    }
    let total = before[4]
        .size
        .checked_add(before[5].size)
        .ok_or("generated content size overflow")?;
    if total > MAX_CONTENT_BYTES {
        return Err("generated contents exceed aggregate bound".into());
    }
    let mut files = Vec::new();
    for (index, name) in [(4, "records.jsonl"), (5, "health.jsonl")] {
        let mut remaining = before[index].size;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            current(start)?;
            let bound = remaining.min(buffer.len() as u64) as usize;
            let count = backend.read(index, &mut buffer[..bound])?;
            if count == 0 || count > bound {
                return Err("generated content read did not match held size".into());
            }
            hash.update(&buffer[..count]);
            buffer[..count].fill(0);
            remaining -= count as u64;
        }
        current(start)?;
        if backend.read(index, &mut buffer[..1])? != 0 {
            return Err("generated content grew beyond held size".into());
        }
        files.push(FileDigest {
            name,
            bytes: before[index].size,
            sha256: format!("sha256:{:x}", hash.finalize()),
        });
    }
    for (index, expected) in before.iter().enumerate() {
        current(start)?;
        if backend.facts(index)? != *expected {
            return Err("held identity, metadata or selected security changed".into());
        }
    }
    current(start)?;
    Ok((before, files))
}

#[cfg(any(target_os = "windows", test))]
fn validate(facts: &ObjectFacts, path: &str, index: usize) -> Result<(), String> {
    let hexadecimal = |value: &str, size| {
        value.len() == size
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if facts.final_path != format!("\\\\?\\{path}")
        || !hexadecimal(&facts.volume_serial, 16)
        || !hexadecimal(&facts.file_id, 32)
        || facts.file_id.bytes().all(|byte| byte == b'0')
        || facts.directory != (index < 4)
        || !facts.ntfs
        || !facts.disk_file
        || facts.delete_pending
        || facts.reparse_tag != 0
        || facts.attributes & (0x400 | 0x1000) != 0
        || (facts.attributes & 0x10 != 0) != facts.directory
        || (index >= 4 && (facts.links != 1 || facts.size == 0 || facts.size > MAX_CONTENT_BYTES))
        || facts.selected_security.security_information != SELECTED_SECURITY_INFORMATION
        || facts.selected_security.sacl_observed
        || facts.selected_security.finite_descriptor.is_some() != (index >= 3)
    {
        return Err("local file facts differ from the finite generated recipe".into());
    }
    Ok(())
}
