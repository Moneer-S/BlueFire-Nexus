//! Pure enrolled-resource schema and bounded authority validation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::canonical::canonical_hash;

pub(crate) const PROBE_ACTION: &str = "file_access.probe.non_owner.v1";
pub(crate) const OWNER_ACTION: &str = "file_access.verify.owner.v1";
pub(crate) const MAX_REPORT: usize = 16 * 1024;
pub(crate) const REFUSAL: &str = "the enrolled file-access resource or reader is unavailable";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileAccessResource {
    pub root: String,
    pub root_device: u64,
    pub root_inode: u64,
    pub parent_device: u64,
    pub parent_inode: u64,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub sha256: String,
    pub size: u64,
    pub record_count: u64,
    pub acl_digest: String,
    pub parent_acl_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileAccessWorker {
    pub socket_path: String,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub start_ticks: u64,
    pub launch_nonce: String,
    pub namespaces: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileAccessBinding {
    pub schema_version: String,
    pub enrollment_id: String,
    pub enrollment_digest: String,
    pub expires_at_ms: i64,
    pub resource_id: String,
    pub resource_generation: String,
    pub control_revision: u32,
    pub mode: String,
    pub resource: FileAccessResource,
    pub worker: FileAccessWorker,
}

pub(crate) fn deserialize_binding<'de, D>(
    deserializer: D,
) -> Result<Option<FileAccessBinding>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    FileAccessBinding::deserialize(deserializer).map(Some)
}

pub(crate) fn require(condition: bool) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|tail| hex(tail, 64))
}

fn identifier(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|tail| hex(tail, 32))
}

impl FileAccessBinding {
    pub(crate) fn validate(&self) -> Result<(), String> {
        require(
            self.schema_version == "bluefire.file-access-execution.v1"
                && identifier(&self.enrollment_id, "file-enrollment-")
                && identifier(&self.resource_id, "file-resource-")
                && identifier(&self.resource_generation, "file-generation-")
                && digest(&self.enrollment_digest)
                && self.expires_at_ms > 0
                && (1..=i32::MAX as u32).contains(&self.control_revision)
                && matches!(self.mode.as_str(), "0600" | "0640"),
        )?;
        let generation = self
            .resource_generation
            .strip_prefix("file-generation-")
            .ok_or(REFUSAL)?;
        let resource = &self.resource;
        let worker = &self.worker;
        let acl = canonical_hash(
            &json!({"system.posix_acl_access":null,"system.posix_acl_default":null}),
        );
        require(
            resource.root == format!("/run/bluefire-file-access/data/{generation}")
                && resource.root_inode > 0
                && resource.parent_inode > 0
                && resource.inode > 0
                && resource.root_device == resource.parent_device
                && resource.device == resource.root_device
                && resource.owner_uid == 1000
                && resource.group_gid == 1002
                && digest(&resource.sha256)
                && (1..=1_048_576).contains(&resource.size)
                && (1..=100).contains(&resource.record_count)
                && resource.acl_digest == acl
                && resource.parent_acl_digest == acl
                && worker.socket_path
                    == format!("/run/bluefire-file-access/control/{generation}/probe.sock")
                && worker.uid == 1002
                && worker.gid == 1002
                && (2..=i32::MAX as u32).contains(&worker.pid)
                && (1..=i64::MAX as u64).contains(&worker.start_ticks)
                && hex(&worker.launch_nonce, 64)
                && worker.namespaces.len() == 4,
        )?;
        for kind in ["mnt", "net", "pid", "ipc"] {
            let value = worker.namespaces.get(kind).ok_or(REFUSAL)?;
            let number = value
                .strip_prefix(&format!("{kind}:["))
                .and_then(|v| v.strip_suffix(']'))
                .ok_or(REFUSAL)?;
            require(!number.starts_with('0') && number.parse::<u64>().is_ok())?;
        }
        Ok(())
    }
}
