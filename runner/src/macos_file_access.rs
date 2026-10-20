//! Fixed Darwin primitives. Wire documents do not adopt creator/child custody.

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
use sha2::{Digest, Sha256};

use crate::canonical::canonical_hash;

pub const MAX_MESSAGE: usize = 16 * 1024;
pub const MAX_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS: u32 = 64;
pub const MAX_OPERATION_NS: u64 = 5_000_000_000;
pub const LEAF: &str = "records.jsonl";
pub const MONOTONIC_CLOCK: &str = "darwin-mach-absolute-ns";
pub(crate) const REFUSAL: &str = "the fixed Darwin primitive is unavailable";

fn require(condition: bool) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|tail| hex(tail, 64))
}

fn identifier(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|tail| hex(tail, 32))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub groups: Vec<u32>,
}

impl Credentials {
    pub(crate) fn validate(&self) -> Result<(), String> {
        require(
            self.real_uid > 0
                && self.real_uid < u32::MAX
                && self.real_uid == self.effective_uid
                && self.real_uid == self.saved_uid
                && self.real_gid > 0
                && self.real_gid < u32::MAX
                && self.real_gid == self.effective_gid
                && self.real_gid == self.saved_gid
                && !self.groups.is_empty()
                && self.groups.len() <= 64
                && self.groups.iter().all(|gid| *gid > 0 && *gid < u32::MAX)
                && self.groups.windows(2).all(|pair| pair[0] < pair[1])
                && self.groups.contains(&self.effective_gid),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub mode: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub size_bytes: u64,
    pub record_count: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub schema_version: String,
    pub enrollment_id: String,
    pub generation: String,
    pub custody_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub original_deadline_ns: u64,
    pub owner: Credentials,
    pub reader: Credentials,
    pub directory: Directory,
    pub resource: Resource,
    pub control_revision: u32,
    pub mode: String,
}

impl Binding {
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.owner.validate()?;
        self.reader.validate()?;
        require(
            self.schema_version == "bluefire.macos-file-access-binding.v1"
                && identifier(&self.enrollment_id, "file-enrollment-")
                && identifier(&self.generation, "file-generation-")
                && digest(&self.custody_digest)
                && self.issued_at_ms > 0
                && self.expires_at_ms <= i64::MAX as u64
                && self.expires_at_ms > self.issued_at_ms
                && self.expires_at_ms - self.issued_at_ms <= 900_000
                && self.original_deadline_ns > 0
                && (1..=i32::MAX as u32).contains(&self.control_revision)
                && matches!(self.mode.as_str(), "0640" | "0600")
                && self.owner.effective_uid != self.reader.effective_uid,
        )?;
        let directory = &self.directory;
        let resource = &self.resource;
        require(
            directory.owner_uid == 0
                && directory.inode > 0
                && directory.mode == "0550"
                && self.owner.groups.contains(&directory.group_gid)
                && self.reader.groups.contains(&directory.group_gid)
                && resource.device == directory.device
                && resource.inode > 0
                && resource.inode != directory.inode
                && resource.owner_uid == self.owner.effective_uid
                && self.reader.groups.contains(&resource.group_gid)
                && (1..=MAX_BYTES as u64).contains(&resource.size_bytes)
                && resource.record_count == 8
                && digest(&resource.sha256),
        )
    }

    #[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
    fn anchor(&self) -> Result<String, String> {
        let mut value = serde_json::to_value(self).map_err(|_| REFUSAL)?;
        let fields = value.as_object_mut().ok_or(REFUSAL)?;
        fields.remove("mode");
        fields.remove("control_revision");
        Ok(canonical_hash(&value))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: String,
    pub binding: Binding,
    pub binding_digest: String,
    pub request_id: String,
    pub sequence: u32,
    pub operation: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub issued_monotonic_ns: u64,
    pub deadline_ns: u64,
}

impl Request {
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.binding.validate()?;
        require(
            self.schema_version == "bluefire.macos-file-access-request.v1"
                && self.binding_digest
                    == canonical_hash(&serde_json::to_value(&self.binding).map_err(|_| REFUSAL)?)
                && hex(&self.request_id, 64)
                && (1..=MAX_REQUESTS).contains(&self.sequence)
                && matches!(
                    self.operation.as_str(),
                    "read_reader" | "read_owner" | "harden" | "rollback" | "close"
                )
                && self.issued_at_ms >= self.binding.issued_at_ms
                && self.expires_at_ms > self.issued_at_ms
                && self.expires_at_ms <= self.binding.expires_at_ms
                && self.expires_at_ms - self.issued_at_ms <= 5000
                && self.issued_monotonic_ns > 0
                && self.deadline_ns > self.issued_monotonic_ns
                && self.deadline_ns <= self.binding.original_deadline_ns
                && self.deadline_ns - self.issued_monotonic_ns <= MAX_OPERATION_NS,
        )
    }
}

pub fn decode_request(raw: &[u8]) -> Result<Request, String> {
    require(!raw.is_empty() && raw.len() <= MAX_MESSAGE)?;
    let request: Request = serde_json::from_slice(raw).map_err(|_| REFUSAL)?;
    request.validate()?;
    Ok(request)
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) struct Facts {
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub mode: String,
    pub size: u64,
    pub links: u64,
    pub modified_ns: i128,
    pub changed_ns: i128,
}

#[derive(Clone, Copy)]
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) struct Clock {
    pub wall_ms: u64,
    pub monotonic_ns: u64,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) enum OpenFailure {
    Denied,
    Unknown,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) trait Backend {
    fn clock(&mut self) -> Result<Clock, ()>;
    fn principal(&mut self) -> Result<Credentials, ()>;
    fn directory(&mut self) -> Result<Directory, ()>;
    fn open_leaf(&mut self) -> Result<i32, OpenFailure>;
    fn facts(&mut self, handle: i32) -> Result<Facts, ()>;
    fn read(&mut self, handle: i32, maximum: usize, deadline_ns: u64) -> Result<Vec<u8>, ()>;
    fn close_read(&mut self, handle: i32) -> Result<(), ()>;
    fn held_leaf(&mut self) -> Result<i32, ()>;
    fn set_mode(&mut self, handle: i32, mode: &str) -> Result<(), ()>;
    fn close_held(&mut self) -> Result<(), ()>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Entry {
    Reader,
    OwnerControl,
}

#[derive(Debug, Serialize)]
#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub struct Observation {
    pub schema_version: &'static str,
    pub binding_digest: String,
    pub request_id: String,
    pub sequence: u32,
    pub operation: String,
    pub outcome: &'static str,
    pub principal: Option<Credentials>,
    pub fresh_read: Option<Value>,
    pub held_control: Option<Value>,
    pub request_handle_cleanup: &'static str,
    pub held_handle_cleanup: &'static str,
    pub custody: &'static str,
    pub prevention_proven: bool,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
impl Observation {
    fn new(request: &Request) -> Self {
        Self {
            schema_version: "bluefire.macos-file-access-observation.v1",
            binding_digest: request.binding_digest.clone(),
            request_id: request.request_id.clone(),
            sequence: request.sequence,
            operation: request.operation.clone(),
            outcome: "refused",
            principal: None,
            fresh_read: None,
            held_control: None,
            request_handle_cleanup: "not_opened",
            held_handle_cleanup: "retained",
            custody: "requires_original_creator_evidence",
            prevention_proven: false,
        }
    }
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) struct Session {
    anchor: Option<String>,
    last_sequence: u32,
    last_revision: u32,
    requests: BTreeSet<String>,
    last_clock: Option<Clock>,
    pub(crate) poisoned: bool,
    pub(crate) closed: bool,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
impl Session {
    pub(crate) fn new() -> Self {
        Self {
            anchor: None,
            last_sequence: 0,
            last_revision: 0,
            requests: BTreeSet::new(),
            last_clock: None,
            poisoned: false,
            closed: false,
        }
    }

    fn current(&mut self, backend: &mut impl Backend, request: &Request) -> Result<(), ()> {
        let now = backend.clock()?;
        if now.wall_ms < request.issued_at_ms
            || now.wall_ms >= request.expires_at_ms
            || now.monotonic_ns < request.issued_monotonic_ns
            || now.monotonic_ns >= request.deadline_ns
            || self.last_clock.is_some_and(|last| {
                now.wall_ms < last.wall_ms || now.monotonic_ns < last.monotonic_ns
            })
        {
            return Err(());
        }
        self.last_clock = Some(now);
        Ok(())
    }

    fn consume(&mut self, request: &Request) -> Result<(), String> {
        request.validate()?;
        let anchor = request.binding.anchor()?;
        require(
            !self.closed
                && request.sequence == self.last_sequence + 1
                && request.binding.control_revision >= self.last_revision
                && self.anchor.as_ref().is_none_or(|prior| prior == &anchor)
                && !self.requests.contains(&request.request_id),
        )?;
        self.anchor = Some(anchor);
        self.last_sequence = request.sequence;
        self.last_revision = request.binding.control_revision;
        self.requests.insert(request.request_id.clone());
        Ok(())
    }

    pub(crate) fn execute(
        &mut self,
        backend: &mut impl Backend,
        entry: Entry,
        request: &Request,
    ) -> Observation {
        let mut result = Observation::new(request);
        if self.consume(request).is_err() {
            return result;
        }
        if request.operation == "close" {
            self.closed = true;
            if backend.close_held().is_ok() {
                result.outcome = "closed";
                result.held_handle_cleanup = "closed";
            } else {
                result.outcome = "unknown";
                result.held_handle_cleanup = "unknown";
            }
            return result;
        }
        if self.poisoned || self.current(backend, request).is_err() {
            return result;
        }
        let read = matches!(request.operation.as_str(), "read_reader" | "read_owner");
        if (entry == Entry::Reader) != read {
            return result;
        }
        let expected = if request.operation == "read_reader" {
            &request.binding.reader
        } else {
            &request.binding.owner
        };
        let Ok(principal) = backend.principal() else {
            return result;
        };
        if principal != *expected || principal.validate().is_err() {
            return result;
        }
        result.principal = Some(principal);
        if read {
            self.read(backend, request, &mut result);
        } else {
            self.control(backend, request, &mut result);
        }
        if result.outcome == "unknown" {
            self.poisoned = true;
        }
        result
    }

    fn read(&mut self, backend: &mut impl Backend, request: &Request, result: &mut Observation) {
        let Ok(directory) = backend.directory() else {
            return;
        };
        if directory != request.binding.directory || self.current(backend, request).is_err() {
            return;
        }
        match backend.open_leaf() {
            Err(OpenFailure::Denied) => {
                result.outcome = if backend.directory().is_ok_and(|actual| actual == directory)
                    && self.current(backend, request).is_ok()
                {
                    "denied"
                } else {
                    "unknown"
                };
            }
            Err(OpenFailure::Unknown) => result.outcome = "unknown",
            Ok(handle) => {
                result.outcome = "unknown";
                let proof = (|| {
                    self.current(backend, request)?;
                    let before = backend.facts(handle)?;
                    match_resource(&before, &request.binding, &request.binding.mode)?;
                    let bytes = backend.read(handle, MAX_BYTES + 1, request.deadline_ns)?;
                    verify_bytes(&bytes, &request.binding.resource)?;
                    let after = backend.facts(handle)?;
                    let expected = if request.operation == "read_reader" {
                        &request.binding.reader
                    } else {
                        &request.binding.owner
                    };
                    if before != after
                        || backend.directory()? != directory
                        || backend.principal()? != *expected
                    {
                        return Err(());
                    }
                    self.current(backend, request)?;
                    Ok(
                        json!({"device": after.device, "inode": after.inode, "mode": after.mode,
                        "size_bytes": bytes.len(), "record_count": 8, "sha256": request.binding.resource.sha256}),
                    )
                })();
                result.request_handle_cleanup = if backend.close_read(handle).is_ok() {
                    "closed"
                } else {
                    "unknown"
                };
                if let Ok(proof) = proof {
                    if result.request_handle_cleanup == "closed"
                        && self.current(backend, request).is_ok()
                    {
                        result.fresh_read = Some(proof);
                        result.outcome = "allowed";
                    }
                }
            }
        }
    }

    fn control(&mut self, backend: &mut impl Backend, request: &Request, result: &mut Observation) {
        let target = if request.operation == "harden" {
            "0600"
        } else {
            "0640"
        };
        if request.binding.mode == target {
            return;
        }
        let preimage = (|| {
            let handle = backend.held_leaf()?;
            let before = backend.facts(handle)?;
            match_resource(&before, &request.binding, &request.binding.mode)?;
            let bytes = backend.read(handle, MAX_BYTES + 1, request.deadline_ns)?;
            verify_bytes(&bytes, &request.binding.resource)?;
            if backend.facts(handle)? != before {
                return Err(());
            }
            if backend.principal()? != request.binding.owner {
                return Err(());
            }
            self.current(backend, request)?;
            Ok((handle, before))
        })();
        let Ok((handle, before)) = preimage else {
            return;
        };
        result.outcome = "unknown";
        // No metadata callbacks or renewed interval between final guard and setter.
        if backend.set_mode(handle, target).is_err() {
            return;
        }
        let proof = (|| {
            self.current(backend, request)?;
            let after = backend.facts(handle)?;
            match_resource(&after, &request.binding, target)?;
            let bytes = backend.read(handle, MAX_BYTES + 1, request.deadline_ns)?;
            verify_bytes(&bytes, &request.binding.resource)?;
            if backend.facts(handle)? != after || backend.principal()? != request.binding.owner {
                return Err(());
            }
            self.current(backend, request)?;
            Ok(
                json!({"device": after.device, "inode": after.inode, "before_mode": before.mode,
                "after_mode": after.mode, "size_bytes": bytes.len(), "record_count": 8,
                "sha256": request.binding.resource.sha256}),
            )
        })();
        if let Ok(proof) = proof {
            result.outcome = "mode_changed";
            result.held_control = Some(proof);
        }
    }
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
fn match_resource(facts: &Facts, binding: &Binding, mode: &str) -> Result<(), ()> {
    let expected = &binding.resource;
    if facts.device == expected.device
        && facts.inode == expected.inode
        && facts.owner_uid == expected.owner_uid
        && facts.group_gid == expected.group_gid
        && facts.size == expected.size_bytes
        && facts.links == 1
        && facts.mode == mode
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
fn verify_bytes(bytes: &[u8], resource: &Resource) -> Result<(), ()> {
    if bytes.len() != resource.size_bytes as usize
        || bytes.len() > MAX_BYTES
        || format!("sha256:{}", hex::encode(Sha256::digest(bytes))) != resource.sha256
        || !bytes.ends_with(b"\n")
    {
        return Err(());
    }
    let lines = bytes[..bytes.len() - 1]
        .split(|b| *b == b'\n')
        .collect::<Vec<_>>();
    if lines.len() != 8
        || lines
            .iter()
            .any(|line| !serde_json::from_slice::<Value>(line).is_ok_and(|row| row.is_object()))
    {
        return Err(());
    }
    Ok(())
}

#[path = "macos_file_access_native.rs"]
mod native;

fn capability_document(native_available: bool) -> Value {
    json!({"schema_version": "bluefire.macos-file-access-capability.v1", "protocol_supported": true,
        "native_backend_available": native_available, "live_ready": false,
        "scope": "protocol_support_only", "max_bytes": MAX_BYTES, "max_message": MAX_MESSAGE,
        "max_requests": MAX_REQUESTS, "max_operation_ns": MAX_OPERATION_NS,
        "monotonic_clock": MONOTONIC_CLOCK})
}

pub fn capability() -> Value {
    capability_document(native::available())
}

pub fn run_reader(args: &[String]) -> Result<i32, String> {
    native::run(args, Entry::Reader)
}
pub fn run_owner_control(args: &[String]) -> Result<i32, String> {
    native::run(args, Entry::OwnerControl)
}

#[cfg(test)]
#[path = "macos_file_access_tests.rs"]
mod tests;
