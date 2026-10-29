//! Fixed owned-loopback SFTP consumer, deliberately unregistered and unavailable.
//!
//! There is no production admission constructor: ActionContext does not prove
//! current server/resource/session facts. A future authenticated resolver must
//! construct the private admission after independently resolving those facts.
//! The compiled build table is also empty until exact bundle/lab review exists.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::contract::{sha256_hex, ReviewedOperationIdentity};
use crate::native_tool_installations::{NativeToolBinding, NativeToolInstallation};

#[cfg(target_os = "linux")]
#[path = "owned_sftp_process.rs"]
mod process;

pub(crate) const METHOD: &str = "endpoint.collection.openssh-sftp.v1";
const CONTRACT: &str = "sha256:0ff208bf53098c353a017a93301b3b89b62992c402b8c9b5493656d51a1c2093";
pub(crate) const MAX_BYTES: usize = 1_048_576;
pub(crate) const MAX_DIAGNOSTIC: usize = 8192;
const CLEANUP_RESERVE: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentReferences {
    pub endpoint_binding_ref: String,
    pub server_preparation_ref: String,
    pub resource_ref: String,
    pub resource_generation: String,
    pub source_content_sha256: String,
    pub host_key_ref: String,
    pub reader_identity_ref: String,
    pub access_observation_ref: String,
    pub session_prerequisite_ref: String,
}

impl CurrentReferences {
    fn validate(&self) -> Result<(), Issue> {
        let value = serde_json::to_value(self).map_err(|_| Issue::Prerequisite)?;
        if value.as_object().is_none_or(|rows| {
            rows.values()
                .any(|value| value.as_str().is_none_or(|value| !digest(value)))
        }) {
            return Err(Issue::Prerequisite);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub references: CurrentReferences,
    pub bundle_digest: String,
    pub expected_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issue {
    AdmissionUnresolved,
    Prerequisite,
    UnreviewedBuild,
    Installation,
    Cancelled,
    Deadline,
    Spawn,
    Io,
    OutputLimit,
    ProcessIdentity,
    CleanupUnknown,
    ProtocolFailure,
    ContentMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleanup {
    NotStarted,
    ReapedClientGroupAbsent,
    Unknown,
}

pub(crate) struct Retrieval {
    pub bytes: Vec<u8>,
    pub issue: Option<Issue>,
    pub cleanup: Cleanup,
    pub executed: bool,
    pub exit_code: Option<i32>,
    pub diagnostics_bytes: usize,
}

/// Exact identities will be populated only by a separate build and lab review.
/// These are not caller-provided admission records. No synthetic hash is listed.
struct ReviewedBundle {
    digest: &'static str,
    client_digest: &'static str,
    transport_digest: &'static str,
}
const REVIEWED_BUNDLES: &[ReviewedBundle] = &[];

/// Separate compiler-owned observer readiness lease. No production constructor,
/// wire parser, caller boolean, signature invention or metadata-to-lease factory
/// exists here. An authenticated observer issuer must establish this lease after
/// starting the correct owned observation, and bind its lifetime to this session.
struct ObserverReadinessLease {
    admission_ref: String,
    readiness_ref: String,
    session_ref: String,
    scope_digest: String,
    bundle_digest: String,
    ready_at: Instant,
    expires_at: Instant,
}

impl ObserverReadinessLease {
    fn check(
        &self,
        references: &CurrentReferences,
        operation_deadline: Instant,
        bundle_digest: &str,
    ) -> Result<(), Issue> {
        let now = Instant::now();
        let scope = crate::canonical::canonical_hash(
            &serde_json::to_value(references).map_err(|_| Issue::Prerequisite)?,
        );
        if !digest(&self.admission_ref)
            || !digest(&self.readiness_ref)
            || self.session_ref != references.session_prerequisite_ref
            || self.scope_digest != scope
            || self.bundle_digest != bundle_digest
            || self.ready_at > now
            || self.expires_at <= now
            || self.expires_at < operation_deadline
        {
            return Err(Issue::Prerequisite);
        }
        Ok(())
    }
}

/// Compiler-owned capability with a private constructor and no Deserialize.
/// No production code currently constructs it. Metadata parsing, reference
/// equality, and an ActionContext are explicitly insufficient to mint it.
/// The missing resolver must bind these private values to current authenticated
/// server-preparation, endpoint, host-key, owner/reader, generation and new-session
/// evidence, plus separately admitted observer readiness for the selected proof.
pub struct VerifiedSftpAdmission {
    references: CurrentReferences,
    bundle_digest: String,
    operation: ReviewedOperationIdentity,
    authorization_digest: String,
    request_hash: String,
    runner_profile_id: String,
    workspace_id: String,
    remote_path: String,
    expected_size: u64,
    port: u16,
    reader: String,
    host_ed25519: [u8; 32],
    fixture_private_key: Vec<u8>,
    installations: [NativeToolInstallation; 2],
    deadline: Instant,
    observer_readiness: ObserverReadinessLease,
}

impl Drop for VerifiedSftpAdmission {
    fn drop(&mut self) {
        // Best effort only, not a guarantee that allocator/OS copies are erased.
        self.fixture_private_key.fill(0);
    }
}

impl VerifiedSftpAdmission {
    #[cfg(test)]
    pub(crate) fn authored_fixture(path: &str) -> Self {
        tests::fixture(path)
    }
    pub(crate) fn check_request(&self, request: &Request) -> Result<(), Issue> {
        self.references.validate()?;
        request.references.validate()?;
        self.observer_readiness
            .check(&self.references, self.deadline, &self.bundle_digest)?;
        if request.references != self.references
            || request.bundle_digest != self.bundle_digest
            || !owned_remote_path(&self.remote_path)
            || request.expected_size != self.expected_size
            || !digest(&self.bundle_digest)
            || self.expected_size == 0
            || self.expected_size > MAX_BYTES as u64
            || self.port < 1024
            || !reader_name(&self.reader)
            || !(128..=4096).contains(&self.fixture_private_key.len())
            || !self
                .fixture_private_key
                .starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----\n") // pragma: allowlist secret -- public format sentinel, no key material
            || !self
                .fixture_private_key
                .ends_with(b"-----END OPENSSH PRIVATE KEY-----\n")
        {
            return Err(Issue::Prerequisite);
        }
        Ok(())
    }

    pub(crate) fn check_operation(
        &self,
        selected: &ReviewedOperationIdentity,
        authorization_digest: &str,
    ) -> Result<(), Issue> {
        if selected != &self.operation || authorization_digest != self.authorization_digest {
            return Err(Issue::AdmissionUnresolved);
        }
        Ok(())
    }

    pub(crate) fn check_scope(
        &self,
        request_hash: &str,
        profile_id: &str,
        workspace_id: &str,
    ) -> Result<(), Issue> {
        if self.request_hash != request_hash
            || self.runner_profile_id != profile_id
            || self.workspace_id != workspace_id
        {
            return Err(Issue::AdmissionUnresolved);
        }
        Ok(())
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    fn recognize_build(&self) -> Result<(), Issue> {
        for (record, tool) in self
            .installations
            .iter()
            .zip(["openssh.sftp.v1", "openssh.ssh.v1"])
        {
            NativeToolBinding {
                adapter_id: METHOD,
                adapter_version: "0.1.0",
                adapter_contract_digest: CONTRACT,
                tool_id: tool,
            }
            .check_binding(record, "linux", std::env::consts::ARCH)
            .map_err(|_| Issue::Installation)?;
            if record.tool_version != "10.6p1" {
                return Err(Issue::UnreviewedBuild);
            }
        }
        if !REVIEWED_BUNDLES.iter().any(|build| {
            build.digest == self.bundle_digest
                && build.client_digest == self.installations[0].digest()
                && build.transport_digest == self.installations[1].digest()
        }) {
            return Err(Issue::UnreviewedBuild);
        }
        Ok(())
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn reader_name(value: &str) -> bool {
    value.strip_prefix("bfreader_").is_some_and(|suffix| {
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

// Only the missing authenticated server-resource resolver may populate this
// private path. The request contains its resource reference/generation, never
// the path. A get has no globbing, quoting, option or traversal syntax.
fn owned_remote_path(value: &str) -> bool {
    value.len() <= 512
        && value.starts_with("/owned/")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            output.push(if index > chunk.len() {
                '='
            } else {
                ALPHABET[((bits >> (18 - 6 * index)) & 63) as usize] as char
            });
        }
    }
    output
}

fn known_host(admission: &VerifiedSftpAdmission) -> Vec<u8> {
    let mut blob = Vec::from(&b"\0\0\0\x0bssh-ed25519\0\0\0\x20"[..]);
    blob.extend_from_slice(&admission.host_ed25519);
    format!(
        "[127.0.0.1]:{} ssh-ed25519 {}\n",
        admission.port,
        base64(&blob)
    )
    .into_bytes()
}

pub(crate) fn verify_bytes(admission: &VerifiedSftpAdmission, bytes: &[u8]) -> Result<(), Issue> {
    if bytes.len() as u64 != admission.expected_size
        || format!("sha256:{}", sha256_hex(bytes)) != admission.references.source_content_sha256
    {
        return Err(Issue::ContentMismatch);
    }
    Ok(())
}

pub(crate) fn check_execution_admission(
    admission: &VerifiedSftpAdmission,
    request: &Request,
    cancelled: &AtomicBool,
) -> Result<(), Issue> {
    if cancelled.load(Ordering::Acquire) {
        return Err(Issue::Cancelled);
    }
    admission.check_request(request)?;
    admission.recognize_build()?;
    if Instant::now() + CLEANUP_RESERVE >= admission.deadline {
        return Err(Issue::Deadline);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Issue::Installation)
    }
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
}

pub(crate) fn retrieve(
    admission: &VerifiedSftpAdmission,
    request: &Request,
    cancelled: &AtomicBool,
) -> Result<Retrieval, Issue> {
    check_execution_admission(admission, request, cancelled)?;
    #[cfg(target_os = "linux")]
    {
        process::retrieve(admission, cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Issue::Installation)
    }
}

#[cfg(test)]
#[path = "owned_sftp_tests.rs"]
mod tests;
