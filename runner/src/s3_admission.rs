//! Fixed S3 admission authenticated by the configured host and reviewed watchdog.
//!
//! The protected host account is trusted. A plan, sealed JSON document, digest,
//! or worker acknowledgement alone cannot construct this authority.

use std::path::Path;

use chrono::{DateTime, FixedOffset};

use crate::s3_access_binding::S3WorkerBinding;

#[cfg(any(target_os = "linux", test))]
#[path = "s3_admission_wire.rs"]
mod wire;

pub const S3_ACTION_ID: &str = "owned.aws.s3_access.v1";
const REFUSAL: &str = "protected S3 admission was refused";
const CONTEXT_ENV: &str = "BLUEFIRE_S3_CONTEXT_FD";
const ENVELOPE_ENV: &str = "BLUEFIRE_S3_ENVELOPE_FD";

/// No public deserializer or unchecked constructor exists for this token.
pub struct VerifiedS3Admission {
    binding: S3WorkerBinding,
    manifest: crate::contract::ExecutionManifest,
    profile: crate::contract::RunnerProfile,
    enrollment_digest: String,
    approval_digest: String,
    workflow_id: String,
    operation_id: String,
    environment_id: String,
    phase: String,
    revision: u64,
    owner_uid: u32,
    ledger_root: String,
    runtime_root: String,
    expires_at: DateTime<FixedOffset>,
    #[cfg(target_os = "linux")]
    credentials: Option<crate::s3_worker_secret::WorkerSecret>,
}

impl VerifiedS3Admission {
    pub fn binding(&self) -> &S3WorkerBinding {
        &self.binding
    }
    pub(crate) fn manifest(&self) -> &crate::contract::ExecutionManifest {
        &self.manifest
    }
    pub(crate) fn profile(&self) -> &crate::contract::RunnerProfile {
        &self.profile
    }
    pub(crate) fn enrollment_digest(&self) -> &str {
        &self.enrollment_digest
    }
    pub(crate) fn approval_digest(&self) -> &str {
        &self.approval_digest
    }
    pub(crate) fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(crate) fn environment_id(&self) -> &str {
        &self.environment_id
    }
    pub(crate) fn phase(&self) -> &str {
        &self.phase
    }
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }
    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
    pub(crate) fn ledger_root(&self) -> &Path {
        Path::new(&self.ledger_root)
    }
    pub(crate) fn runtime_root(&self) -> &Path {
        Path::new(&self.runtime_root)
    }
    pub(crate) fn expires_at(&self) -> DateTime<FixedOffset> {
        self.expires_at
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn take_credentials(&mut self) -> Option<crate::s3_worker_secret::WorkerSecret> {
        self.credentials.take()
    }
}

pub fn verify_inherited_files(
    manifest: &Path,
    profile: &Path,
) -> Result<Option<VerifiedS3Admission>, String> {
    let context = std::env::var_os(CONTEXT_ENV);
    let envelope = std::env::var_os(ENVELOPE_ENV);
    let credentials = std::env::var_os("BLUEFIRE_S3_CREDENTIALS_FD");
    std::env::remove_var(CONTEXT_ENV);
    std::env::remove_var(ENVELOPE_ENV);
    std::env::remove_var("BLUEFIRE_S3_CREDENTIALS_FD");
    if context.is_none() && envelope.is_none() && credentials.is_none() {
        return Ok(None);
    }
    if context.is_none()
        || envelope.is_none()
        || credentials.is_none()
        || context == envelope
        || context == credentials
        || envelope == credentials
    {
        return Err(REFUSAL.into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (manifest, profile, context, envelope, credentials);
        Err(REFUSAL.into())
    }
    #[cfg(target_os = "linux")]
    {
        use crate::protected_launch_channel::{bounded, verify};
        let launch =
            verify(context, envelope, "bluefire.s3-access-launch.v1").map_err(|_| REFUSAL)?;
        let read_document = |path: &Path| -> Result<serde_json::Value, String> {
            let bytes = bounded(path, 1024 * 1024)?;
            let value = serde_json::from_slice(&bytes).map_err(|_| REFUSAL)?;
            let canonical = crate::canonical::canonical_json(&value);
            if bytes.strip_suffix(b"\n").unwrap_or(&bytes) != canonical.as_bytes() {
                return Err(REFUSAL.into());
            }
            Ok(value)
        };
        let manifest = read_document(manifest)?;
        let profile = read_document(profile)?;
        let mut admission = wire::validate(
            &launch.admission,
            &launch.issuer,
            &manifest,
            &profile,
            crate::contract::utc_now().fixed_offset(),
        )?;
        if admission.owner_uid != launch.uid
            || launch.admission["native_runner_digest"] != launch.runner_digest
        {
            return Err(REFUSAL.into());
        }
        use std::os::unix::fs::FileExt;
        let secret =
            crate::protected_launch_channel::sealed(credentials, unsafe { libc::getppid() }
                as u32)?;
        let length = secret.metadata().map_err(|_| REFUSAL)?.len();
        if length > 16 * 1024 {
            return Err(REFUSAL.into());
        }
        let mut bytes = vec![0; length as usize];
        secret.read_exact_at(&mut bytes, 0).map_err(|_| REFUSAL)?;
        admission.credentials = Some(crate::s3_worker_secret::WorkerSecret::from_bytes(
            &bytes,
            launch.admission["credential_digest"]
                .as_str()
                .ok_or(REFUSAL)?,
            crate::contract::utc_now().fixed_offset(),
            admission.binding.deadline()?,
        )?);
        bytes.fill(0);
        launch.recheck().map_err(|_| REFUSAL)?;
        Ok(Some(admission))
    }
}

#[cfg(test)]
#[path = "s3_admission_tests.rs"]
pub(crate) mod tests;
