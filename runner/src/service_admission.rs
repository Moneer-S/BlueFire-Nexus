//! Protected host/watchdog admission, separate from self-authored task JSON.
//!
//! The configured local host account is a trust anchor. Its enrollment-derived
//! secret context travels separately from the authenticated admission document.
//! This boundary does not defend against that account replacing the host or
//! watchdog. Neither a JSON digest nor an arbitrary sealed document is authority.

use std::path::Path;

use chrono::{DateTime, FixedOffset};
#[cfg(target_os = "linux")]
use serde_json::Value;

use crate::service_operation_binding::ServiceOperationBinding;

#[cfg(target_os = "linux")]
#[path = "service_admission_channel.rs"]
mod channel;
#[cfg(any(target_os = "linux", test))]
#[path = "service_admission_wire.rs"]
mod wire;

pub const SERVICE_ACTION_ID: &str = "owned.user_service.fixed_wait.v1";
const CONTEXT_ENV: &str = "BLUEFIRE_SERVICE_CONTEXT_FD";
const ENVELOPE_ENV: &str = "BLUEFIRE_SERVICE_ENVELOPE_FD";
const REFUSAL: &str = "protected owned-service admission was refused";

/// Only the protected launch path constructs this value in production.
pub struct VerifiedServiceAdmission {
    scope_digest: String,
    grant_digest: String,
    task_id: String,
    enrollment_digest: String,
    runner_profile_id: String,
    target_scope_digest: String,
    workspace_id: String,
    owner_uid: u32,
    boot_id: String,
    manager_id: String,
    unit_nonce: String,
    unit_content_digest: String,
    manager_installation_digest: String,
    payload_installation_digest: String,
    operation_binding_digest: String,
    operation_binding: Option<ServiceOperationBinding>,
    created_at: DateTime<FixedOffset>,
    setup_expires_at: DateTime<FixedOffset>,
    cleanup_expires_at: DateTime<FixedOffset>,
    #[cfg(target_os = "linux")]
    scope: Value,
    #[cfg(target_os = "linux")]
    installations: Vec<crate::native_tool_inspection::InspectedNativeTool>,
}

macro_rules! string_getters {
    ($($field:ident),+ $(,)?) => {$(
        pub fn $field(&self) -> &str { &self.$field }
    )+};
}

impl VerifiedServiceAdmission {
    #[cfg(target_os = "linux")]
    pub(crate) fn observation_manager(
        &self,
    ) -> Option<&crate::native_tool_inspection::InspectedNativeTool> {
        let [manager, payload] = self.installations.as_slice() else {
            return None;
        };
        (manager.installation_digest == self.manager_installation_digest
            && payload.installation_digest == self.payload_installation_digest
            && crate::service_installations::is_reviewed_manager(manager)
            && self.operation_binding.as_ref().is_some_and(|binding| {
                binding.digest() == self.operation_binding_digest
            }))
        .then_some(manager)
    }

    string_getters!(
        scope_digest,
        grant_digest,
        task_id,
        enrollment_digest,
        runner_profile_id,
        target_scope_digest,
        workspace_id,
        boot_id,
        manager_id,
        unit_nonce,
        unit_content_digest,
        manager_installation_digest,
        payload_installation_digest,
        operation_binding_digest,
    );
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
    pub fn created_at(&self) -> DateTime<FixedOffset> {
        self.created_at
    }
    pub fn setup_expires_at(&self) -> DateTime<FixedOffset> {
        self.setup_expires_at
    }
    pub fn cleanup_expires_at(&self) -> DateTime<FixedOffset> {
        self.cleanup_expires_at
    }
    pub fn operation_binding(&self) -> &ServiceOperationBinding {
        self.operation_binding
            .as_ref()
            .expect("production admission has a validated binding")
    }
}

/// Real CLI boundary. Legacy invocations without a service channel are unchanged.
/// A verified service request still cannot dispatch an unregistered adapter.
pub fn verify_inherited_files(
    manifest: &Path,
    profile: &Path,
) -> Result<Option<VerifiedServiceAdmission>, String> {
    let context = std::env::var_os(CONTEXT_ENV);
    let envelope = std::env::var_os(ENVELOPE_ENV);
    std::env::remove_var(CONTEXT_ENV);
    std::env::remove_var(ENVELOPE_ENV);
    if context.is_none() && envelope.is_none() {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    {
        channel::verify(context, envelope, manifest, profile).map(Some)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (manifest, profile, context, envelope);
        Err(REFUSAL.into())
    }
}

#[cfg(test)]
pub(crate) fn reservation_test_admission(
    owner_uid: u32,
    task_id: &str,
    operation_binding_digest: &str,
) -> VerifiedServiceAdmission {
    use crate::canonical::canonical_hash;
    use serde_json::json;
    VerifiedServiceAdmission {
        scope_digest: format!("sha256:{}", "1".repeat(64)),
        grant_digest: canonical_hash(&json!([task_id, operation_binding_digest])),
        task_id: task_id.into(),
        enrollment_digest: format!("sha256:{}", "2".repeat(64)),
        runner_profile_id: "service-lab".into(),
        target_scope_digest: format!("sha256:{}", "3".repeat(64)),
        workspace_id: "service-workspace".into(),
        owner_uid,
        boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        manager_id: "4".repeat(32),
        unit_nonce: "5".repeat(32),
        unit_content_digest: format!("sha256:{}", "6".repeat(64)),
        manager_installation_digest: format!("sha256:{}", "7".repeat(64)),
        payload_installation_digest: format!("sha256:{}", "8".repeat(64)),
        operation_binding_digest: operation_binding_digest.into(),
        operation_binding: None,
        created_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap(),
        setup_expires_at: DateTime::parse_from_rfc3339("2026-01-01T00:05:00Z").unwrap(),
        cleanup_expires_at: DateTime::parse_from_rfc3339("2026-01-01T01:00:00Z").unwrap(),
        #[cfg(target_os = "linux")]
        scope: Value::Null,
        #[cfg(target_os = "linux")]
        installations: Vec::new(),
    }
}

#[cfg(test)]
#[path = "service_admission_tests.rs"]
mod tests;
