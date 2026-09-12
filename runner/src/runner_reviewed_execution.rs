//! Finite reviewed identities supplement, and never replace, ordinary runner policy.

use super::*;
use crate::contract::ReviewedOperationIdentity;

const SCHEMA: &str = "bluefire.reviewed-execution.v1";
const MAX_OPERATIONS: usize = 512;

fn binding_hash<T: serde::Serialize>(binding: &T) -> String {
    canonical_hash(&serde_json::to_value(binding).expect("runner binding serialization"))
}

fn validate_identity(operation: &ReviewedOperationIdentity) -> Result<(), ActionFailure> {
    for (field, value) in [
        ("step_id", &operation.step_id),
        ("behavior_id", &operation.behavior_id),
        ("action_id", &operation.action_id),
    ] {
        validate_identifier(field, value)
            .map_err(|error| blocked("invalid_reviewed_execution", error))?;
    }
    if operation.execution_binding_digest.as_deref().is_some_and(|digest| !is_sha256_digest(digest)) {
        return Err(blocked("invalid_reviewed_execution", "reviewed execution binding digest is invalid"));
    }
    Ok(())
}

pub(super) fn validate_profile(profile: &RunnerProfile) -> Result<(), ActionFailure> {
    let Some(authority) = &profile.reviewed_execution else { return Ok(()); };
    if authority.schema_version != SCHEMA || !is_sha256_digest(&authority.authorization_digest)
        || authority.operations.is_empty() || authority.operations.len() > MAX_OPERATIONS
    {
        return Err(blocked("invalid_reviewed_execution", "reviewed execution schema, digest or bounds are invalid"));
    }
    if authority.operations.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(blocked("invalid_reviewed_execution", "reviewed operations must be unique and canonically ordered"));
    }
    let mut required = BTreeSet::new();
    let mut used_bindings = BTreeSet::new();
    for operation in &authority.operations {
        validate_identity(operation)?;
        required.insert(operation.action_id.clone());
        let native = profile.action_bindings.iter().find(|binding| {
            binding.logical_behavior_id == operation.behavior_id && binding.logical_action_id == operation.action_id
        });
        let provider = profile.provider_bindings.iter().find(|binding| {
            binding.logical_behavior_id == operation.behavior_id && binding.logical_action_id == operation.action_id
        });
        let digest = match (native, provider) {
            (Some(binding), None) => {
                required.insert(binding.runner_opcode.clone());
                Some(binding_hash(binding))
            }
            (None, Some(binding)) => Some(binding_hash(binding)),
            (None, None) if find_action(&operation.action_id).is_some() => None,
            _ => return Err(blocked("invalid_reviewed_execution", "reviewed operation has no unique registered execution binding")),
        };
        if digest != operation.execution_binding_digest {
            return Err(blocked("invalid_reviewed_execution", "reviewed operation binding differs from the profile"));
        }
        if let Some(digest) = digest { used_bindings.insert(digest); }
    }
    if profile.action_bindings.iter().any(|binding| !used_bindings.contains(&binding_hash(binding)))
        || profile.provider_bindings.iter().any(|binding| !used_bindings.contains(&binding_hash(binding)))
    {
        return Err(blocked("invalid_reviewed_execution", "profile includes an unreviewed execution binding"));
    }
    if profile.allowed_actions.iter().cloned().collect::<BTreeSet<_>>() != required
        || profile.control_blocked_actions.iter().any(|action| required.contains(action))
    {
        return Err(blocked("invalid_reviewed_execution", "allowed actions must exactly cover reviewed operations without blocked actions"));
    }
    Ok(())
}

pub(super) fn validate_manifest(manifest: &ExecutionManifest, profile: &RunnerProfile) -> Result<(), ActionFailure> {
    let (authority, selected) = match (&profile.reviewed_execution, &manifest.reviewed_operation) {
        (None, None) => return Ok(()),
        (Some(authority), Some(selected)) => (authority, selected),
        _ => return Err(blocked("reviewed_operation_blocked", "reviewed operation is required only with reviewed execution authority")),
    };
    let digest = match (&manifest.execution_binding, &manifest.provider_binding) {
        (Some(binding), None) => Some(binding_hash(binding)),
        (None, Some(binding)) => Some(binding_hash(binding)),
        (None, None) => None,
        _ => return Err(blocked("reviewed_operation_blocked", "manifest has competing execution bindings")),
    };
    let identity = ReviewedOperationIdentity {
        step_id: manifest.step_id.clone(), behavior_id: manifest.behavior_id.clone(),
        action_id: manifest.action_id.clone(), execution_binding_digest: digest,
    };
    if selected.authorization_digest != authority.authorization_digest
        || selected.step_id != identity.step_id || selected.behavior_id != identity.behavior_id
        || selected.action_id != identity.action_id || selected.execution_binding_digest != identity.execution_binding_digest
        || !authority.operations.contains(&identity)
    {
        return Err(blocked("reviewed_operation_blocked", "manifest operation is outside reviewed execution authority"));
    }
    Ok(())
}
