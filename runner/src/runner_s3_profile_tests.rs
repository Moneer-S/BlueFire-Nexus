//! Reserved cloud metadata coexists with ordinary actions without granting dispatch.

use super::*;

#[test]
fn mixed_profile_recognizes_only_exact_reserved_cloud_metadata() {
    let binding = alias_binding(
        "acme.profile.v1",
        "acme.profile-action.v1",
        "endpoint.discovery.system.v1",
    );
    let (mut profile, mut manifest) = alias_documents(Path::new("."), binding, json!({}));
    profile
        .allowed_actions
        .push(crate::s3_admission::S3_ACTION_ID.into());
    reseal_documents(&mut profile, &mut manifest);
    assert!(validate_profile(&profile).is_ok());
    for alias in [false, true] {
        let mut request = manifest.clone();
        if alias {
            request.execution_binding.as_mut().unwrap().runner_opcode =
                crate::s3_admission::S3_ACTION_ID.into();
        } else {
            request.action_id = crate::s3_admission::S3_ACTION_ID.into();
            request.execution_binding = None;
        }
        crate::contract::seal_manifest(&mut request);
        let result = Runner::new().unwrap().execute(request, profile.clone());
        assert_eq!(result.status, TaskStatus::Refused);
        assert_eq!(result.error.unwrap().code, "s3_admission_required");
        assert!(result.receipt_ids.is_empty() && result.cleanup.is_none());
    }
    profile.allowed_actions.push("owned.aws.other.v1".into());
    crate::contract::seal_profile(&mut profile);
    assert_eq!(
        validate_profile(&profile).unwrap_err().code,
        "invalid_profile"
    );
}

#[test]
fn reserved_cloud_profile_name_cannot_be_shadowed_by_a_provider() {
    let artifact = provider_module(&provider_output("artifact.acme.provider-result.v1", 7), "");
    let mut binding = provider_binding(&artifact);
    binding.logical_action_id = crate::s3_admission::S3_ACTION_ID.into();
    binding.action_contract_digest = provider_action_contract_digest(&binding);
    binding.runtime_contract_digest = runtime_action_contract_digest(&binding);
    binding.program_digest = provider_program_digest(&binding);
    let (profile, _) = provider_documents(&artifact, binding);
    let error = validate_profile(&profile).unwrap_err();
    assert_eq!(error.code, "invalid_profile");
    assert_eq!(
        error.message,
        "provider binding cannot shadow a registered action"
    );
}
