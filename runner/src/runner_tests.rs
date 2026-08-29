use super::*;
use crate::contract::{
    canonical_json, ProviderActionLimits, ProviderArtifact, ProviderArtifactSpec,
    ProviderParameterSpec, ProviderParameterType, PROVIDER_EXECUTION_BINDING_SCHEMA_VERSION,
};
use crate::provider_action::{
    provider_action_contract_digest, provider_program_digest, runtime_action_contract_digest,
    PROVIDER_ACTION_OUTPUT_SCHEMA_VERSION,
};
use crate::providers::{
    provider_artifact_digest, provider_runtime_contract_digest, PROVIDER_ABI_V1,
    PROVIDER_ENTRYPOINT_V1, PROVIDER_MEMORY_EXPORT,
};

const PROVIDER_OUTPUT_OFFSET: u64 = 4096;

fn test_limits() -> ExecutionLimits {
    ExecutionLimits {
        timeout_ms: 5_000,
        max_stdout_bytes: 8 * 1024,
        max_stderr_bytes: 8 * 1024,
        max_artifact_bytes: 1024 * 1024,
        max_files: 32,
    }
}

fn bytes_literal(value: &[u8]) -> String {
    value.iter().map(|byte| format!("\\{byte:02x}")).collect()
}

fn provider_module(output: &Value, body: &str) -> Vec<u8> {
    let output = canonical_json(output).into_bytes();
    let packed = (PROVIDER_OUTPUT_OFFSET << 32) | output.len() as u64;
    wat::parse_str(format!(
        r#"(module
                (memory (export "{PROVIDER_MEMORY_EXPORT}") 1 8)
                (data (i32.const {PROVIDER_OUTPUT_OFFSET}) "{}")
                (func (export "{PROVIDER_ENTRYPOINT_V1}") (param i32 i32) (result i64)
                    {body}
                    (i64.const {packed})))"#,
        bytes_literal(&output),
    ))
    .expect("test provider WAT must compile")
}

fn provider_output(artifact_type: &str, value: u64) -> Value {
    json!({
        "schema_version": PROVIDER_ACTION_OUTPUT_SCHEMA_VERSION,
        "outputs": {
            "result": {
                "type": artifact_type,
                "value": value,
            }
        }
    })
}

fn provider_binding(artifact: &[u8]) -> ProviderExecutionBinding {
    let mut binding = ProviderExecutionBinding {
        schema_version: PROVIDER_EXECUTION_BINDING_SCHEMA_VERSION.to_string(),
        catalog_generation: 7,
        catalog_digest: format!("sha256:{}", "1".repeat(64)),
        logical_behavior_id: "acme.provider.behavior.v1".to_string(),
        logical_action_id: "acme.provider.action.v1".to_string(),
        package_id: "acme.provider-pack".to_string(),
        package_version: "1.2.3".to_string(),
        package_digest: format!("sha256:{}", "2".repeat(64)),
        content_digest: format!("sha256:{}", "3".repeat(64)),
        program_digest: String::new(),
        provider_id: "acme.provider.runtime.v1".to_string(),
        abi_version: PROVIDER_ABI_V1.to_string(),
        artifact_sha256: provider_artifact_digest(artifact),
        artifact_size: artifact.len(),
        action_contract_digest: format!("sha256:{}", "4".repeat(64)),
        runtime_contract_digest: String::new(),
        provider_runtime_contract_digest: provider_runtime_contract_digest(),
        inputs: Vec::new(),
        outputs: vec![ProviderArtifactSpec {
            name: "result".to_string(),
            artifact_type: "artifact.acme.provider-result.v1".to_string(),
            required: true,
            multiple: false,
        }],
        parameters: vec![ProviderParameterSpec {
            name: "seed".to_string(),
            parameter_type: ProviderParameterType::Integer,
            required: true,
            default: Value::Null,
            enum_values: Vec::new(),
            minimum: Some(serde_json::Number::from(0)),
            maximum: Some(serde_json::Number::from(100)),
        }],
        capabilities: vec![crate::contract::Capability::NativeExecution],
        safety_tier: crate::contract::SafetyTier::Safe,
        platforms: vec![crate::contract::Platform::current()],
        mutates: false,
        cleanup_action_id: None,
        limits: ProviderActionLimits {
            max_module_bytes: 256 * 1024,
            max_memory_bytes: 2 * 1024 * 1024,
            max_input_bytes: 64 * 1024,
            max_output_bytes: 64 * 1024,
            fuel: 1_000_000,
        },
    };
    binding.action_contract_digest = provider_action_contract_digest(&binding);
    binding.runtime_contract_digest = runtime_action_contract_digest(&binding);
    binding.program_digest = provider_program_digest(&binding);
    binding
}

fn provider_documents(
    artifact: &[u8],
    binding: ProviderExecutionBinding,
) -> (RunnerProfile, ExecutionManifest) {
    let mut profile = RunnerProfile {
        schema_version: PROFILE_SCHEMA_VERSION.to_string(),
        profile_id: "profile.provider-test.v1".to_string(),
        runner_id: "runner.provider-test.v1".to_string(),
        platform: crate::contract::Platform::current(),
        sandbox_root: Path::new(".").to_path_buf(),
        allowed_actions: vec![binding.logical_action_id.clone()],
        control_blocked_actions: Vec::new(),
        action_bindings: Vec::new(),
        provider_bindings: vec![binding.clone()],
        provider_artifacts: vec![ProviderArtifact {
            artifact_sha256: binding.artifact_sha256.clone(),
            artifact_size: artifact.len(),
            artifact_hex: hex::encode(artifact),
        }],
        capabilities: vec![crate::contract::Capability::NativeExecution],
        max_safety_tier: crate::contract::SafetyTier::Safe,
        approval_required_at_or_above: None,
        target_scope: crate::contract::TargetScope {
            filesystem: Vec::new(),
            network: Vec::new(),
        },
        limits: test_limits(),
        policy_digest: String::new(),
    };
    crate::contract::seal_profile(&mut profile);

    let requested_at = utc_now() - ChronoDuration::seconds(1);
    let mut manifest = ExecutionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        request_id: "request.provider-test.v1".to_string(),
        run_id: "run.provider-test.v1".to_string(),
        step_id: "step.provider-test.v1".to_string(),
        behavior_id: binding.logical_behavior_id.clone(),
        action_id: binding.logical_action_id.clone(),
        execution_binding: None,
        provider_binding: Some(binding),
        mode: RunMode::Execute,
        runner_id: profile.runner_id.clone(),
        runner_profile_id: profile.profile_id.clone(),
        platform: crate::contract::Platform::current(),
        requested_at,
        expires_at: requested_at + ChronoDuration::minutes(5),
        params: json!({"seed": 7}),
        target_scope: profile.target_scope.clone(),
        required_capabilities: vec![crate::contract::Capability::NativeExecution],
        safety_tier: crate::contract::SafetyTier::Safe,
        limits: test_limits(),
        cleanup_action_id: "sandbox.cleanup.v1".to_string(),
        policy_digest: profile.policy_digest.clone(),
        approval: None,
        evidence_refs: Vec::new(),
        request_hash: String::new(),
    };
    crate::contract::seal_manifest(&mut manifest);
    (profile, manifest)
}

fn reseal_documents(profile: &mut RunnerProfile, manifest: &mut ExecutionManifest) {
    crate::contract::seal_profile(profile);
    manifest.policy_digest = profile.policy_digest.clone();
    crate::contract::seal_manifest(manifest);
}

fn alias_binding(
    logical_behavior_id: &str,
    logical_action_id: &str,
    opcode: &str,
) -> ExecutionBinding {
    let action = find_action(opcode).expect("test opcode is registered");
    let mut binding = ExecutionBinding {
        schema_version: EXECUTION_BINDING_SCHEMA_VERSION.to_string(),
        catalog_generation: 7,
        catalog_digest: format!("sha256:{}", "1".repeat(64)),
        logical_behavior_id: logical_behavior_id.to_string(),
        logical_action_id: logical_action_id.to_string(),
        package_id: "acme.endpoint-profile-pack".to_string(),
        package_version: "1.2.3".to_string(),
        package_digest: format!("sha256:{}", "2".repeat(64)),
        content_digest: format!("sha256:{}", "3".repeat(64)),
        program_digest: String::new(),
        runner_opcode: opcode.to_string(),
        opcode_contract_digest: descriptor_digest(action.descriptor()),
        constants: reviewed_program_constants(opcode).expect("test opcode is reviewed"),
    };
    binding.program_digest = program_digest(&binding);
    binding
}

fn alias_documents(
    root: &Path,
    binding: ExecutionBinding,
    params: Value,
) -> (RunnerProfile, ExecutionManifest) {
    let descriptor = find_action(&binding.runner_opcode)
        .expect("test opcode is registered")
        .descriptor();
    let mut profile = RunnerProfile {
        schema_version: PROFILE_SCHEMA_VERSION.to_string(),
        profile_id: "profile.test.v1".to_string(),
        runner_id: "runner.test.v1".to_string(),
        platform: crate::contract::Platform::current(),
        sandbox_root: root.to_path_buf(),
        allowed_actions: vec![
            binding.runner_opcode.clone(),
            binding.logical_action_id.clone(),
        ],
        control_blocked_actions: Vec::new(),
        action_bindings: vec![binding.clone()],
        provider_bindings: Vec::new(),
        provider_artifacts: Vec::new(),
        capabilities: descriptor.capabilities.to_vec(),
        max_safety_tier: descriptor.safety_tier,
        approval_required_at_or_above: None,
        target_scope: crate::contract::TargetScope {
            filesystem: vec!["fixtures".to_string()],
            network: Vec::new(),
        },
        limits: test_limits(),
        policy_digest: String::new(),
    };
    crate::contract::seal_profile(&mut profile);
    let requested_at = utc_now() - ChronoDuration::seconds(1);
    let mut manifest = ExecutionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        request_id: "request.package-alias.v1".to_string(),
        run_id: "run.package-alias.v1".to_string(),
        step_id: "step.package-alias.v1".to_string(),
        behavior_id: binding.logical_behavior_id.clone(),
        action_id: binding.logical_action_id.clone(),
        execution_binding: Some(binding),
        provider_binding: None,
        mode: RunMode::Execute,
        runner_id: profile.runner_id.clone(),
        runner_profile_id: profile.profile_id.clone(),
        platform: crate::contract::Platform::current(),
        requested_at,
        expires_at: requested_at + ChronoDuration::minutes(5),
        params,
        target_scope: profile.target_scope.clone(),
        required_capabilities: descriptor.capabilities.to_vec(),
        safety_tier: descriptor.safety_tier,
        limits: test_limits(),
        cleanup_action_id: "sandbox.cleanup.v1".to_string(),
        policy_digest: profile.policy_digest.clone(),
        approval: None,
        evidence_refs: Vec::new(),
        request_hash: String::new(),
    };
    crate::contract::seal_manifest(&mut manifest);
    (profile, manifest)
}

#[test]
fn parameter_depth_is_bounded() {
    let mut value = Value::Null;
    for _ in 0..=MAX_JSON_DEPTH + 1 {
        value = json!([value]);
    }
    assert!(validate_json_shape(&value).is_err());
}

#[test]
fn resource_limits_cannot_expand_profile() {
    let maximum = ExecutionLimits {
        timeout_ms: 100,
        max_stdout_bytes: 100,
        max_stderr_bytes: 100,
        max_artifact_bytes: 100,
        max_files: 2,
    };
    let mut requested = maximum.clone();
    requested.timeout_ms = 101;
    assert!(validate_limits(&requested, &maximum).is_err());
    requested.timeout_ms = 0;
    assert!(validate_limits(&requested, &maximum).is_err());
}

#[test]
fn shared_action_readiness_gate_refuses_non_ready_descriptors() {
    let mut descriptor = find_action("endpoint.discovery.system.v1")
        .expect("test action is registered")
        .descriptor()
        .clone();
    assert!(ensure_action_ready(&descriptor).is_ok());

    for readiness in [ActionReadiness::Structural, ActionReadiness::Unavailable] {
        descriptor.readiness = readiness;
        let failure = ensure_action_ready(&descriptor)
            .expect_err("non-ready actions must be rejected before execution");
        assert_eq!(failure.status, TaskStatus::ControlBlocked);
        assert_eq!(failure.code, "action_not_ready");
        assert_eq!(
            failure.message,
            "selected action is not ready for execution"
        );
    }
}

#[test]
fn sealed_provider_dispatch_executes_real_wasm_outside_the_static_registry() {
    let artifact_type = "artifact.acme.provider-result.v1";
    let expected_output = provider_output(artifact_type, 7);
    let expected_output_bytes = canonical_json(&expected_output).len();
    let artifact = provider_module(&expected_output, "");
    let binding = provider_binding(&artifact);
    let artifact_digest = binding.artifact_sha256.clone();
    assert!(find_action(&binding.logical_action_id).is_none());
    assert!(crate::actions::inventory()
        .iter()
        .all(|descriptor| descriptor.action_id != binding.logical_action_id));
    let (profile, manifest) = provider_documents(&artifact, binding.clone());

    let result = Runner::new().unwrap().execute(manifest, profile);

    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    assert_eq!(result.behavior_id, binding.logical_behavior_id);
    assert_eq!(result.action_id, binding.logical_action_id);
    assert_eq!(result.output, expected_output);
    assert!(result.receipt_ids.is_empty());
    assert!(result.cleanup.is_none());
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.evidence[0].behavior_id, result.behavior_id);
    assert_eq!(result.evidence[0].action_id, result.action_id);
    let metrics = &result.evidence[0].details["provider_execution"];
    assert_eq!(metrics["artifact_sha256"], artifact_digest);
    assert!(metrics["fuel_consumed"]
        .as_u64()
        .is_some_and(|fuel| fuel > 0));
    assert_eq!(metrics["memory_bytes"], 65_536);
    assert_eq!(metrics["output_bytes"], expected_output_bytes);
    assert_eq!(metrics["no_host_imports"], true);
}

#[test]
fn provider_dispatch_fails_closed_on_missing_substituted_or_mismatched_seals() {
    let output = provider_output("artifact.acme.provider-result.v1", 7);
    let artifact = provider_module(&output, "");
    let binding = provider_binding(&artifact);

    let (mut profile, mut manifest) = provider_documents(&artifact, binding.clone());
    profile.provider_artifacts.clear();
    reseal_documents(&mut profile, &mut manifest);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "invalid_profile");

    let replacement = provider_module(&provider_output("artifact.acme.provider-result.v1", 8), "");
    assert_eq!(replacement.len(), artifact.len());
    assert_ne!(
        provider_artifact_digest(&replacement),
        binding.artifact_sha256
    );
    let (mut profile, mut manifest) = provider_documents(&artifact, binding.clone());
    profile.provider_artifacts[0].artifact_hex = hex::encode(replacement);
    reseal_documents(&mut profile, &mut manifest);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "invalid_profile");

    let (profile, mut manifest) = provider_documents(&artifact, binding);
    manifest.provider_binding.as_mut().unwrap().package_version = "1.2.4".to_string();
    crate::contract::seal_manifest(&mut manifest);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "provider_binding_mismatch");
}

#[test]
fn provider_dispatch_maps_fuel_and_output_failures_to_stable_statuses() {
    let expected_output = provider_output("artifact.acme.provider-result.v1", 7);
    let looping_artifact = provider_module(&expected_output, "(loop $forever (br $forever))");
    let mut looping_binding = provider_binding(&looping_artifact);
    looping_binding.limits.fuel = 10_000;
    let (profile, manifest) = provider_documents(&looping_artifact, looping_binding);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::TimedOut, "{result:#?}");
    assert_eq!(result.error.unwrap().code, "provider_fuel_exhausted");

    let invalid_output = provider_output("artifact.acme.unexpected-result.v1", 7);
    let invalid_artifact = provider_module(&invalid_output, "");
    let invalid_binding = provider_binding(&invalid_artifact);
    let (profile, manifest) = provider_documents(&invalid_artifact, invalid_binding);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::Failed, "{result:#?}");
    assert_eq!(result.error.unwrap().code, "provider_runtime_failed");

    let invalid_guest = wat::parse_str(format!(
        r#"(module
                (memory (export "{PROVIDER_MEMORY_EXPORT}") 1)
                (func (export "unexpected_entrypoint") (param i32 i32) (result i64)
                    (i64.const 0)))"#,
    ))
    .unwrap();
    let guest_binding = provider_binding(&invalid_guest);
    let (profile, manifest) = provider_documents(&invalid_guest, guest_binding);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::Failed, "{result:#?}");
    assert_eq!(result.error.unwrap().code, "provider_runtime_failed");
}

#[test]
fn static_actions_refuse_provider_shadowing_and_mixed_dispatch_bindings() {
    let provider_artifact =
        provider_module(&provider_output("artifact.acme.provider-result.v1", 7), "");
    let provider_binding = provider_binding(&provider_artifact);
    let (profile, mut manifest) = provider_documents(&provider_artifact, provider_binding.clone());
    manifest.execution_binding = Some(alias_binding(
        "acme.endpoint.profile.v1",
        "acme.endpoint.profile-action.v1",
        "endpoint.discovery.system.v1",
    ));
    crate::contract::seal_manifest(&mut manifest);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "execution_binding_mismatch");

    let static_action_id = "endpoint.discovery.system.v1";
    let static_behavior_id = find_action(static_action_id)
        .unwrap()
        .descriptor()
        .behavior_ids[0];
    let alias = alias_binding(
        "acme.endpoint.profile.v1",
        "acme.endpoint.profile-action.v1",
        static_action_id,
    );
    let (profile, mut manifest) = alias_documents(Path::new("."), alias, json!({}));
    let mut shadow = provider_binding;
    shadow.logical_behavior_id = static_behavior_id.to_string();
    shadow.logical_action_id = static_action_id.to_string();
    shadow.runtime_contract_digest = runtime_action_contract_digest(&shadow);
    manifest.behavior_id = static_behavior_id.to_string();
    manifest.action_id = static_action_id.to_string();
    manifest.execution_binding = None;
    manifest.provider_binding = Some(shadow);
    crate::contract::seal_manifest(&mut manifest);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "provider_binding_mismatch");
}

#[test]
fn package_alias_dispatch_preserves_logical_result_and_evidence_identity() {
    let root = std::env::temp_dir().join(format!(
        "bluefire-runner-alias-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let binding = alias_binding(
        "acme.endpoint.profile.v1",
        "acme.endpoint.profile-action.v1",
        "endpoint.discovery.system.v1",
    );
    assert_eq!(
        binding.program_digest,
        "sha256:e9fa0fe32f0e7bb0b38d5bb946ac3b3fcf91cc4abc14945fc4c1053c0cf57c4a"
    );
    let (profile, manifest) = alias_documents(&root, binding.clone(), json!({}));

    let result = Runner::new().unwrap().execute(manifest, profile);

    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    assert_eq!(result.behavior_id, binding.logical_behavior_id);
    assert_eq!(result.action_id, binding.logical_action_id);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.evidence[0].behavior_id, result.behavior_id);
    assert_eq!(result.evidence[0].action_id, result.action_id);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn latent_windows_version_opcode_executes_only_through_a_package_alias() {
    let root = std::env::temp_dir().join(format!(
        "bluefire-runner-windows-version-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let binding = alias_binding(
        "acme.windows-version.v1",
        "acme.windows-version-action.v1",
        "endpoint.discovery.windows-version.v1",
    );
    let (profile, manifest) = alias_documents(&root, binding, json!({}));

    let result = Runner::new().unwrap().execute(manifest, profile);

    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    let object = result.output.as_object().expect("output must be an object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "build_number",
            "major_version",
            "minor_version",
            "operating_system",
        ])
    );
    assert_eq!(result.output["operating_system"], "windows");
    assert!(result.output["major_version"].as_u64().is_some());
    assert!(result.output["minor_version"].as_u64().is_some());
    assert!(result.output["build_number"].as_u64().is_some());
    assert!(result.receipt_ids.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn package_alias_receipt_retains_the_logical_action_identity() {
    let root = std::env::temp_dir().join(format!(
        "bluefire-runner-alias-receipt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let binding = alias_binding(
        "acme.fixture.create.v1",
        "acme.fixture.create-action.v1",
        "sandbox.fixture.create.v1",
    );
    let (profile, manifest) = alias_documents(
        &root,
        binding.clone(),
        json!({
            "path": "fixtures/package-alias.txt",
            "content_template": "telemetry-seed",
            "record_count": 1
        }),
    );

    let result = Runner::new().unwrap().execute(manifest, profile);

    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    assert_eq!(result.receipt_ids.len(), 1);
    let receipt = SafeRoot::open(&root)
        .unwrap()
        .load_receipt(&result.receipt_ids[0])
        .unwrap()
        .expect("successful mutation must persist its cleanup receipt");
    assert_eq!(receipt.action_id, binding.logical_action_id);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn package_alias_fails_closed_on_profile_or_descriptor_substitution() {
    let root = Path::new(".");
    let binding = alias_binding(
        "acme.endpoint.profile.v1",
        "acme.endpoint.profile-action.v1",
        "endpoint.discovery.system.v1",
    );
    let (profile, mut manifest) = alias_documents(root, binding.clone(), json!({}));
    manifest.execution_binding.as_mut().unwrap().package_version = "1.2.4".to_string();
    crate::contract::seal_manifest(&mut manifest);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "execution_binding_mismatch");

    let mut substituted = binding;
    substituted.opcode_contract_digest = format!("sha256:{}", "9".repeat(64));
    let (mut profile, mut manifest) = alias_documents(root, substituted, json!({}));
    crate::contract::seal_profile(&mut profile);
    manifest.policy_digest = profile.policy_digest.clone();
    crate::contract::seal_manifest(&mut manifest);
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "invalid_profile");
}

#[test]
fn package_alias_constants_are_exactly_the_reviewed_opcode_attestations() {
    let mut binding = alias_binding(
        "acme.network.loopback.v1",
        "acme.network.loopback-action.v1",
        "sandbox.network.loopback.v1",
    );
    binding
        .constants
        .insert("method".to_string(), Value::String("GET".to_string()));
    binding.program_digest = program_digest(&binding);
    assert!(validate_execution_binding(&binding)
        .err()
        .expect("mismatched constants must be refused")
        .contains("constants"));
}
