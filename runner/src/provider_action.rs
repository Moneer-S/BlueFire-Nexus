//! Policy and typed contracts for action-pack WebAssembly providers.
//!
//! Provider artifacts are carried only inside the sealed runner profile. This
//! module validates the signed action contract, reconstructs its canonical
//! runtime digests, and hands verified bytes to the zero-import runtime.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::contract::{
    canonical_hash, Capability, ExecutionManifest, Platform, ProviderActionLimits,
    ProviderArtifact, ProviderArtifactSpec, ProviderExecutionBinding, ProviderParameterSpec,
    ProviderParameterType, RunnerProfile, SafetyTier, PROVIDER_EXECUTION_BINDING_SCHEMA_VERSION,
};
use crate::providers::{
    execute_provider, provider_artifact_digest, provider_runtime_contract_digest,
    validate_provider_limits, ProviderArtifactContract, ProviderError, ProviderExecution,
    ProviderLimits, PROVIDER_ABI_V1,
};

pub const PROVIDER_RUNTIME_ACTION_CONTRACT_SCHEMA_VERSION: &str =
    "bluefire.provider-runtime-action-contract.v1";
pub const PROVIDER_ACTION_CONTRACT_SCHEMA_VERSION: &str = "bluefire.provider-action-contract.v1";
pub const WASM_PROVIDER_PROGRAM_SCHEMA_VERSION: &str = "bluefire.wasm-provider-program.v1";
pub const PROVIDER_ACTION_INPUT_SCHEMA_VERSION: &str = "bluefire.provider-action-input.v1";
pub const PROVIDER_ACTION_OUTPUT_SCHEMA_VERSION: &str = "bluefire.provider-action-output.v1";

const MAX_PROVIDER_BINDINGS: usize = 512;
const MAX_PROVIDER_ARTIFACTS: usize = 64;
const MAX_PROVIDER_ARTIFACT_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_OUTPUTS: usize = 64;
const MAX_PROVIDER_PARAMETERS: usize = 64;
const MAX_PROVIDER_ENUM_VALUES: usize = 64;

#[derive(Debug)]
pub struct ProviderActionExecution {
    pub output: Value,
    pub artifact_sha256: String,
    pub fuel_consumed: u64,
    pub memory_bytes: usize,
    pub output_bytes: usize,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderActionInput<'a> {
    schema_version: &'static str,
    action_id: &'a str,
    behavior_id: &'a str,
    request_hash: &'a str,
    parameters: &'a Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderActionOutput {
    schema_version: String,
    outputs: BTreeMap<String, Value>,
}

pub fn runtime_action_contract_digest(binding: &ProviderExecutionBinding) -> String {
    let inputs = binding
        .inputs
        .iter()
        .map(artifact_spec_value)
        .collect::<Vec<_>>();
    let outputs = binding
        .outputs
        .iter()
        .map(artifact_spec_value)
        .collect::<Vec<_>>();
    let parameters = binding
        .parameters
        .iter()
        .map(parameter_contract_value)
        .collect::<Vec<_>>();
    canonical_hash(&json!({
        "schema_version": PROVIDER_RUNTIME_ACTION_CONTRACT_SCHEMA_VERSION,
        "logical_action_id": &binding.logical_action_id,
        "inputs": inputs,
        "outputs": outputs,
        "parameters": parameters,
        "capabilities": &binding.capabilities,
        "safety_tier": binding.safety_tier,
        "platforms": &binding.platforms,
        "mutates": binding.mutates,
        "cleanup_action_id": &binding.cleanup_action_id,
    }))
}

pub fn provider_program_digest(binding: &ProviderExecutionBinding) -> String {
    canonical_hash(&json!({
        "schema_version": WASM_PROVIDER_PROGRAM_SCHEMA_VERSION,
        "provider_id": &binding.provider_id,
        "action_contract_digest": &binding.action_contract_digest,
    }))
}

pub fn validate_provider_binding(binding: &ProviderExecutionBinding) -> Result<(), String> {
    if binding.schema_version != PROVIDER_EXECUTION_BINDING_SCHEMA_VERSION {
        return Err("provider execution binding schema version is unsupported".to_string());
    }
    if binding.catalog_generation == 0 || binding.catalog_generation > i64::MAX as u64 {
        return Err("provider execution binding catalog generation is invalid".to_string());
    }
    for (kind, digest) in [
        ("catalog", binding.catalog_digest.as_str()),
        ("package", binding.package_digest.as_str()),
        ("content", binding.content_digest.as_str()),
        ("program", binding.program_digest.as_str()),
        ("action contract", binding.action_contract_digest.as_str()),
        ("runtime contract", binding.runtime_contract_digest.as_str()),
        (
            "provider runtime contract",
            binding.provider_runtime_contract_digest.as_str(),
        ),
        ("artifact", binding.artifact_sha256.as_str()),
    ] {
        if !is_sha256_digest(digest) {
            return Err(format!(
                "provider execution binding {kind} digest must be exact lowercase SHA-256"
            ));
        }
    }
    if !is_stable_id(&binding.logical_behavior_id)
        || !is_stable_id(&binding.logical_action_id)
        || !is_package_identifier(&binding.package_id)
        || !is_semver(&binding.package_version)
        || !is_stable_id(&binding.provider_id)
    {
        return Err("provider execution binding identity is invalid".to_string());
    }
    if binding.abi_version != PROVIDER_ABI_V1 {
        return Err("provider execution binding ABI is unsupported".to_string());
    }
    if binding.artifact_size < 8
        || binding.artifact_size > MAX_PROVIDER_ARTIFACT_BYTES
        || binding.artifact_size > binding.limits.max_module_bytes
    {
        return Err("provider execution binding artifact size is invalid".to_string());
    }
    validate_provider_limits(provider_limits(binding.limits)).map_err(|error| error.to_string())?;
    if binding.program_digest != provider_program_digest(binding) {
        return Err("provider execution binding program digest does not match".to_string());
    }
    if binding.action_contract_digest != provider_action_contract_digest(binding) {
        return Err("provider execution binding action contract digest does not match".to_string());
    }
    if binding.runtime_contract_digest != runtime_action_contract_digest(binding) {
        return Err(
            "provider execution binding runtime contract digest does not match".to_string(),
        );
    }
    if binding.provider_runtime_contract_digest != provider_runtime_contract_digest() {
        return Err("provider execution binding targets another provider runtime".to_string());
    }
    if !binding.inputs.is_empty() {
        return Err("provider ABI v1 does not expose host artifact inputs".to_string());
    }
    validate_artifact_specs(&binding.outputs)?;
    validate_parameter_specs(&binding.parameters)?;
    if binding.capabilities != [Capability::NativeExecution] {
        return Err("provider ABI v1 requires exactly native_execution capability".to_string());
    }
    if binding.safety_tier != SafetyTier::Safe {
        return Err("provider ABI v1 actions must use the safe tier".to_string());
    }
    if binding.platforms.is_empty()
        || binding
            .platforms
            .windows(2)
            .any(|pair| platform_wire_name(pair[0]) >= platform_wire_name(pair[1]))
        || !binding.platforms.contains(&Platform::current())
    {
        return Err("provider execution binding platform contract is invalid".to_string());
    }
    if binding.mutates || binding.cleanup_action_id.is_some() {
        return Err("provider ABI v1 actions cannot claim host mutation or cleanup".to_string());
    }
    Ok(())
}

pub fn validate_provider_profile(
    bindings: &[ProviderExecutionBinding],
    artifacts: &[ProviderArtifact],
) -> Result<(), String> {
    if bindings.len() > MAX_PROVIDER_BINDINGS {
        return Err("provider_bindings exceeds the runner profile limit".to_string());
    }
    if artifacts.len() > MAX_PROVIDER_ARTIFACTS {
        return Err("provider_artifacts exceeds the runner profile limit".to_string());
    }

    let mut previous_pair: Option<(&str, &str)> = None;
    let mut catalog_identity: Option<(u64, &str)> = None;
    let mut expected_artifacts = BTreeMap::<&str, usize>::new();
    for binding in bindings {
        validate_provider_binding(binding)?;
        let pair = (
            binding.logical_behavior_id.as_str(),
            binding.logical_action_id.as_str(),
        );
        if previous_pair.is_some_and(|previous| previous >= pair) {
            return Err(
                "provider_bindings must be ordered by logical behavior/action pair".to_string(),
            );
        }
        previous_pair = Some(pair);
        let candidate_identity = (binding.catalog_generation, binding.catalog_digest.as_str());
        if let Some(expected) = catalog_identity {
            if expected != candidate_identity {
                return Err("provider_bindings span more than one catalog generation".to_string());
            }
        } else {
            catalog_identity = Some(candidate_identity);
        }
        if let Some(size) =
            expected_artifacts.insert(&binding.artifact_sha256, binding.artifact_size)
        {
            if size != binding.artifact_size {
                return Err("provider bindings disagree about artifact size".to_string());
            }
        }
    }

    let mut actual_artifacts = BTreeSet::new();
    let mut previous_digest: Option<&str> = None;
    for artifact in artifacts {
        if previous_digest.is_some_and(|previous| previous >= artifact.artifact_sha256.as_str()) {
            return Err("provider_artifacts must be ordered by artifact digest".to_string());
        }
        previous_digest = Some(&artifact.artifact_sha256);
        let bytes = decode_provider_artifact(artifact)?;
        let expected_size = expected_artifacts
            .get(artifact.artifact_sha256.as_str())
            .ok_or_else(|| {
                "runner profile contains an unreferenced provider artifact".to_string()
            })?;
        if *expected_size != bytes.len() {
            return Err("provider artifact size differs from its binding".to_string());
        }
        if !actual_artifacts.insert(artifact.artifact_sha256.as_str()) {
            return Err("runner profile contains a duplicate provider artifact".to_string());
        }
    }
    let expected = expected_artifacts.keys().copied().collect::<BTreeSet<_>>();
    if actual_artifacts != expected {
        return Err("runner profile does not contain exactly its referenced artifacts".to_string());
    }
    Ok(())
}

pub fn provider_artifact_bytes(
    profile: &RunnerProfile,
    binding: &ProviderExecutionBinding,
) -> Result<Vec<u8>, String> {
    let artifact = profile
        .provider_artifacts
        .iter()
        .find(|candidate| candidate.artifact_sha256 == binding.artifact_sha256)
        .ok_or_else(|| "provider artifact is absent from the sealed profile".to_string())?;
    let bytes = decode_provider_artifact(artifact)?;
    if bytes.len() != binding.artifact_size {
        return Err("provider artifact size differs from its execution binding".to_string());
    }
    Ok(bytes)
}

pub fn validate_provider_parameters(
    binding: &ProviderExecutionBinding,
    parameters: &Value,
) -> Result<(), String> {
    let values = parameters
        .as_object()
        .ok_or_else(|| "provider parameters must be a JSON object".to_string())?;
    let specs = binding
        .parameters
        .iter()
        .map(|spec| (spec.name.as_str(), spec))
        .collect::<BTreeMap<_, _>>();
    for name in values.keys() {
        if !specs.contains_key(name.as_str()) {
            return Err(format!("provider parameters contain unknown field {name}"));
        }
    }
    for spec in &binding.parameters {
        match values.get(&spec.name) {
            Some(value) => validate_parameter_value(spec, value)?,
            None if spec.required => {
                return Err(format!("provider parameter {} is required", spec.name))
            }
            None => {}
        }
    }
    Ok(())
}

pub fn execute_provider_action(
    manifest: &ExecutionManifest,
    binding: &ProviderExecutionBinding,
    artifact: &[u8],
) -> Result<ProviderActionExecution, ProviderError> {
    let input = ProviderActionInput {
        schema_version: PROVIDER_ACTION_INPUT_SCHEMA_VERSION,
        action_id: &manifest.action_id,
        behavior_id: &manifest.behavior_id,
        request_hash: &manifest.request_hash,
        parameters: &manifest.params,
    };
    let execution: ProviderExecution<ProviderActionOutput> = execute_provider(
        artifact,
        &ProviderArtifactContract::new(&binding.abi_version, &binding.artifact_sha256),
        &input,
        provider_limits(binding.limits),
    )?;
    if execution.output.schema_version != PROVIDER_ACTION_OUTPUT_SCHEMA_VERSION {
        return Err(ProviderError::InvalidOutput(
            "provider action output schema is unsupported".to_string(),
        ));
    }
    validate_provider_outputs(&binding.outputs, &execution.output.outputs)
        .map_err(ProviderError::InvalidOutput)?;
    let output = serde_json::to_value(&execution.output)
        .map_err(|error| ProviderError::InvalidOutput(error.to_string()))?;
    Ok(ProviderActionExecution {
        output,
        artifact_sha256: execution.artifact_sha256,
        fuel_consumed: execution.fuel_consumed,
        memory_bytes: execution.memory_bytes,
        output_bytes: execution.output_bytes,
    })
}

fn provider_limits(limits: ProviderActionLimits) -> ProviderLimits {
    ProviderLimits {
        max_module_bytes: limits.max_module_bytes,
        max_memory_bytes: limits.max_memory_bytes,
        max_input_bytes: limits.max_input_bytes,
        max_output_bytes: limits.max_output_bytes,
        fuel: limits.fuel,
    }
}

fn artifact_spec_value(spec: &ProviderArtifactSpec) -> Value {
    json!({
        "name": &spec.name,
        "type": &spec.artifact_type,
        "required": spec.required,
        "multiple": spec.multiple,
    })
}

fn parameter_contract_value(spec: &ProviderParameterSpec) -> Value {
    json!({
        "name": &spec.name,
        "type": spec.parameter_type,
        "required": spec.required,
        "default": &spec.default,
        "enum": &spec.enum_values,
        "minimum": &spec.minimum,
        "maximum": &spec.maximum,
    })
}

fn validate_artifact_specs(specs: &[ProviderArtifactSpec]) -> Result<(), String> {
    if specs.is_empty() || specs.len() > MAX_PROVIDER_OUTPUTS {
        return Err(format!(
            "provider outputs must contain 1..={MAX_PROVIDER_OUTPUTS} specifications"
        ));
    }
    let mut names = BTreeSet::new();
    for spec in specs {
        if !is_field_name(&spec.name) || !is_stable_id(&spec.artifact_type) {
            return Err("provider output specification identity is invalid".to_string());
        }
        if !names.insert(spec.name.as_str()) {
            return Err("provider output specifications contain duplicate names".to_string());
        }
    }
    Ok(())
}

fn validate_parameter_specs(specs: &[ProviderParameterSpec]) -> Result<(), String> {
    if specs.len() > MAX_PROVIDER_PARAMETERS {
        return Err(format!(
            "provider parameters exceed {MAX_PROVIDER_PARAMETERS} specifications"
        ));
    }
    let mut names = BTreeSet::new();
    for spec in specs {
        if !is_field_name(&spec.name) {
            return Err("provider parameter specification is invalid".to_string());
        }
        if !names.insert(spec.name.as_str()) {
            return Err("provider parameter specifications contain duplicate names".to_string());
        }
        if spec.enum_values.len() > MAX_PROVIDER_ENUM_VALUES {
            return Err(format!(
                "provider parameter enum exceeds {MAX_PROVIDER_ENUM_VALUES} values"
            ));
        }
        if spec.minimum.is_some() || spec.maximum.is_some() {
            if !matches!(
                spec.parameter_type,
                ProviderParameterType::Integer | ProviderParameterType::Number
            ) {
                return Err("only numeric provider parameters may declare bounds".to_string());
            }
            let minimum = spec.minimum.as_ref().and_then(number_as_f64);
            let maximum = spec.maximum.as_ref().and_then(number_as_f64);
            if minimum.is_none() && spec.minimum.is_some()
                || maximum.is_none() && spec.maximum.is_some()
                || minimum
                    .zip(maximum)
                    .is_some_and(|(left, right)| left > right)
            {
                return Err("provider parameter numeric bounds are invalid".to_string());
            }
        }
        if spec.default != Value::Null {
            validate_parameter_value(spec, &spec.default)?;
        }
        let mut enum_values = BTreeSet::new();
        for value in &spec.enum_values {
            validate_parameter_value_without_enum(spec, value)?;
            let encoded = serde_json::to_string(value)
                .map_err(|_| "provider parameter enum is invalid".to_string())?;
            if !enum_values.insert(encoded) {
                return Err("provider parameter enum contains duplicates".to_string());
            }
        }
    }
    Ok(())
}

fn validate_parameter_value(spec: &ProviderParameterSpec, value: &Value) -> Result<(), String> {
    validate_parameter_value_without_enum(spec, value)?;
    if !spec.enum_values.is_empty() && !spec.enum_values.contains(value) {
        return Err(format!(
            "provider parameter {} is not an allowed value",
            spec.name
        ));
    }
    Ok(())
}

fn validate_parameter_value_without_enum(
    spec: &ProviderParameterSpec,
    value: &Value,
) -> Result<(), String> {
    let valid_type = match spec.parameter_type {
        ProviderParameterType::String => value.is_string(),
        ProviderParameterType::Integer => value
            .as_number()
            .is_some_and(|number| number.is_i64() || number.is_u64()),
        ProviderParameterType::Number => value.is_number(),
        ProviderParameterType::Boolean => value.is_boolean(),
        ProviderParameterType::StringList => value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string)),
    };
    if !valid_type {
        return Err(format!(
            "provider parameter {} has the wrong type",
            spec.name
        ));
    }
    if value.is_number() {
        let numeric = value
            .as_number()
            .and_then(number_as_f64)
            .ok_or_else(|| format!("provider parameter {} is not finite", spec.name))?;
        if spec
            .minimum
            .as_ref()
            .and_then(number_as_f64)
            .is_some_and(|minimum| numeric < minimum)
        {
            return Err(format!("provider parameter {} is below minimum", spec.name));
        }
        if spec
            .maximum
            .as_ref()
            .and_then(number_as_f64)
            .is_some_and(|maximum| numeric > maximum)
        {
            return Err(format!("provider parameter {} exceeds maximum", spec.name));
        }
    }
    Ok(())
}

fn validate_provider_outputs(
    specs: &[ProviderArtifactSpec],
    outputs: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let declared = specs
        .iter()
        .map(|spec| (spec.name.as_str(), spec))
        .collect::<BTreeMap<_, _>>();
    for name in outputs.keys() {
        if !declared.contains_key(name.as_str()) {
            return Err(format!("provider returned undeclared output {name}"));
        }
    }
    for spec in specs {
        let Some(value) = outputs.get(&spec.name) else {
            if spec.required {
                return Err(format!("provider omitted required output {}", spec.name));
            }
            continue;
        };
        if spec.multiple {
            let values = value
                .as_array()
                .ok_or_else(|| format!("provider output {} must be an array", spec.name))?;
            if spec.required && values.is_empty() {
                return Err(format!("provider output {} cannot be empty", spec.name));
            }
            for item in values {
                validate_typed_artifact(spec, item)?;
            }
        } else {
            validate_typed_artifact(spec, value)?;
        }
    }
    Ok(())
}

fn validate_typed_artifact(spec: &ProviderArtifactSpec, value: &Value) -> Result<(), String> {
    let artifact = value
        .as_object()
        .ok_or_else(|| format!("provider output {} must be an artifact object", spec.name))?;
    if artifact.get("type").and_then(Value::as_str) != Some(spec.artifact_type.as_str()) {
        return Err(format!(
            "provider output {} has the wrong artifact type",
            spec.name
        ));
    }
    Ok(())
}

fn decode_provider_artifact(artifact: &ProviderArtifact) -> Result<Vec<u8>, String> {
    if !is_sha256_digest(&artifact.artifact_sha256)
        || artifact.artifact_size < 8
        || artifact.artifact_size > MAX_PROVIDER_ARTIFACT_BYTES
    {
        return Err("provider artifact identity is invalid".to_string());
    }
    let expected_hex_len = artifact
        .artifact_size
        .checked_mul(2)
        .ok_or_else(|| "provider artifact size overflowed".to_string())?;
    if artifact.artifact_hex.len() != expected_hex_len
        || !artifact.artifact_hex.len().is_multiple_of(2)
        || !artifact
            .artifact_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("provider artifact must use canonical lowercase even hex".to_string());
    }
    let bytes = hex::decode(&artifact.artifact_hex)
        .map_err(|_| "provider artifact hex is invalid".to_string())?;
    if provider_artifact_digest(&bytes) != artifact.artifact_sha256 {
        return Err("provider artifact digest does not match its bytes".to_string());
    }
    Ok(bytes)
}

fn number_as_f64(number: &serde_json::Number) -> Option<f64> {
    number.as_f64().filter(|value| value.is_finite())
}

pub fn provider_action_contract_digest(binding: &ProviderExecutionBinding) -> String {
    let inputs = binding
        .inputs
        .iter()
        .map(artifact_spec_value)
        .collect::<Vec<_>>();
    let outputs = binding
        .outputs
        .iter()
        .map(artifact_spec_value)
        .collect::<Vec<_>>();
    let parameters = binding
        .parameters
        .iter()
        .map(parameter_contract_value)
        .collect::<Vec<_>>();
    canonical_hash(&json!({
        "schema_version": PROVIDER_ACTION_CONTRACT_SCHEMA_VERSION,
        "action": {
            "id": &binding.logical_action_id,
            "inputs": inputs,
            "outputs": outputs,
            "parameters": parameters,
            "capabilities": ["native.execution"],
            "safety_tier": binding.safety_tier,
            "platforms": &binding.platforms,
            "mutates": binding.mutates,
            "cleanup_action_id": &binding.cleanup_action_id,
        },
    }))
}

fn platform_wire_name(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => "linux",
        Platform::Macos => "macos",
        Platform::Windows => "windows",
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_field_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn is_package_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut previous_separator = false;
    for byte in bytes.iter().copied() {
        let separator = matches!(byte, b'.' | b'_' | b'-');
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && !separator {
            return false;
        }
        if separator && previous_separator {
            return false;
        }
        previous_separator = separator;
    }
    !previous_separator
}

fn is_stable_id(value: &str) -> bool {
    if !is_package_identifier(value) {
        return false;
    }
    let Some((prefix, version)) = value.rsplit_once(".v") else {
        return false;
    };
    !prefix.is_empty()
        && !version.is_empty()
        && !version.starts_with('0')
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let core_and_pre = value.split_once('+').map_or(value, |(left, metadata)| {
        if metadata.is_empty()
            || metadata.split('.').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return "";
        }
        left
    });
    let (core, prerelease) = core_and_pre
        .split_once('-')
        .map_or((core_and_pre, None), |(left, right)| (left, Some(right)));
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || part.parse::<u64>().is_err()
        })
    {
        return false;
    }
    if let Some(prerelease) = prerelease {
        if prerelease.is_empty()
            || prerelease.split('.').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || (part.bytes().all(|byte| byte.is_ascii_digit())
                        && part.len() > 1
                        && part.starts_with('0'))
            })
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_contract_is_sensitive_to_signed_parameter_fields() {
        let mut binding = test_binding();
        let original = runtime_action_contract_digest(&binding);
        let original_action = provider_action_contract_digest(&binding);
        binding.parameters[0].required = false;
        assert_ne!(runtime_action_contract_digest(&binding), original);
        assert_ne!(provider_action_contract_digest(&binding), original_action);
    }

    #[test]
    fn declared_spec_order_is_preserved_while_duplicate_names_are_refused() {
        let binding = test_binding();
        let mut later_output = binding.outputs[0].clone();
        later_output.name = "zeta".to_string();
        let outputs = vec![later_output, binding.outputs[0].clone()];
        validate_artifact_specs(&outputs).unwrap();
        let mut duplicate_outputs = outputs;
        duplicate_outputs[1].name = "zeta".to_string();
        assert!(validate_artifact_specs(&duplicate_outputs).is_err());

        let mut later_parameter = binding.parameters[0].clone();
        later_parameter.name = "zeta".to_string();
        let parameters = vec![later_parameter, binding.parameters[0].clone()];
        validate_parameter_specs(&parameters).unwrap();
        let mut duplicate_parameters = parameters;
        duplicate_parameters[1].name = "zeta".to_string();
        assert!(validate_parameter_specs(&duplicate_parameters).is_err());

        let mut missing_minimum = serde_json::to_value(&binding.parameters[0]).unwrap();
        missing_minimum.as_object_mut().unwrap().remove("minimum");
        assert!(serde_json::from_value::<ProviderParameterSpec>(missing_minimum).is_err());

        let mut missing_cleanup = serde_json::to_value(&binding).unwrap();
        missing_cleanup
            .as_object_mut()
            .unwrap()
            .remove("cleanup_action_id");
        assert!(serde_json::from_value::<ProviderExecutionBinding>(missing_cleanup).is_err());
    }

    #[test]
    fn provider_platforms_use_wire_order_and_semver_metadata_is_strict() {
        let mut binding = test_binding();
        binding.platforms = vec![Platform::Linux, Platform::Macos, Platform::Windows];
        assert_eq!(
            provider_action_contract_digest(&binding),
            "sha256:0cbd16c3b86228a54447e7f0567983dd207aa5756e174adcfb14668033f49d7a"
        );
        binding.action_contract_digest = provider_action_contract_digest(&binding);
        binding.runtime_contract_digest = runtime_action_contract_digest(&binding);
        binding.program_digest = provider_program_digest(&binding);
        assert!(validate_provider_binding(&binding).is_ok());

        binding.platforms = vec![Platform::Windows, Platform::Linux, Platform::Macos];
        binding.action_contract_digest = provider_action_contract_digest(&binding);
        binding.runtime_contract_digest = runtime_action_contract_digest(&binding);
        binding.program_digest = provider_program_digest(&binding);
        assert!(validate_provider_binding(&binding).is_err());

        binding.platforms = vec![Platform::current()];
        binding.package_version = "1.2.3+a..b".to_string();
        binding.action_contract_digest = provider_action_contract_digest(&binding);
        binding.runtime_contract_digest = runtime_action_contract_digest(&binding);
        binding.program_digest = provider_program_digest(&binding);
        assert!(validate_provider_binding(&binding).is_err());
    }

    #[test]
    fn profile_rejects_noncanonical_or_unreferenced_artifacts() {
        let artifact = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "bluefire_provider_run_v1") (param i32 i32) (result i64)
                    (i64.const 0)))"#,
        )
        .unwrap();
        let mut binding = test_binding();
        binding.artifact_sha256 = provider_artifact_digest(&artifact);
        binding.artifact_size = artifact.len();
        binding.limits.max_module_bytes = artifact.len();
        binding.action_contract_digest = provider_action_contract_digest(&binding);
        binding.runtime_contract_digest = runtime_action_contract_digest(&binding);
        binding.program_digest = provider_program_digest(&binding);
        let mut stored = ProviderArtifact {
            artifact_sha256: binding.artifact_sha256.clone(),
            artifact_size: artifact.len(),
            artifact_hex: hex::encode(&artifact),
        };
        validate_provider_profile(&[binding.clone()], &[stored.clone()]).unwrap();

        stored.artifact_hex.make_ascii_uppercase();
        assert!(validate_provider_profile(&[binding.clone()], &[stored]).is_err());

        let extra_bytes = [0_u8; 8];
        let extra = ProviderArtifact {
            artifact_sha256: provider_artifact_digest(&extra_bytes),
            artifact_size: extra_bytes.len(),
            artifact_hex: hex::encode(extra_bytes),
        };
        assert!(validate_provider_profile(&[binding], &[extra]).is_err());
    }

    fn test_binding() -> ProviderExecutionBinding {
        let mut binding = ProviderExecutionBinding {
            schema_version: PROVIDER_EXECUTION_BINDING_SCHEMA_VERSION.to_string(),
            catalog_generation: 1,
            catalog_digest: format!("sha256:{}", "1".repeat(64)),
            logical_behavior_id: "example.provider.behavior.v1".to_string(),
            logical_action_id: "example.provider.action.v1".to_string(),
            package_id: "example.provider".to_string(),
            package_version: "1.0.0".to_string(),
            package_digest: format!("sha256:{}", "2".repeat(64)),
            content_digest: format!("sha256:{}", "3".repeat(64)),
            program_digest: format!("sha256:{}", "4".repeat(64)),
            provider_id: "example.provider.runtime.v1".to_string(),
            abi_version: PROVIDER_ABI_V1.to_string(),
            artifact_sha256: format!("sha256:{}", "5".repeat(64)),
            artifact_size: 8,
            action_contract_digest: format!("sha256:{}", "6".repeat(64)),
            runtime_contract_digest: format!("sha256:{}", "7".repeat(64)),
            provider_runtime_contract_digest: provider_runtime_contract_digest(),
            inputs: Vec::new(),
            outputs: vec![ProviderArtifactSpec {
                name: "result".to_string(),
                artifact_type: "artifact.example.provider-result.v1".to_string(),
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
            capabilities: vec![Capability::NativeExecution],
            safety_tier: SafetyTier::Safe,
            platforms: vec![Platform::current()],
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
}
