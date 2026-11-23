//! Authored metadata cases. These do not inspect or run a service installation.

use super::*;
use crate::service_admission::{wire, VerifiedServiceAdmission};
use serde_json::json;
use std::time::Duration;

fn installation(role: &str) -> Value {
    json!({
        "schema_version": "bluefire.native-tool-installation.v1",
        "adapter_id": format!("owned.service.observation.{role}.v1"),
        "adapter_version": "1.0.0",
        "adapter_contract_digest": format!("sha256:{}", "a".repeat(64)),
        "tool_id": format!("owned.service.observation.{role}.binary.v1"),
        "tool_version": "1.0.0", "platform": "linux", "architecture": "x86_64",
        "content_sha256": format!("sha256:{}", if role == "broker" { "b" } else { "c" }.repeat(64)),
        "size_bytes": 4096, "installation_location": format!("/opt/bluefire/authored-{role}")
    })
}

fn reference(record: &Value) -> Value {
    json!({
        "installation_id": record["tool_id"], "path": record["installation_location"],
        "digest": canonical_hash(record), "content_sha256": record["content_sha256"]
    })
}

fn request() -> (Value, Value) {
    let broker = installation("broker");
    let daemon = installation("systemd");
    let runtime = json!({
        "schema_version": SCHEMA,
        "contract_digest": format!("sha256:{}", "d".repeat(64)),
        "system_broker_uid": 103,
        "installations": {"broker": reference(&broker), "systemd_daemon": reference(&daemon)}
    });
    (
        runtime,
        json!({"native_tool_installations": [broker, daemon]}),
    )
}

#[test]
fn valid_metadata_does_not_support_a_runtime_or_create_peer_authority() {
    let (runtime, profile) = request();
    let requested = parse(&runtime, &profile).unwrap();
    assert!(requested.matches(&runtime));
    assert!(SUPPORTED_CONTRACTS.is_empty());
    for deadline in [Instant::now(), Instant::now() + Duration::from_secs(1)] {
        assert!(requested.require_supported(deadline).is_err());
    }
    let mut changed = runtime.clone();
    changed["system_broker_uid"] = json!(104);
    assert!(!requested.matches(&changed));
}

#[test]
fn broker_uid_requires_an_explicit_bounded_integer() {
    let (runtime, profile) = request();
    for uid in [json!(0), json!(u32::MAX - 1)] {
        let mut value = runtime.clone();
        value["system_broker_uid"] = uid;
        assert!(parse(&value, &profile).is_ok());
    }
    for uid in [
        Value::Null,
        json!(true),
        json!(-1),
        json!(u32::MAX),
        json!("103"),
        json!(103.5),
    ] {
        let mut value = runtime.clone();
        value["system_broker_uid"] = uid;
        assert!(parse(&value, &profile).is_err());
    }
    let mut value = runtime;
    value.as_object_mut().unwrap().remove("system_broker_uid");
    assert!(parse(&value, &profile).is_err());
}

#[test]
fn runtime_has_no_caller_selected_endpoint_process_or_closure_list() {
    let (runtime, profile) = request();
    for key in [
        "endpoint",
        "pid",
        "unique_name",
        "closure",
        "fallback",
        "duration",
    ] {
        let mut value = runtime.clone();
        value[key] = json!("authored");
        assert!(parse(&value, &profile).is_err());
    }
    for version in ["", "bluefire.owned-service-observation-runtime.v2"] {
        let mut value = runtime.clone();
        value["schema_version"] = json!(version);
        assert!(parse(&value, &profile).is_err());
    }
    for value in ["sha256:", "SHA256:0000", "unknown"] {
        let mut changed = runtime.clone();
        changed["contract_digest"] = json!(value);
        assert!(parse(&changed, &profile).is_err());
    }
}

#[test]
fn runtime_references_require_exact_distinct_role_records() {
    let (runtime, profile) = request();
    for role in ["broker", "systemd_daemon"] {
        for field in ["installation_id", "path", "digest", "content_sha256"] {
            let mut value = runtime.clone();
            value["installations"][role][field] = json!("changed");
            assert!(parse(&value, &profile).is_err());
        }
        let mut value = runtime.clone();
        value["installations"].as_object_mut().unwrap().remove(role);
        assert!(parse(&value, &profile).is_err());
    }
    let mut swapped = runtime.clone();
    swapped["installations"]["broker"] = runtime["installations"]["systemd_daemon"].clone();
    swapped["installations"]["systemd_daemon"] = runtime["installations"]["broker"].clone();
    assert!(parse(&swapped, &profile).is_err());
    let mut duplicate = profile.clone();
    duplicate["native_tool_installations"]
        .as_array_mut()
        .unwrap()
        .push(profile["native_tool_installations"][0].clone());
    assert!(parse(&runtime, &duplicate).is_err());
    for count in [0, 1, 17] {
        let records = vec![profile["native_tool_installations"][0].clone(); count];
        assert!(parse(&runtime, &json!({"native_tool_installations": records})).is_err());
    }
}

#[test]
fn rebinding_a_record_does_not_allow_wrong_adapter_platform_or_architecture() {
    let (runtime, profile) = request();
    for (field, replacement) in [
        ("adapter_id", "owned.service.manager.v1"),
        ("tool_id", "owned.service.manager.binary.v1"),
        ("adapter_version", "2.0.0"),
        ("platform", "windows"),
        ("architecture", "aarch64"),
    ] {
        let mut changed_profile = profile.clone();
        changed_profile["native_tool_installations"][0][field] = json!(replacement);
        let mut changed_runtime = runtime.clone();
        changed_runtime["installations"]["broker"] =
            reference(&changed_profile["native_tool_installations"][0]);
        assert!(parse(&changed_runtime, &changed_profile).is_err());
    }
}

fn legacy() -> Value {
    serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/owned_service_admission_v1.json"
    ))
    .unwrap()
}

fn validate(value: &Value) -> Result<VerifiedServiceAdmission, String> {
    let mut issuer = value["admission"]["issuer"].clone();
    issuer.as_object_mut().unwrap().remove("server_instance_id");
    wire::validate(
        &value["admission"],
        &issuer,
        &value["manifest"],
        &value["profile"],
        chrono::DateTime::parse_from_rfc3339(value["now"].as_str().unwrap()).unwrap(),
    )
}

fn rehash_grant(value: &mut Value) {
    value["admission"]["grant"]["scope_digest"] =
        json!(canonical_hash(&value["admission"]["grant"]["scope"]));
    value["admission"]["grant_digest"] = json!(canonical_hash(&value["admission"]["grant"]));
}

fn v2() -> Value {
    // Generated by Python's actual configured-profile, sealing and grant-minting
    // pipeline. Keep its hashes unchanged so this tests cross-language binding.
    serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/owned_service_admission_v2.json"
    ))
    .unwrap()
}

#[test]
fn legacy_remains_exact_and_v2_metadata_cannot_obtain_runtime_support() {
    assert!(validate(&legacy()).unwrap().observation_runtime.is_none());
    let value = v2();
    let admission = validate(&value).unwrap();
    let requested = admission.observation_runtime.as_ref().unwrap();
    assert!(requested.matches(&value["admission"]["grant"]["scope"]["observation_runtime"]));
    assert!(requested
        .require_supported(Instant::now() + Duration::from_secs(1))
        .is_err());
}

#[test]
fn mixed_version_families_and_v1_runtime_additions_are_refused() {
    for admission in [1, 2] {
        for grant in [1, 2] {
            for scope in [1, 2] {
                if [admission, grant, scope] == [2, 2, 2] {
                    continue;
                }
                let mut value = v2();
                value["admission"]["schema_version"] = json!(format!(
                    "bluefire.owned-user-service-admission.v{admission}"
                ));
                value["admission"]["grant"]["schema_version"] =
                    json!(format!("bluefire.owned-user-service-grant.v{grant}"));
                value["admission"]["grant"]["scope"]["schema_version"] =
                    json!(format!("bluefire.owned-user-service-scope.v{scope}"));
                rehash_grant(&mut value);
                assert!(validate(&value).is_err());
            }
        }
    }
}

#[test]
fn changed_runtime_cannot_reuse_the_reviewed_journal_binding() {
    for field in ["system_broker_uid", "contract_digest"] {
        let mut value = v2();
        assert!(validate(&value).is_ok());
        value["admission"]["grant"]["scope"]["observation_runtime"][field] =
            if field == "system_broker_uid" {
                json!(104)
            } else {
                json!(format!("sha256:{}", "e".repeat(64)))
            };
        // Updating self-authored hashes cannot update the captured journal intent.
        rehash_grant(&mut value);
        assert!(validate(&value).is_err());
    }
}

#[test]
fn sealed_profile_drift_cannot_reuse_v2_admission() {
    let mut value = v2();
    value["profile"]["native_tool_installations"][2]["installation_location"] =
        json!("/opt/bluefire/changed");
    assert!(validate(&value).is_err());
}
