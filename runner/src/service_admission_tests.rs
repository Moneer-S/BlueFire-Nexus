use super::*;
use crate::canonical::canonical_hash;
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/owned_service_admission_v1.json"
    ))
    .unwrap()
}
fn check(value: &Value) -> Result<VerifiedServiceAdmission, String> {
    let mut issuer = value["admission"]["issuer"].clone();
    issuer.as_object_mut().unwrap().remove("server_instance_id");
    wire::validate(
        &value["admission"],
        &issuer,
        &value["manifest"],
        &value["profile"],
        DateTime::parse_from_rfc3339(value["now"].as_str().unwrap()).unwrap(),
    )
}
fn rehash(value: &mut Value) {
    value["admission"]["grant"]["scope_digest"] =
        json!(canonical_hash(&value["admission"]["grant"]["scope"]));
    value["admission"]["grant_digest"] = json!(canonical_hash(&value["admission"]["grant"]));
}

fn reseal_request(value: &mut Value) {
    let mut manifest: crate::contract::ExecutionManifest =
        serde_json::from_value(value["manifest"].clone()).unwrap();
    crate::contract::seal_manifest(&mut manifest);
    value["manifest"] = serde_json::to_value(manifest).unwrap();
    value["admission"]["grant"]["manifest_request_hash"] =
        value["manifest"]["request_hash"].clone();
    value["admission"]["grant"]["execution"]["manifest_digest"] =
        json!(canonical_hash(&value["manifest"]));
    value["admission"]["grant"]["execution"]["task_id"] = json!(format!(
        "execute-{}",
        &canonical_hash(&json!({"manifest": value["manifest"], "profile": value["profile"]}))[7..]
    ));
    rehash(value);
}

#[test]
fn python_golden_admission_binds_exact_scope_claim_task_and_operation() {
    let value = fixture();
    let admission = check(&value).unwrap();
    assert_eq!(
        admission.scope_digest(),
        value["admission"]["grant"]["scope_digest"]
    );
    assert_eq!(
        admission.operation_binding_digest(),
        admission.operation_binding().digest()
    );
    assert_eq!(
        admission.task_id(),
        value["admission"]["grant"]["execution"]["task_id"]
    );
    assert!(admission.created_at() < admission.setup_expires_at());
    assert!(admission.setup_expires_at() <= admission.cleanup_expires_at());
}

#[test]
fn issuer_restart_does_not_change_stable_enrollment_identity() {
    let value = fixture();
    let baseline = check(&value).unwrap();
    let mut changed = value.clone();
    changed["admission"]["issuer"]["server_instance_id"] = json!("restarted-host");
    assert_eq!(
        check(&changed).unwrap().enrollment_digest(),
        baseline.enrollment_digest()
    );
    let mut expected = value["admission"]["issuer"].clone();
    expected
        .as_object_mut()
        .unwrap()
        .remove("server_instance_id");
    expected["client_id"] = json!("different-client");
    assert!(wire::validate(
        &value["admission"],
        &expected,
        &value["manifest"],
        &value["profile"],
        DateTime::parse_from_rfc3339(value["now"].as_str().unwrap()).unwrap()
    )
    .is_err());
}

#[test]
fn every_changed_request_or_closed_scope_is_refused_even_when_rehashed() {
    let original = fixture();
    let mutations = [
        ("/manifest/params/duration_seconds", json!(121)),
        ("/profile/sandbox_root", json!("/different-workspace")),
        (
            "/admission/grant/execution/task_id",
            json!(format!("execute-{}", "a".repeat(64))),
        ),
        ("/admission/grant/claim/state_digest", json!("not-a-digest")),
        ("/admission/grant/scope/target/owner_uid", json!(0)),
        (
            "/admission/grant/scope/target/boot_id",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
        (
            "/admission/grant/scope/target/manager_instance_id",
            json!("a".repeat(32)),
        ),
        ("/admission/grant/scope/unit/nonce", json!("0".repeat(32))),
        (
            "/admission/grant/scope/template/content_digest",
            json!(format!("sha256:{}", "a".repeat(64))),
        ),
        (
            "/admission/grant/scope/installations/payload/path",
            json!("/usr/bin/a;bad"),
        ),
        ("/admission/grant/scope/limits/max_processes", json!(17)),
        ("/admission/grant/scope/effects/setup", json!(["arbitrary"])),
        (
            "/admission/grant/operation_binding/operation_id",
            json!(format!("op-{}", "a".repeat(32))),
        ),
    ];
    for (pointer, replacement) in mutations {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        rehash(&mut value);
        assert!(check(&value).is_err(), "accepted mutated {pointer}");
    }
    let mut value = original;
    value["admission"]["grant"]["scope"]["command"] = json!("forbidden");
    rehash(&mut value);
    assert!(check(&value).is_err());
}

#[test]
fn setup_expiry_and_future_claim_are_not_renewed_by_launch() {
    let mut value = fixture();
    value["now"] = value["admission"]["grant"]["scope"]["setup_expires_at"].clone();
    assert!(check(&value).is_err());
    value = fixture();
    value["now"] = json!("2025-01-01T00:00:00Z");
    assert!(check(&value).is_err());
}

#[test]
fn claimed_approval_must_have_been_valid_at_consumption() {
    for operation in ["create_unit", "stop"] {
        let mut baseline = fixture();
        if operation == "stop" {
            baseline["admission"]["grant"]["operation_binding"]["operation"] = json!(operation);
            baseline["admission"]["grant"]["operation_binding"]["journal_revision"] = json!(3);
            baseline["admission"]["grant"]["execution"]["operation_binding_digest"] = json!(
                canonical_hash(&baseline["admission"]["grant"]["operation_binding"])
            );
            baseline["manifest"]["requested_at"] = json!("2026-01-01T12:11:00Z");
            baseline["manifest"]["expires_at"] = json!("2026-01-01T12:13:00Z");
            baseline["now"] = json!("2026-01-01T12:12:00Z");
            reseal_request(&mut baseline);
        }
        assert!(check(&baseline).is_ok());
        for (field, time) in [
            ("consumed_at", "2026-01-01T11:59:59Z"),
            ("consumed_at", "2026-01-01T12:05:00Z"),
            ("approval_expires_at", "2026-01-01T12:01:00Z"),
        ] {
            let mut value = baseline.clone();
            value["admission"]["grant"]["claim"][field] = json!(time);
            rehash(&mut value);
            assert!(check(&value).is_err());
        }
    }
}

#[test]
fn consumed_claim_keeps_microsecond_ordering_and_original_expiry() {
    let mut value = fixture();
    value["now"] = json!("2026-01-01T12:03:00.500000Z");
    value["admission"]["grant"]["claim"]["consumed_at"] = json!("2026-01-01T12:03:00.499999Z");
    rehash(&mut value);
    assert!(check(&value).is_ok());
    value["admission"]["grant"]["claim"]["consumed_at"] = json!("2026-01-01T12:03:00.500001Z");
    rehash(&mut value);
    assert!(check(&value).is_err());

    value["admission"]["grant"]["claim"]["consumed_at"] = json!("2026-01-01T12:01:00.000001Z");
    value["admission"]["grant"]["claim"]["approval_expires_at"] =
        json!("2026-01-01T12:03:00.500001Z");
    rehash(&mut value);
    assert!(check(&value).is_ok());
    value["admission"]["grant"]["claim"]["approval_expires_at"] = value["now"].clone();
    rehash(&mut value);
    assert!(check(&value).is_err());

    for invalid in [
        "2026-01-01T12:01:00.0000001Z",
        "2026-01-01T12:01:00.Z",
        "2026-01-01T12:01:00.1+00:00",
        "2026-01-01T12:01:60.1Z",
    ] {
        let mut invalid_value = fixture();
        invalid_value["admission"]["grant"]["claim"]["consumed_at"] = json!(invalid);
        rehash(&mut invalid_value);
        assert!(check(&invalid_value).is_err());
    }
}

#[test]
fn task_bound_manifest_cannot_expand_reviewed_operation_timeout() {
    let mut value = fixture();
    reseal_request(&mut value);
    assert!(check(&value).is_ok());
    value["manifest"]["limits"]["timeout_ms"] = json!(30_001);
    reseal_request(&mut value);
    assert!(check(&value).is_err());
}

#[test]
fn public_runner_cannot_dispatch_service_through_ordinary_registry() {
    let value = fixture();
    let manifest = serde_json::from_value(value["manifest"].clone()).unwrap();
    let profile = serde_json::from_value(value["profile"].clone()).unwrap();
    let result = crate::Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, crate::TaskStatus::Refused);
    assert_eq!(result.error.unwrap().code, "service_admission_required");
    assert!(result.receipt_ids.is_empty() && result.cleanup.is_none());
}

#[test]
fn ordinary_action_alias_cannot_smuggle_service_opcode() {
    let value = fixture();
    let mut manifest: crate::contract::ExecutionManifest =
        serde_json::from_value(value["manifest"].clone()).unwrap();
    manifest.action_id = "sandbox.fixture.create.v1".into();
    let digest = format!("sha256:{}", "a".repeat(64));
    manifest.execution_binding = Some(
        serde_json::from_value(json!({
            "schema_version": "bluefire.execution-binding.v1", "catalog_generation": 1,
            "catalog_digest": digest, "logical_behavior_id": manifest.behavior_id,
            "logical_action_id": manifest.action_id, "package_id": "package.test.v1",
            "package_version": "1.0.0", "package_digest": digest,
            "content_digest": digest, "program_digest": digest,
            "runner_opcode": SERVICE_ACTION_ID, "opcode_contract_digest": digest, "constants": {}
        }))
        .unwrap(),
    );
    crate::contract::seal_manifest(&mut manifest);
    let profile = serde_json::from_value(value["profile"].clone()).unwrap();
    let result = crate::Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, crate::TaskStatus::Refused);
    assert_eq!(result.error.unwrap().code, "service_admission_required");
    assert!(result.receipt_ids.is_empty() && result.cleanup.is_none());
}
