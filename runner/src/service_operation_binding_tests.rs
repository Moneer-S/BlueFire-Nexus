use super::*;
use serde_json::{json, Value};

fn document() -> Value {
    let identity = json!({
        "schema_version": "bluefire.owned-user-service.v1",
        "authorization_digest": format!("sha256:{}", "1".repeat(64)),
        "runner_profile_id": "profile.test",
        "workspace_id": "workspace.test",
        "target_scope_digest": format!("sha256:{}", "2".repeat(64)),
        "owner_uid": 1000,
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "manager_id": "1".repeat(32),
        "unit_nonce": "2".repeat(32),
        "unit_content_digest": format!("sha256:{}", "3".repeat(64)),
        "created_at": "2026-09-22T12:00:00.000001Z",
        "cleanup_due_at": "2026-09-22T13:00:00.000001Z"
    });
    json!({
        "schema_version": SCHEMA,
        "identity_digest": canonical_hash(&identity),
        "identity": identity,
        "journal_request_id": "request.test",
        "journal_revision": 1,
        "journal_record_hash": format!("sha256:{}", "4".repeat(64)),
        "operation_id": format!("op-{}", "5".repeat(32)),
        "operation": "create_unit",
        "reviewed_scope_digest": format!("sha256:{}", "6".repeat(64)),
        "manager_installation_digest": format!("sha256:{}", "7".repeat(64)),
        "payload_installation_digest": format!("sha256:{}", "8".repeat(64))
    })
}

fn parse(value: &Value) -> Result<ServiceOperationBinding, String> {
    ServiceOperationBinding::from_json(&serde_json::to_vec(value).unwrap())
}

fn identity_change(field: &str, value: Value) -> Value {
    let mut changed = document();
    changed["identity"][field] = value;
    // Do not let the outer consistency check hide identity-validation defects.
    changed["identity_digest"] = json!(canonical_hash(&changed["identity"]));
    changed
}

#[test]
fn round_trip_preserves_exact_timestamp_strings_and_canonical_digest() {
    let value = document();
    let parsed = parse(&value).unwrap();
    assert_eq!(parsed.canonical_json(), canonical_json(&value));
    assert_eq!(parsed.digest(), canonical_hash(&value));
    assert_eq!(
        ServiceOperationBinding::from_json(parsed.canonical_json().as_bytes()).unwrap(),
        parsed
    );
    assert!(parsed.canonical_json().contains("12:00:00.000001Z"));
    let mut other = value;
    other["reviewed_scope_digest"] = json!(format!("sha256:{}", "9".repeat(64)));
    assert_ne!(parse(&other).unwrap().digest(), parsed.digest());
}

#[test]
fn all_nine_operation_names_accept_only_odd_pending_revisions() {
    for operation in [
        "create_unit",
        "reload",
        "enable",
        "start",
        "stop",
        "disable",
        "remove_links",
        "remove_unit",
        "reload_after_cleanup",
    ] {
        for revision in [1, 3, 63] {
            let mut value = document();
            value["operation"] = json!(operation);
            value["journal_revision"] = json!(revision);
            assert!(parse(&value).is_ok());
        }
    }
    for invalid in [
        json!(0),
        json!(2),
        json!(64),
        json!(65),
        json!(-1),
        json!(true),
        json!(1.0),
        json!("1"),
    ] {
        let mut value = document();
        value["journal_revision"] = invalid;
        assert!(parse(&value).is_err());
    }
}

#[test]
fn reject_unknown_missing_duplicate_and_oversized_wire_data() {
    let mut value = document();
    value["command"] = json!("not admitted");
    assert!(parse(&value).is_err());
    let mut value = document();
    value
        .as_object_mut()
        .unwrap()
        .remove("payload_installation_digest");
    assert!(parse(&value).is_err());
    assert!(parse(&identity_change("command", json!("not admitted"))).is_err());
    let duplicate =
        serde_json::to_string(&document())
            .unwrap()
            .replacen("{", "{\"operation\":\"stop\",", 1);
    assert!(ServiceOperationBinding::from_json(duplicate.as_bytes()).is_err());
    let duplicate_identity = serde_json::to_string(&document())
        .unwrap()
        .replace("\"identity\":{", "\"identity\":{\"owner_uid\":1000,");
    assert!(ServiceOperationBinding::from_json(duplicate_identity.as_bytes()).is_err());
    assert!(ServiceOperationBinding::from_json(&[b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
    assert!(ServiceOperationBinding::from_json(b"{}").is_err());
    assert!(ServiceOperationBinding::from_json(b"\xff").is_err());
    assert!(ServiceOperationBinding::from_json(b"").is_err());
}

#[test]
fn decoding_uses_utf8_without_bom_and_counts_raw_input_bytes() {
    let encoded = serde_json::to_vec(&document()).unwrap();
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend(&encoded);
    assert!(ServiceOperationBinding::from_json(&bom).is_err());
    let mut utf16 = vec![0xff, 0xfe];
    for unit in std::str::from_utf8(&encoded).unwrap().encode_utf16() {
        utf16.extend(unit.to_le_bytes());
    }
    assert!(ServiceOperationBinding::from_json(&utf16).is_err());
    let mut padded = encoded;
    padded.resize(MAX_DOCUMENT_BYTES, b' ');
    assert!(ServiceOperationBinding::from_json(&padded).is_ok());
    padded.push(b' ');
    assert!(ServiceOperationBinding::from_json(&padded).is_err());
}

#[test]
fn reject_forged_binding_fields_without_exposing_caller_text() {
    for (field, invalid) in [
        ("schema_version", "other"),
        ("identity_digest", "sha256:incorrect"),
        ("journal_request_id", "request/path"),
        ("operation_id", "op-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("operation", "restart"),
        ("journal_record_hash", "not-a-digest"),
        ("reviewed_scope_digest", "not-a-digest"),
        ("manager_installation_digest", "not-a-digest"),
        ("payload_installation_digest", "not-a-digest"),
    ] {
        let mut value = document();
        value[field] = json!(invalid);
        let error = parse(&value).unwrap_err();
        assert!(!error.contains(invalid));
    }
    let mut value = document();
    value["identity_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    assert!(parse(&value).is_err());
}

#[test]
fn reject_invalid_identity_even_with_recomputed_identity_hash() {
    for (field, invalid) in [
        ("schema_version", json!("other")),
        (
            "authorization_digest",
            json!(format!("sha256:{}", "A".repeat(64))),
        ),
        ("runner_profile_id", json!("profile/path")),
        ("workspace_id", json!("x".repeat(129))),
        ("target_scope_digest", json!(false)),
        ("owner_uid", json!(0)),
        ("owner_uid", json!(u32::MAX)),
        ("owner_uid", json!(true)),
        ("owner_uid", json!(1000.0)),
        ("boot_id", json!("00000000-0000-0000-0000-000000000000")),
        ("boot_id", json!("11111111-2222-3333-4444-55555555555A")),
        ("manager_id", json!("0".repeat(32))),
        ("unit_nonce", json!("f".repeat(33))),
        ("unit_content_digest", json!("none")),
    ] {
        assert!(parse(&identity_change(field, invalid)).is_err(), "{field}");
    }
}

#[test]
fn timestamps_obey_python_utc_lexical_and_calendar_rules() {
    for invalid in [
        "2026-09-22T12:00:00+00:00",
        "2026-09-22 12:00:00Z",
        "2026-09-22T12:00:00z",
        "2026-09-22T12:00:00.Z",
        "2026-09-22T12:00:00.0000001Z",
        "2026-09-22T12:00:60Z",
        "0000-09-22T12:00:00Z",
        "2026-02-30T12:00:00Z",
        "2026-09-22T24:00:00Z",
    ] {
        assert!(
            parse(&identity_change("created_at", json!(invalid))).is_err(),
            "{invalid}"
        );
    }
    for invalid_due in [
        "2026-09-22T12:00:00.000001Z",
        "2026-09-22T11:59:59Z",
        "2026-09-22T13:00:00.000002Z",
    ] {
        assert!(parse(&identity_change("cleanup_due_at", json!(invalid_due))).is_err());
    }
    for valid_due in [
        "2026-09-22T12:00:00.000002Z",
        "2026-09-22T12:01:00Z",
        "2026-09-22T12:01:00.1Z",
    ] {
        assert!(parse(&identity_change("cleanup_due_at", json!(valid_due))).is_ok());
    }
}

#[test]
fn shared_python_rust_fixture_preserves_canonical_digests_and_refusals() {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/service_operation_binding_v1.json"
    ))
    .unwrap();
    assert_eq!(
        fixtures["schema_version"],
        "bluefire.service-operation-binding-fixtures.v1"
    );
    for case in fixtures["valid"].as_array().unwrap() {
        let parsed =
            parse(&case["document"]).unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
        assert_eq!(
            parsed.digest(),
            case["canonical_sha256"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(parsed.canonical_json(), canonical_json(&case["document"]));
    }
    for case in fixtures["invalid"].as_array().unwrap() {
        assert!(parse(&case["document"]).is_err(), "{}", case["name"]);
    }
    for case in fixtures["invalid_json"].as_array().unwrap() {
        assert!(
            ServiceOperationBinding::from_json(case["json"].as_str().unwrap().as_bytes()).is_err(),
            "{}",
            case["name"]
        );
    }
    for case in fixtures["invalid_bytes"].as_array().unwrap() {
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        assert!(
            ServiceOperationBinding::from_json(&bytes).is_err(),
            "{}",
            case["name"]
        );
    }
}
