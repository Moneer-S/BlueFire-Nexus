//! Pure consistency tests. These neither grant sends nor contact any service.

use bluefire_runner::s3_access_binding::{S3WorkerBinding, MAX_DOCUMENT_BYTES};
use bluefire_runner::s3_access_send::S3SendPreview;
use chrono::DateTime;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn corpus() -> Value {
    serde_json::from_str(include_str!("fixtures/s3_access_binding_v1.json")).unwrap()
}

fn request(operation: &str) -> Value {
    corpus()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["request"]["operation"] == operation)
        .unwrap()["request"]
        .clone()
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn hash(value: &Value) -> String {
    // All corpus keys and strings are ASCII; serde's sorted map matches canonical JSON.
    format!("sha256:{}", hex::encode(Sha256::digest(bytes(value))))
}

fn rebind(value: &mut Value) {
    if !value["policy_change"].is_null() {
        value["policy_change"]["before_digest"] = json!(hash(&value["policy_change"]["before"]));
        value["policy_change"]["after_digest"] = json!(hash(&value["policy_change"]["after"]));
        value["scope"]["policy"]["baseline_digest"] =
            value["policy_change"]["before_digest"].clone();
    }
    value["scope_digest"] = json!(hash(&value["scope"]));
    if !value["policy_change"].is_null() {
        value["policy_change"]["scope_digest"] = value["scope_digest"].clone();
    }
}

#[test]
fn shared_python_corpus_has_exact_canonical_hash_plan_and_resources() {
    let corpus = corpus();
    assert_eq!(
        corpus["schema_version"],
        "bluefire.s3-native-binding-fixtures.v1"
    );
    for case in corpus["cases"].as_array().unwrap() {
        let binding = S3WorkerBinding::from_json(&bytes(&case["request"])).unwrap();
        assert_eq!(binding.digest(), case["request_digest"].as_str().unwrap());
        assert_eq!(binding.canonical_json().as_bytes(), bytes(&case["request"]));
        assert_eq!(
            serde_json::to_value(binding.operation_plan()).unwrap(),
            case["plan"]
        );
        for (index, resource) in case["resources"].as_array().unwrap().iter().enumerate() {
            assert_eq!(&binding.planned_resource(index + 1).unwrap(), resource);
            assert_eq!(
                binding.planned_send(index + 1).unwrap(),
                case["sends"][index]
            );
        }
        assert!(binding.planned_resource(0).is_err());
        assert!(binding
            .planned_resource(binding.operation_plan().len() + 1)
            .is_err());
        if let Some(expected) = case["policy_payload_digest"].as_str() {
            assert_eq!(binding.policy_payload_digest().unwrap(), expected);
        } else {
            assert!(binding.policy_payload_digest().is_err());
        }
        binding
            .assert_current(DateTime::parse_from_rfc3339(corpus["now"].as_str().unwrap()).unwrap())
            .unwrap();
    }
}

#[test]
fn closed_fields_and_explicit_nulls_are_required() {
    for pointer in [
        "",
        "/scope",
        "/scope/roles",
        "/scope/objects/0",
        "/scope/policy",
        "/scope/limits",
        "/policy_change",
        "/policy_change/before",
        "/policy_change/before/Statement/0",
        "/policy_change/before/Statement/0/Principal",
    ] {
        let mut value = request("apply_policy");
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(true));
        rebind(&mut value);
        assert!(
            S3WorkerBinding::from_json(&bytes(&value)).is_err(),
            "{pointer}"
        );
    }
    for key in ["policy_change", "exclusive_writer_digest"] {
        let mut value = request("inspect_policy");
        value.as_object_mut().unwrap().remove(key);
        assert!(S3WorkerBinding::from_json(&bytes(&value)).is_err(), "{key}");
    }
}

#[test]
fn nested_duplicate_keys_are_rejected_before_hashing() {
    let original = String::from_utf8(bytes(&request("apply_policy"))).unwrap();
    for field in [
        "launch_id",
        "scope",
        "controller",
        "size_bytes",
        "api_calls",
        "Version",
        "AWS",
        "Sid",
        "Action",
        "Resource",
    ] {
        let marker = format!("\"{field}\":");
        let repeated = original.replacen(&marker, &format!("{marker}null,{marker}"), 1);
        assert_ne!(original, repeated);
        assert!(
            S3WorkerBinding::from_json(repeated.as_bytes()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn numeric_positions_do_not_coerce_boolean_float_negative_or_overflow() {
    for pointer in [
        "/max_sends",
        "/scope/limits/api_calls",
        "/scope/limits/session_seconds",
        "/scope/objects/0/size_bytes",
    ] {
        for invalid in [
            json!(true),
            json!(1.0),
            json!(-1),
            json!(0),
            json!(u64::MAX),
            json!("1"),
        ] {
            let mut value = request("apply_policy");
            *value.pointer_mut(pointer).unwrap() = invalid;
            rebind(&mut value);
            assert!(
                S3WorkerBinding::from_json(&bytes(&value)).is_err(),
                "{pointer}"
            );
        }
    }
}

#[test]
fn exact_scope_refuses_foreign_resource_principal_region_and_expansion() {
    for (pointer, invalid) in [
        ("/scope/schema_version", json!("unknown")),
        ("/scope/scope_id", json!("s3-ABC")),
        ("/scope/account_id", json!("12345678901x")),
        ("/scope/region", json!("cn-north-1")),
        ("/scope/region", json!("us-east-01")),
        ("/scope/region", json!("us-gov-west-1")),
        (
            "/scope/roles/probe",
            json!("arn:aws:iam::999999999999:role/probe"),
        ),
        (
            "/scope/roles/probe",
            json!("arn:aws:iam::123456789012:role/path/probe"),
        ),
        ("/scope/bucket", json!("other.example.com")),
        ("/scope/bucket", json!("-invalid")),
        ("/scope/bucket", json!("bucket--x-s3")),
        ("/scope/prefix", json!("bluefire/other/")),
        ("/scope/objects/0/key", json!("other")),
        ("/scope/objects/1/purpose", json!("primary")),
        ("/scope/objects/0/sha256", json!("sha256:bad")),
        ("/scope/policy/probe_sid", json!("Other")),
        ("/scope/ownership_receipt_digest", json!("bad")),
        ("/scope/created_at", json!("2026-10-09T00:00:00+00:00")),
        ("/scope/expires_at", json!("2027-10-09T00:00:00Z")),
    ] {
        let mut value = request("apply_policy");
        *value.pointer_mut(pointer).unwrap() = invalid;
        rebind(&mut value);
        assert!(
            S3WorkerBinding::from_json(&bytes(&value)).is_err(),
            "{pointer}"
        );
    }
    let mut value = request("probe_read");
    value["scope"]["roles"]["probe"] = value["scope"]["roles"]["controller"].clone();
    rebind(&mut value);
    assert!(S3WorkerBinding::from_json(&bytes(&value)).is_err());
}

#[test]
fn policy_edit_cannot_change_unrelated_statement_or_reader_routes() {
    for (pointer, invalid) in [
        ("/policy_change/before/Statement/0/Action", json!("s3:*")),
        (
            "/policy_change/before/Statement/0/Principal/AWS",
            json!("*"),
        ),
        (
            "/policy_change/before/Statement/0/Resource",
            json!("arn:aws:s3:::other/*"),
        ),
        ("/policy_change/before/Statement/1/Effect", json!("Deny")),
        ("/policy_change/after/Statement/0/Effect", json!("Deny")),
        ("/policy_change/removed_sid", json!("PreservedRead")),
        ("/policy_change/after/Version", json!("2008-10-17")),
    ] {
        let mut value = request("apply_policy");
        *value.pointer_mut(pointer).unwrap() = invalid;
        rebind(&mut value);
        assert!(
            S3WorkerBinding::from_json(&bytes(&value)).is_err(),
            "{pointer}"
        );
    }
    for source in ["before", "after"] {
        let mut value = request("apply_policy");
        let duplicate = value["policy_change"][source]["Statement"][0].clone();
        value["policy_change"][source]["Statement"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        rebind(&mut value);
        assert!(S3WorkerBinding::from_json(&bytes(&value)).is_err());
    }
    let mut value = request("apply_policy");
    value["policy_change"]["after"]["Statement"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    rebind(&mut value);
    assert!(S3WorkerBinding::from_json(&bytes(&value)).is_err());
}

#[test]
fn request_identifiers_mutation_binding_and_drift_are_closed() {
    for (pointer, invalid) in [
        ("/schema_version", json!("other")),
        ("/launch_id", json!("A".repeat(64))),
        ("/request_id", json!("short")),
        ("/worker_generation", json!("bad")),
        ("/runtime_digest", json!("bad")),
        ("/scope_digest", json!(format!("sha256:{}", "0".repeat(64)))),
        ("/operation", json!("DeleteBucket")),
        ("/exclusive_writer_digest", Value::Null),
        ("/policy_change", Value::Null),
        ("/deadline", json!("2026-10-09T00:00:00Z")),
        ("/deadline", json!("2026-10-09T00:00:60Z")),
        ("/deadline", json!("0000-10-09T00:00:30Z")),
        ("/deadline", json!("2026-10-09T00:00:30.000000Z")),
    ] {
        let mut value = request("apply_policy");
        *value.pointer_mut(pointer).unwrap() = invalid;
        assert!(
            S3WorkerBinding::from_json(&bytes(&value)).is_err(),
            "{pointer}"
        );
    }
    let mut value = request("apply_policy");
    value["operation"] = json!("inspect_policy");
    value["max_sends"] = json!(2);
    assert!(S3WorkerBinding::from_json(&bytes(&value)).is_err());
}

#[test]
fn injected_clock_checks_scope_and_request_deadline() {
    let binding = S3WorkerBinding::from_json(&bytes(&request("probe_read"))).unwrap();
    for invalid in [
        "2026-10-08T23:59:59Z",
        "2026-10-09T00:00:30Z",
        "2026-10-10T00:00:00Z",
    ] {
        assert!(binding
            .assert_current(DateTime::parse_from_rfc3339(invalid).unwrap())
            .is_err());
    }
    binding
        .assert_current(DateTime::parse_from_rfc3339("2026-10-09T00:00:29.999999Z").unwrap())
        .unwrap();
}

#[test]
fn bounded_parser_refuses_non_objects_trailing_values_and_oversize() {
    for bytes in [
        b"null".as_slice(),
        b"[]",
        b"{} {}",
        b"",
        b"{\"max_sends\":NaN}",
    ] {
        assert!(S3WorkerBinding::from_json(bytes).is_err());
    }
    assert!(S3WorkerBinding::from_json(&vec![b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
}

fn frame_bytes(value: &Value) -> Vec<u8> {
    let mut result = bytes(value);
    result.push(b'\n');
    result
}

fn rehash_frame(frame: &mut Value) {
    let mut preview = frame.clone();
    preview.as_object_mut().unwrap().remove("send_digest");
    frame["send_digest"] = json!(hash(&preview));
}

#[test]
fn shared_send_frames_match_without_issuing_any_permit() {
    for case in corpus()["cases"].as_array().unwrap() {
        let binding = S3WorkerBinding::from_json(&bytes(&case["request"])).unwrap();
        for (index, frame) in case["send_frames"].as_array().unwrap().iter().enumerate() {
            let preview =
                S3SendPreview::from_frame(&binding, &frame_bytes(frame), (index + 1) as u64)
                    .unwrap();
            assert_eq!(preview.sequence(), (index + 1) as u64);
            assert_eq!(preview.digest(), frame["send_digest"].as_str().unwrap());
            assert_eq!(preview.canonical_json().as_bytes(), bytes(frame));
            assert_eq!(
                preview.is_write(),
                frame["send"]["operation"] == "PutBucketPolicy"
            );
        }
    }
}

#[test]
fn send_preview_rejects_endpoint_resource_payload_or_sequence_changes() {
    let fixture = corpus();
    let case = &fixture["cases"][3];
    let binding = S3WorkerBinding::from_json(&bytes(&case["request"])).unwrap();
    for (pointer, changed) in [
        ("/kind", json!("permit")),
        (
            "/request_digest",
            json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("/sequence", json!(true)),
        ("/sequence", json!(4.0)),
        ("/sequence", json!(3)),
        ("/send/service", json!("iam")),
        ("/send/operation", json!("PutObject")),
        ("/send/role", json!("controller")),
        ("/send/method", json!("PUT")),
        (
            "/send/host",
            json!("s3.us-east-1.amazonaws.com.evil.example"),
        ),
        ("/send/host", json!("s3.us-east-1.amazonaws.com:443")),
        ("/send/resource/key", json!("unrelated")),
        ("/send/resource/bucket", json!("other")),
        (
            "/send/payload_digest",
            json!(format!("sha256:{}", "0".repeat(64))),
        ),
    ] {
        let mut frame = case["send_frames"][3].clone();
        *frame.pointer_mut(pointer).unwrap() = changed;
        rehash_frame(&mut frame);
        assert!(
            S3SendPreview::from_frame(&binding, &frame_bytes(&frame), 4).is_err(),
            "{pointer}"
        );
    }
    let frame = &case["send_frames"][3];
    assert!(S3SendPreview::from_frame(&binding, &frame_bytes(frame), 3).is_err());
    assert!(S3SendPreview::from_frame(&binding, &frame_bytes(frame), 0).is_err());
    assert!(S3SendPreview::from_frame(&binding, &frame_bytes(frame), u64::MAX).is_err());
}

#[test]
fn send_frames_reject_unknown_duplicate_fields_bad_hashes_and_bad_framing() {
    let fixture = corpus();
    let case = &fixture["cases"][4];
    let binding = S3WorkerBinding::from_json(&bytes(&case["request"])).unwrap();
    for pointer in ["", "/send", "/send/resource"] {
        let mut frame = case["send_frames"][1].clone();
        frame
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(true));
        rehash_frame(&mut frame);
        assert!(S3SendPreview::from_frame(&binding, &frame_bytes(&frame), 2).is_err());
    }
    let frame = &case["send_frames"][1];
    let raw = String::from_utf8(frame_bytes(frame)).unwrap();
    for field in [
        "kind",
        "sequence",
        "host",
        "resource",
        "role_arn",
        "session_name",
    ] {
        let marker = format!("\"{field}\":");
        let repeated = raw.replacen(&marker, &format!("{marker}null,{marker}"), 1);
        assert_ne!(repeated, raw);
        assert!(
            S3SendPreview::from_frame(&binding, repeated.as_bytes(), 2).is_err(),
            "{field}"
        );
    }
    for payload in [
        bytes(frame),
        Vec::new(),
        vec![b' '; 4097],
        format!("{raw}\n").into_bytes(),
    ] {
        assert!(S3SendPreview::from_frame(&binding, &payload, 2).is_err());
    }
    let mut changed = frame.clone();
    changed["send_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    assert!(S3SendPreview::from_frame(&binding, &frame_bytes(&changed), 2).is_err());
}
