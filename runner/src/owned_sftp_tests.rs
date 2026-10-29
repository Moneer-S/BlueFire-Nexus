//! Authored contract vectors only; no installed OpenSSH, server or credentials.

use super::*;
use crate::contract::ReviewedOperationIdentity;

fn reference(label: &str) -> String {
    format!("sha256:{}", sha256_hex(label.as_bytes()))
}

pub(super) fn fixture(path: &str) -> VerifiedSftpAdmission {
    let references = CurrentReferences {
        endpoint_binding_ref: reference("endpoint"),
        server_preparation_ref: reference("server"),
        resource_ref: reference(path),
        resource_generation: reference("generation"),
        source_content_sha256: reference("generated-public-data"),
        host_key_ref: reference("host-key"),
        reader_identity_ref: reference("reader"),
        access_observation_ref: reference("fresh-access"),
        session_prerequisite_ref: reference("new-session"),
    };
    let record = |tool: &str, path: &str| NativeToolInstallation {
        schema_version: crate::native_tool_installations::SCHEMA.into(),
        adapter_id: METHOD.into(),
        adapter_version: "0.1.0".into(),
        adapter_contract_digest: CONTRACT.into(),
        tool_id: tool.into(),
        tool_version: "10.6p1".into(),
        platform: "linux".into(),
        architecture: std::env::consts::ARCH.into(),
        content_sha256: reference(path),
        size_bytes: 1234,
        installation_location: path.into(),
    };
    let now = Instant::now();
    let deadline = now + Duration::from_secs(2);
    let observer_readiness = ObserverReadinessLease {
        admission_ref: reference("observer-admission"),
        readiness_ref: reference("observer-readiness"),
        session_ref: references.session_prerequisite_ref.clone(),
        scope_digest: crate::canonical::canonical_hash(&serde_json::to_value(&references).unwrap()),
        bundle_digest: reference("synthetic-not-approved-bundle"),
        ready_at: now,
        expires_at: deadline + Duration::from_secs(1),
    };
    VerifiedSftpAdmission {
        references,
        bundle_digest: reference("synthetic-not-approved-bundle"),
        operation: ReviewedOperationIdentity {
            step_id: "retrieve".into(),
            behavior_id: METHOD.into(),
            action_id: METHOD.into(),
            execution_binding_digest: None,
        },
        authorization_digest: reference("authorization"),
        request_hash: "b".repeat(64),
        runner_profile_id: "profile:test".into(),
        workspace_id: reference("workspace"),
        remote_path: path.into(),
        expected_size: b"generated-public-data".len() as u64,
        port: 22022,
        reader: "bfreader_0123456789abcdef".into(),
        host_ed25519: [7; 32],
        fixture_private_key: format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", // pragma: allowlist secret -- authored non-key format fixture
            "x".repeat(100)
        )
        .into_bytes(),
        installations: [
            record("openssh.sftp.v1", "/usr/bin/sftp"),
            record("openssh.ssh.v1", "/usr/bin/ssh"),
        ],
        deadline,
        observer_readiness,
    }
}

#[test]
fn separate_observer_lease_must_bind_scope_session_and_the_whole_deadline() {
    let mut admission = fixture("/owned/reports/reconciliation.jsonl");
    let request = request(&admission);
    admission.observer_readiness.session_ref = reference("other-observation-session");
    assert_eq!(admission.check_request(&request), Err(Issue::Prerequisite));
    admission.observer_readiness.session_ref = request.references.session_prerequisite_ref.clone();
    admission.observer_readiness.expires_at = Instant::now();
    assert_eq!(admission.check_request(&request), Err(Issue::Prerequisite));
    admission.observer_readiness.expires_at = admission.deadline + Duration::from_secs(1);
    admission.observer_readiness.scope_digest = reference("other-resource-generation");
    assert_eq!(admission.check_request(&request), Err(Issue::Prerequisite));
}

fn request(admission: &VerifiedSftpAdmission) -> Request {
    Request {
        references: admission.references.clone(),
        bundle_digest: admission.bundle_digest.clone(),
        expected_size: admission.expected_size,
    }
}

#[test]
fn arbitrary_resource_names_use_the_same_single_file_method() {
    for path in [
        "/owned/fixtures/original.jsonl",
        "/owned/staging/copy.jsonl",
        "/owned/reports/reconciliation.jsonl",
    ] {
        let admission = fixture(path);
        assert_eq!(admission.check_request(&request(&admission)), Ok(()));
        assert_eq!(admission.recognize_build(), Err(Issue::UnreviewedBuild));
    }
}

#[test]
fn every_mutable_reference_is_required_and_cannot_be_historical() {
    let admission = fixture("/owned/reports/reconciliation.jsonl");
    let value = serde_json::to_value(request(&admission)).unwrap();
    for key in value["references"].as_object().unwrap().keys() {
        let mut changed = value.clone();
        changed["references"][key] = serde_json::json!(reference("old-generation-or-session"));
        let changed: Request = serde_json::from_value(changed).unwrap();
        assert_eq!(admission.check_request(&changed), Err(Issue::Prerequisite));
        let mut absent = value.clone();
        absent["references"].as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<Request>(absent).is_err());
    }
}

#[test]
fn request_has_no_path_host_command_config_privilege_or_helper_controls() {
    let admission = fixture("/owned/reports/reconciliation.jsonl");
    for field in [
        "path",
        "host",
        "argv",
        "config",
        "script",
        "remote_command",
        "privilege",
        "transport",
        "source",
    ] {
        let mut value = serde_json::to_value(request(&admission)).unwrap();
        value[field] = serde_json::json!("unreviewed");
        assert!(serde_json::from_value::<Request>(value).is_err());
    }
}

#[test]
fn prepared_resource_path_cannot_escape_or_add_batch_syntax() {
    for path in [
        "/etc/shadow",
        "/owned/../etc/shadow",
        "/owned/a/./b",
        "/owned//a",
        "/owned/a/",
        "/owned/*",
        "/owned/a b",
        "/owned/a\n!sh",
        "/owned/a;id",
        "/owned/a\\b",
        "/owned/-x",
    ] {
        // A leading '-' in a component is harmless after the absolute prefix;
        // every other vector either escapes the root or changes batch syntax.
        let admission = fixture(path);
        assert_eq!(
            admission.check_request(&request(&admission)).is_ok(),
            path == "/owned/-x"
        );
    }
}

#[test]
fn role_swap_version_change_and_invalid_hash_are_never_build_admission() {
    let mut admission = fixture("/owned/a/data.jsonl");
    admission.installations.swap(0, 1);
    assert_eq!(admission.recognize_build(), Err(Issue::Installation));
    admission.installations.swap(0, 1);
    admission.installations[1].tool_version = "9.9p1".into();
    assert_eq!(admission.recognize_build(), Err(Issue::UnreviewedBuild));
    admission.installations[1].tool_version = "10.6p1".into();
    admission.installations[0].content_sha256 = "invalid".into();
    assert_eq!(admission.recognize_build(), Err(Issue::Installation));
}

#[test]
fn admission_is_not_minted_by_a_matching_request_or_action_context() {
    assert!(REVIEWED_BUNDLES.is_empty());
    let admission = fixture("/owned/a/data.jsonl");
    assert_eq!(
        admission.check_scope(&"c".repeat(64), "profile:test", &admission.workspace_id),
        Err(Issue::AdmissionUnresolved)
    );
    assert_eq!(
        admission.check_scope(
            &admission.request_hash,
            "profile:other",
            &admission.workspace_id
        ),
        Err(Issue::AdmissionUnresolved)
    );
    let cancelled = AtomicBool::new(false);
    assert_eq!(
        retrieve(&admission, &request(&admission), &cancelled).err(),
        Some(Issue::UnreviewedBuild)
    );
    cancelled.store(true, Ordering::Release);
    assert_eq!(
        retrieve(&admission, &request(&admission), &cancelled).err(),
        Some(Issue::Cancelled)
    );
    let mut operation = admission.operation.clone();
    operation.step_id = "other-step".into();
    assert_eq!(
        admission.check_operation(&operation, &admission.authorization_digest),
        Err(Issue::AdmissionUnresolved)
    );
    assert_eq!(
        admission.check_operation(&admission.operation, &reference("other-review")),
        Err(Issue::AdmissionUnresolved)
    );
}

#[test]
fn source_content_and_size_both_bind_actual_downloaded_bytes() {
    let admission = fixture("/owned/a/data.jsonl");
    assert_eq!(verify_bytes(&admission, b"generated-public-data"), Ok(()));
    assert_eq!(
        verify_bytes(&admission, b"generated-public-datb"),
        Err(Issue::ContentMismatch)
    );
    assert_eq!(
        verify_bytes(&admission, b"partial"),
        Err(Issue::ContentMismatch)
    );
    let mut oversized = request(&admission);
    oversized.expected_size = MAX_BYTES as u64 + 1;
    assert_eq!(
        admission.check_request(&oversized),
        Err(Issue::Prerequisite)
    );
}

#[test]
fn known_hosts_uses_only_one_bound_ed25519_key_and_exact_loopback_port() {
    for (bytes, expected) in [
        (b"".as_slice(), ""),
        (b"f".as_slice(), "Zg=="),
        (b"fo".as_slice(), "Zm8="),
        (b"foo".as_slice(), "Zm9v"),
    ] {
        assert_eq!(base64(bytes), expected);
    }
    let line = String::from_utf8(known_host(&fixture("/owned/a/data.jsonl"))).unwrap();
    let fields: Vec<_> = line.split_whitespace().collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "[127.0.0.1]:22022");
    assert_eq!(fields[1], "ssh-ed25519");
    assert_eq!(fields[2].len(), 68);
    assert!(line.ends_with('\n'));
}
