//! Pure authority-shape tests. These never launch or impersonate a probe identity.

use super::*;

fn binding() -> Value {
    let generation = "a".repeat(32);
    let acl =
        canonical_hash(&json!({"system.posix_acl_access":null,"system.posix_acl_default":null}));
    json!({
        "schema_version":"bluefire.file-access-execution.v1",
        "enrollment_id":format!("file-enrollment-{}", "b".repeat(32)),
        "enrollment_digest":format!("sha256:{}", "c".repeat(64)),
        "resource_id":format!("file-resource-{}", "d".repeat(32)),
        "resource_generation":format!("file-generation-{generation}"),
        "expires_at_ms":crate::contract::utc_now().timestamp_millis()+90_000,
        "control_revision":1,"mode":"0640",
        "resource":{"root":format!("/run/bluefire-file-access/data/{generation}"),
            "root_device":3,"root_inode":101,"parent_device":3,"parent_inode":102,
            "device":3,"inode":103,"owner_uid":1000,"group_gid":1002,
            "sha256":format!("sha256:{}", "e".repeat(64)),"size":100,"record_count":6,
            "acl_digest":acl,"parent_acl_digest":acl},
        "worker":{"socket_path":format!("/run/bluefire-file-access/control/{generation}/probe.sock"),
            "uid":1002,"gid":1002,"pid":23,"start_ticks":42,"launch_nonce":"f".repeat(64),
            "namespaces":{"mnt":"mnt:[123]","net":"net:[123]","pid":"pid:[123]","ipc":"ipc:[123]"}}
    })
}

#[test]
fn exact_file_access_binding_round_trips_without_effects() {
    let value = binding();
    let parsed: FileAccessBinding = serde_json::from_value(value.clone()).unwrap();
    parsed.current().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

#[test]
fn file_access_unknown_null_and_identity_extensions_fail_closed() {
    let mut unknown = binding();
    unknown["command"] = json!("anything");
    assert!(serde_json::from_value::<FileAccessBinding>(unknown).is_err());
    assert!(serde_json::from_value::<FileAccessBinding>(Value::Null).is_err());
    for (path, value) in [
        ("/mode", json!("0666")),
        ("/resource/root", json!("/etc")),
        ("/resource/device", json!(4)),
        ("/resource/owner_uid", json!(1002)),
        ("/resource/group_gid", json!(1000)),
        ("/resource/size", json!(1_048_577)),
        (
            "/resource/acl_digest",
            json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("/worker/uid", json!(1001)),
        ("/worker/socket_path", json!("/tmp/probe.sock")),
        ("/worker/namespaces/mnt", json!("mnt:[0]")),
    ] {
        let mut changed = binding();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            serde_json::from_value::<FileAccessBinding>(changed)
                .unwrap()
                .validate()
                .is_err(),
            "{path}"
        );
    }
}

#[test]
fn file_access_time_bound_never_renews_enrollment() {
    let mut value = binding();
    value["expires_at_ms"] = json!(1);
    assert!(serde_json::from_value::<FileAccessBinding>(value.clone())
        .unwrap()
        .current()
        .is_err());
    value["expires_at_ms"] = json!(crate::contract::utc_now().timestamp_millis() + 1_800_000);
    assert!(serde_json::from_value::<FileAccessBinding>(value)
        .unwrap()
        .current()
        .is_err());
}
