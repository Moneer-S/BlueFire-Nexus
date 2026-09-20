//! Read-only installation inspection through the fixed runner boundary.

use std::time::Duration;

use serde_json::{json, Value};

use crate::actions::find_action;
use crate::native_tool_installations::{
    validate_location, validate_tool_version, NativeToolInstallation, MAX_SIZE_BYTES,
};

const CANDIDATE_SCHEMA: &str = "bluefire.native-tool-candidate.v1";
const CANDIDATE_RESULT_SCHEMA: &str = "bluefire.native-tool-candidate-inspection.v1";

pub fn inspect_installation(installation: &NativeToolInstallation) -> Value {
    let mut response = json!({
        "schema_version": "bluefire.native-tool-inspection.v1",
        "installation_digest": installation.digest(),
        "status": "unavailable", "code": "binding_mismatch",
        "content_sha256": null, "size_bytes": null,
        "platform": crate::contract::Platform::current(),
        "architecture": std::env::consts::ARCH,
    });
    if installation.validate().is_err() {
        response["code"] = json!("invalid_installation");
        return response;
    }
    let Some(binding) =
        find_action(&installation.adapter_id).and_then(|action| action.native_tool_binding())
    else {
        return response;
    };
    if binding
        .check_binding(installation, "linux", std::env::consts::ARCH)
        .is_err()
    {
        return response;
    }
    match crate::native_tool_inspection::inspect(installation, Duration::from_secs(5)) {
        Ok(inspected) => {
            response["installation_digest"] = json!(inspected.installation_digest);
            response["status"] = json!("ready");
            response["code"] = json!("verified");
            response["content_sha256"] = json!(inspected.content_sha256);
            response["size_bytes"] = json!(inspected.size_bytes);
        }
        Err(error) => response["code"] = json!(error.code),
    }
    response
}

pub fn inspect_candidate(candidate: &Value) -> Value {
    let platform = match crate::contract::Platform::current() {
        crate::contract::Platform::Linux => "linux",
        crate::contract::Platform::Windows => "windows",
        crate::contract::Platform::Macos => "macos",
    };
    let architecture = std::env::consts::ARCH.to_string();
    let unavailable = |code: &str| {
        json!({
            "schema_version": CANDIDATE_RESULT_SCHEMA,
            "candidate_digest": crate::canonical::canonical_hash(candidate),
            "status": "unavailable", "code": code, "installation": null,
            "platform": platform, "architecture": architecture,
        })
    };
    let Some(object) = candidate.as_object() else {
        return unavailable("invalid_installation");
    };
    if object.len() != 4 || candidate.get("schema_version") != Some(&json!(CANDIDATE_SCHEMA)) {
        return unavailable("invalid_installation");
    }
    let Some(action_id) = candidate.get("action_id").and_then(Value::as_str) else {
        return unavailable("invalid_installation");
    };
    let Some(location) = candidate
        .get("installation_location")
        .and_then(Value::as_str)
    else {
        return unavailable("invalid_installation");
    };
    let Some(tool_version) = candidate.get("tool_version").and_then(Value::as_str) else {
        return unavailable("invalid_installation");
    };
    if !crate::reviewed_native_builds::supports(action_id)
        || validate_tool_version(tool_version).is_err()
        || validate_location(location).is_err()
    {
        return unavailable("invalid_installation");
    }
    let Some(binding) = find_action(action_id).and_then(|action| action.native_tool_binding())
    else {
        return unavailable("binding_mismatch");
    };
    if platform != "linux" {
        return unavailable("unsupported_platform");
    }
    if binding.adapter_id != action_id {
        return unavailable("binding_mismatch");
    }
    let candidate_digest = crate::canonical::canonical_hash(candidate);
    match crate::native_tool_inspection::inspect_candidate(
        location,
        &architecture,
        candidate_digest.clone(),
        Duration::from_secs(5),
    ) {
        Ok(inspected) => {
            let (content_sha256, size_bytes) = inspected.observed_identity();
            let installation = NativeToolInstallation {
                schema_version: crate::native_tool_installations::SCHEMA.into(),
                adapter_id: binding.adapter_id.into(),
                adapter_version: binding.adapter_version.into(),
                adapter_contract_digest: binding.adapter_contract_digest.into(),
                tool_id: binding.tool_id.into(),
                tool_version: tool_version.into(),
                platform: "linux".into(),
                architecture: architecture.clone(),
                content_sha256: content_sha256.into(),
                size_bytes,
                installation_location: location.into(),
            };
            if installation.validate().is_err() || size_bytes == 0 || size_bytes > MAX_SIZE_BYTES {
                return unavailable("invalid_installation");
            }
            if let Err(error) = crate::reviewed_native_builds::verify(&installation) {
                return unavailable(error.code);
            }
            json!({
                "schema_version": CANDIDATE_RESULT_SCHEMA,
                "candidate_digest": candidate_digest,
                "status": "ready", "code": "verified",
                "installation": installation,
                "platform": platform, "architecture": architecture,
            })
        }
        Err(error) => unavailable(error.code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_ordinary_action_cannot_inspect_a_tool_by_attaching_metadata() {
        let installation = NativeToolInstallation {
            schema_version: crate::native_tool_installations::SCHEMA.into(),
            adapter_id: "sandbox.fixture.transform.v1".into(),
            adapter_version: "1.0.0".into(),
            adapter_contract_digest: format!("sha256:{}", "a".repeat(64)),
            tool_id: "gnu.coreutils.chmod.v1".into(),
            tool_version: "9.4".into(),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            content_sha256: format!("sha256:{}", "b".repeat(64)),
            size_bytes: 1234,
            installation_location: "/unavailable/reviewed/chmod".into(),
        };
        let response = inspect_installation(&installation);
        assert_eq!(response["code"], "binding_mismatch");
        assert_eq!(response["status"], "unavailable");
        assert!(response["content_sha256"].is_null());
        assert_eq!(response["installation_digest"], installation.digest());
        assert!(!response.to_string().contains("/unavailable"));
    }

    #[test]
    fn candidate_unknown_action_and_extra_fields_fail_closed() {
        let unknown = json!({
            "schema_version": CANDIDATE_SCHEMA,
            "action_id": "sandbox.fixture.transform.v1",
            "installation_location": "/usr/bin/chmod",
            "tool_version": "9.5"
        });
        assert_eq!(inspect_candidate(&unknown)["status"], "unavailable");
        assert_eq!(inspect_candidate(&unknown)["code"], "invalid_installation");
        let extra = json!({
            "schema_version": CANDIDATE_SCHEMA,
            "action_id": "sandbox.permission.chmod.v1",
            "installation_location": "/usr/bin/chmod",
            "tool_version": "9.5",
            "content_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        });
        assert_eq!(inspect_candidate(&extra)["code"], "invalid_installation");
    }

    #[cfg(target_os = "linux")]
    fn refuse_relabelled_tool(action_id: &str, location: &str, version: &str) {
        // Read-only regression: never invoke the system tool or create effects.
        let candidate = json!({
            "schema_version": CANDIDATE_SCHEMA,
            "action_id": action_id,
            "installation_location": location,
            "tool_version": version
        });
        let response = inspect_candidate(&candidate);
        assert_eq!(response["status"], "unavailable");
        assert!(response["installation"].is_null());
        // Minimal images may lack this protected path; either way it is never
        // admitted. Normal Linux CI exercises the independent identity refusal.
        assert!(matches!(
            response["code"].as_str(),
            Some(
                "unrecognized_tool_build"
                    | "inspection_unavailable"
                    | "unsafe_installation"
                    | "unsupported_binary"
                    | "capabilities_unknown"
            )
        ));
        if let Ok(observed) = crate::native_tool_inspection::inspect_candidate(
            location,
            std::env::consts::ARCH,
            crate::canonical::canonical_hash(&candidate),
            Duration::from_secs(5),
        ) {
            assert_eq!(response["code"], "unrecognized_tool_build");
            let binding = find_action(action_id)
                .unwrap()
                .native_tool_binding()
                .unwrap();
            let record = NativeToolInstallation {
                schema_version: crate::native_tool_installations::SCHEMA.into(),
                adapter_id: binding.adapter_id.into(),
                adapter_version: binding.adapter_version.into(),
                adapter_contract_digest: binding.adapter_contract_digest.into(),
                tool_id: binding.tool_id.into(),
                tool_version: version.into(),
                platform: "linux".into(),
                architecture: std::env::consts::ARCH.into(),
                content_sha256: observed.content_sha256,
                size_bytes: observed.size_bytes,
                installation_location: location.into(),
            };
            // A forged saved record with the correct observed digest is refused
            // by both setup inspection and the exact inspector used at dispatch.
            assert_eq!(
                inspect_installation(&record)["code"],
                "unrecognized_tool_build"
            );
            assert_eq!(
                crate::native_tool_inspection::inspect(&record, Duration::from_secs(5))
                    .unwrap_err()
                    .code,
                "unrecognized_tool_build"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protected_non_chmod_elf_cannot_become_a_chmod_installation() {
        refuse_relabelled_tool(
            "sandbox.permission.chmod.v1",
            "/usr/bin/touch",
            "9.4-3ubuntu6.1",
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gzip_setup_cannot_admit_chmod_or_another_protected_elf() {
        for location in ["/usr/bin/chmod", "/usr/bin/touch"] {
            refuse_relabelled_tool(
                "sandbox.collection.atomic-gzip.v1",
                location,
                "1.12-1ubuntu3.2",
            );
        }
    }

    #[test]
    fn candidate_unavailable_never_invents_installation_identity() {
        let candidate = json!({
            "schema_version": CANDIDATE_SCHEMA,
            "action_id": "sandbox.permission.chmod.v1",
            "installation_location": "/unavailable/reviewed/chmod",
            "tool_version": "9.5"
        });
        let response = inspect_candidate(&candidate);
        assert_eq!(response["status"], "unavailable");
        assert!(response["installation"].is_null());
        assert_eq!(
            response["candidate_digest"],
            crate::canonical::canonical_hash(&candidate)
        );
    }

    #[test]
    fn candidate_reuses_strict_version_and_location_bounds() {
        for (field, value) in [
            ("tool_version", json!("-9.5")),
            ("tool_version", json!(".9.5")),
            ("installation_location", json!("/usr/bin/")),
            ("installation_location", json!("/usr/../bin/chmod")),
            (
                "installation_location",
                json!(format!("/{}", "x".repeat(4096))),
            ),
        ] {
            let mut candidate = json!({
                "schema_version": CANDIDATE_SCHEMA,
                "action_id": "sandbox.permission.chmod.v1",
                "installation_location": "/usr/bin/chmod",
                "tool_version": "9.5"
            });
            candidate[field] = value;
            assert_eq!(
                inspect_candidate(&candidate)["code"],
                "invalid_installation"
            );
        }
    }
}
