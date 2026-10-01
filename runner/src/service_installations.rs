//! Closed, read-only installation identities for protected service admission.
//! These roles are not registered actions or ToolAdapterContract v1 methods.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::canonical::canonical_hash;
use crate::native_tool_installations::{NativeToolBinding, NativeToolInstallation};
#[cfg(target_os = "linux")]
use crate::native_tool_inspection::{
    inspect_protected_record, CurrentExecutable, InspectedNativeTool,
};
#[cfg(target_os = "linux")]
use std::time::Instant;

const REFUSAL: &str = "protected owned-service installation was refused";
const MANAGER_VERSION: &str = "255.4-1ubuntu8.12";
const MANAGER_SHA256: &str =
    "sha256:d03995d5d2ce6a5dd1822854f80c40cdf3d92c7a008179d89e80e5ffcd1a9aa2";
const MANAGER_SIZE: u64 = 1_501_304;
const MANAGER_BINDING: NativeToolBinding = NativeToolBinding {
    adapter_id: "owned.service.manager.v1",
    adapter_version: "1.0.0",
    adapter_contract_digest:
        "sha256:54f7fb7bd236d5c28f79903ca6b9efb01bd2144c3f8793ad0d22f776894fa6a7",
    tool_id: "owned.service.manager.binary.v1",
};
const PAYLOAD_BINDING: NativeToolBinding = NativeToolBinding {
    adapter_id: "owned.service.payload.v1",
    adapter_version: "1.0.0",
    adapter_contract_digest:
        "sha256:60bb8f6cd6e6b796bd1a7039b1e38c793faeb89f088302730f05da6f89d965e7",
    tool_id: "owned.service.payload.binary.v1",
};

#[derive(Clone, Copy)]
enum Role {
    Manager,
    Payload,
}

impl Role {
    fn binding(self) -> NativeToolBinding {
        match self {
            Self::Manager => MANAGER_BINDING,
            Self::Payload => PAYLOAD_BINDING,
        }
    }

    /// Closed review metadata. Its own resulting digest is deliberately absent.
    fn contract(self) -> Value {
        let binding = self.binding();
        let (role, architectures, identity) = match self {
            Self::Manager => (
                "manager",
                json!(["x86_64"]),
                json!({
                    "project": "systemd", "version": MANAGER_VERSION,
                    "content_sha256": MANAGER_SHA256, "size_bytes": MANAGER_SIZE,
                    "license": "LGPL-2.1-or-later",
                    "license_reference": "https://github.com/systemd/systemd-stable/blob/v255.4/LICENSE.LGPL2.1",
                    "build_reference": "https://launchpad.net/ubuntu/+source/systemd/255.4-1ubuntu8.12/+build/31559902",
                    "package_sha256": "sha256:f4bfc1162fe45590c5422935323e324616aba72fd42771a0b4beb5d74e4d2689",
                    "source_reference": "https://launchpad.net/ubuntu/+source/systemd/255.4-1ubuntu8.12",
                    "upstream_source_sha256": "sha256:96e75bd08c57ad401677456fb88ef54a9f05bb1695693013bc6ecce839640fd5",
                    "packaging_source_sha256": "sha256:74c143cbd1e1c3aea57726171cb0810534bc957d863a31aff91aa956a1ea76c9"
                }),
            ),
            Self::Payload => (
                "payload",
                json!(["x86_64", "aarch64"]),
                json!({
                    "project": "bluefire-runner", "version": env!("CARGO_PKG_VERSION"),
                    "authority": "authenticated-current-runner-bytes-and-size",
                    "entrypoint": "owned-service-payload",
                    "duration_seconds": {"minimum": 1, "maximum": crate::service_payload::MAX_DURATION_SECONDS}
                }),
            ),
        };
        json!({
            "schema_version": "bluefire.owned-service-installation-contract.v1",
            "role": role, "adapter_id": binding.adapter_id,
            "adapter_version": binding.adapter_version, "tool_id": binding.tool_id,
            "platform": "linux", "architectures": architectures,
            "inspection": {
                "path": "root-owned-nofollow-components",
                "executable": "bounded-elf-without-special-bits-or-capabilities",
                "identity": "exact-version-size-sha256",
                "recheck": "retained-handles-and-shared-monotonic-deadline"
            },
            "dispatch": "unregistered", "identity": identity
        })
    }

    fn validate(
        self,
        installation: &NativeToolInstallation,
        current_runner: (&str, u64),
    ) -> Result<(), String> {
        let binding = self.binding();
        if canonical_hash(&self.contract()) != binding.adapter_contract_digest {
            return Err(REFUSAL.into());
        }
        binding
            .check_binding(installation, "linux", std::env::consts::ARCH)
            .map_err(|_| REFUSAL)?;
        let recognized = match self {
            Self::Manager => {
                installation.architecture == "x86_64"
                    && installation.tool_version == MANAGER_VERSION
                    && installation.content_sha256 == MANAGER_SHA256
                    && installation.size_bytes == MANAGER_SIZE
            }
            Self::Payload => {
                installation.tool_version == env!("CARGO_PKG_VERSION")
                    && (installation.content_sha256.as_str(), installation.size_bytes)
                        == current_runner
            }
        };
        if !recognized {
            return Err(REFUSAL.into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationReference {
    installation_id: String,
    path: String,
    digest: String,
    content_sha256: String,
}

impl InstallationReference {
    fn matches(&self, record: &NativeToolInstallation) -> bool {
        self.installation_id == record.tool_id
            && self.path == record.installation_location
            && self.digest == record.digest()
            && self.content_sha256 == record.content_sha256
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredInstallations {
    manager: InstallationReference,
    payload: InstallationReference,
}

fn select(
    scope: &Value,
    profile: &Value,
    current_runner: (&str, u64),
) -> Result<[NativeToolInstallation; 2], String> {
    let required: RequiredInstallations =
        serde_json::from_value(scope["installations"].clone()).map_err(|_| REFUSAL)?;
    let records: Vec<NativeToolInstallation> =
        serde_json::from_value(profile["native_tool_installations"].clone())
            .map_err(|_| REFUSAL)?;
    if records.len() > 16 {
        return Err(REFUSAL.into());
    }
    let mut adapters = std::collections::BTreeSet::new();
    for record in &records {
        record.validate().map_err(|_| REFUSAL)?;
        if !adapters.insert(&record.adapter_id) {
            return Err(REFUSAL.into());
        }
    }
    let select_role = |role: Role, required: &InstallationReference| {
        let matches: Vec<_> = records.iter().filter(|record| required.matches(record)).collect();
        let [record] = matches.as_slice() else {
            return Err(REFUSAL.to_string());
        };
        role.validate(record, current_runner)?;
        Ok((**record).clone())
    };
    Ok([
        select_role(Role::Manager, &required.manager)?,
        select_role(Role::Payload, &required.payload)?,
    ])
}

#[cfg(target_os = "linux")]
pub(crate) fn inspect(
    scope: &Value,
    profile: &Value,
    current_runner: &CurrentExecutable,
    deadline: Instant,
) -> Result<[InspectedNativeTool; 2], String> {
    let [manager, payload] = select(scope, profile, current_runner.observed_identity())?;
    let manager = inspect_protected_record(&manager, deadline).map_err(|_| REFUSAL)?;
    let payload = inspect_protected_record(&payload, deadline).map_err(|_| REFUSAL)?;
    manager.recheck().map_err(|_| REFUSAL)?;
    payload.recheck().map_err(|_| REFUSAL)?;
    current_runner.recheck().map_err(|_| REFUSAL)?;
    Ok([manager, payload])
}

#[cfg(test)]
#[path = "service_installations_tests.rs"]
mod tests;
