//! Explicit reviewed runtime requests, not inspected installations or peer authority.
//!
//! The first v2 contract has no supported production runtime. In particular, a
//! root-owned ELF or a caller-chosen digest cannot select a broker implementation.
//! Exact provider bytes and dependency/configuration provenance must be reviewed
//! before implementing acquisition. Existing v1 admission remains unchanged.

use std::collections::BTreeSet;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use super::REFUSAL;
use crate::canonical::canonical_hash;
use crate::native_tool_installations::NativeToolInstallation;

const SCHEMA: &str = "bluefire.owned-service-observation-runtime.v1";
const SUPPORTED_CONTRACTS: &[&str] = &[];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationReference {
    installation_id: String,
    path: String,
    digest: String,
    content_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeInstallations {
    broker: InstallationReference,
    systemd_daemon: InstallationReference,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDocument {
    schema_version: String,
    contract_digest: String,
    system_broker_uid: u32,
    installations: RuntimeInstallations,
}

/// Only the complete scope's authenticated binding admits this metadata. No
/// public constructor or path from these hashes to an observation exists.
pub(super) struct RequestedObservationRuntime {
    digest: String,
    contract_digest: String,
}

impl RequestedObservationRuntime {
    pub(super) fn matches(&self, value: &Value) -> bool {
        self.digest == canonical_hash(value)
    }

    pub(super) fn require_supported(&self, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline
            || !SUPPORTED_CONTRACTS.contains(&self.contract_digest.as_str())
        {
            return Err(REFUSAL.into());
        }
        // Adding a digest alone must never enable a runtime. This remains closed
        // until exact installation inspection, closure and peer verification exist.
        Err(REFUSAL.into())
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn select_role(
    reference: &InstallationReference,
    records: &[NativeToolInstallation],
    role: &str,
) -> Result<(), String> {
    let matches: Vec<_> = records
        .iter()
        .filter(|record| {
            reference.installation_id == record.tool_id
                && reference.path == record.installation_location
                && reference.digest == record.digest()
                && reference.content_sha256 == record.content_sha256
        })
        .collect();
    let [record] = matches.as_slice() else {
        return Err(REFUSAL.into());
    };
    if record.adapter_id != format!("owned.service.observation.{role}.v1")
        || record.tool_id != format!("owned.service.observation.{role}.binary.v1")
        || record.adapter_version != "1.0.0"
        || record.platform != "linux"
        || record.architecture != "x86_64"
    {
        return Err(REFUSAL.into());
    }
    Ok(())
}

pub(super) fn parse(value: &Value, profile: &Value) -> Result<RequestedObservationRuntime, String> {
    let document: RuntimeDocument = serde_json::from_value(value.clone()).map_err(|_| REFUSAL)?;
    if document.schema_version != SCHEMA
        || !digest(&document.contract_digest)
        || document.system_broker_uid == u32::MAX
    {
        return Err(REFUSAL.into());
    }
    let records: Vec<NativeToolInstallation> =
        serde_json::from_value(profile["native_tool_installations"].clone())
            .map_err(|_| REFUSAL)?;
    if records.len() > 16 {
        return Err(REFUSAL.into());
    }
    let mut adapters = BTreeSet::new();
    for record in &records {
        record.validate().map_err(|_| REFUSAL)?;
        if !adapters.insert(&record.adapter_id) {
            return Err(REFUSAL.into());
        }
    }
    select_role(&document.installations.broker, &records, "broker")?;
    select_role(&document.installations.systemd_daemon, &records, "systemd")?;
    Ok(RequestedObservationRuntime {
        digest: canonical_hash(value),
        contract_digest: document.contract_digest,
    })
}

#[cfg(test)]
#[path = "service_observation_runtime_tests.rs"]
mod tests;
