//! Unregistered service-operation consistency metadata; never execution authority.
//!
//! A valid hash proves neither approval, provenance, resource ownership nor that
//! a journal record exists. No runner dispatch path consumes this prerequisite.

use chrono::{DateTime, Duration, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_hash, canonical_json};

pub const SCHEMA: &str = "bluefire.service-operation-binding.v1";
pub const MAX_DOCUMENT_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceOperationBinding {
    canonical: String,
    digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    schema_version: String,
    identity: WireIdentity,
    identity_digest: String,
    journal_request_id: String,
    journal_revision: u8,
    journal_record_hash: String,
    operation_id: String,
    operation: String,
    reviewed_scope_digest: String,
    manager_installation_digest: String,
    payload_installation_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireIdentity {
    schema_version: String,
    authorization_digest: String,
    runner_profile_id: String,
    workspace_id: String,
    target_scope_digest: String,
    owner_uid: u32,
    boot_id: String,
    manager_id: String,
    unit_nonce: String,
    unit_content_digest: String,
    created_at: String,
    cleanup_due_at: String,
}

fn require(valid: bool, message: &'static str) -> Result<(), String> {
    if valid {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|suffix| lower_hex(suffix, 64))
}

fn identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn nonce(value: &str) -> bool {
    lower_hex(value, 32) && value.bytes().any(|byte| byte != b'0')
}

fn utc_time(value: &str) -> Result<DateTime<FixedOffset>, String> {
    let bytes = value.as_bytes();
    let valid_length = bytes.len() == 20 || (22..=27).contains(&bytes.len());
    require(valid_length, "service identity timestamp is invalid")?;
    for (index, byte) in bytes.iter().enumerate() {
        let expected = match index {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            index if index == bytes.len() - 1 => Some(b'Z'),
            19 => Some(b'.'),
            _ => None,
        };
        require(
            expected.map_or_else(|| byte.is_ascii_digit(), |expected| *byte == expected),
            "service identity timestamp is invalid",
        )?;
    }
    // chrono admits leap seconds and year zero; Python datetime does not.
    require(
        &value[..4] != "0000" && &value[17..19] < "60",
        "service identity timestamp is invalid",
    )?;
    DateTime::parse_from_rfc3339(value)
        .map_err(|_| "service identity timestamp is invalid".to_string())
}

impl WireIdentity {
    fn validate(&self) -> Result<(), String> {
        require(
            self.schema_version == "bluefire.owned-user-service.v1",
            "service identity schema is unsupported",
        )?;
        require(
            [
                &self.authorization_digest,
                &self.target_scope_digest,
                &self.unit_content_digest,
            ]
            .iter()
            .all(|value| digest(value)),
            "service identity digest is invalid",
        )?;
        require(
            identifier(&self.runner_profile_id) && identifier(&self.workspace_id),
            "service identity identifier is invalid",
        )?;
        require(
            self.owner_uid > 0 && self.owner_uid < u32::MAX,
            "service identity requires a non-root owner UID",
        )?;
        require(
            nonce(&self.manager_id) && nonce(&self.unit_nonce),
            "service identity nonce is invalid",
        )?;
        let boot: Vec<_> = self.boot_id.split('-').collect();
        require(
            boot.len() == 5
                && boot
                    .iter()
                    .zip([8, 4, 4, 4, 12])
                    .all(|(part, length)| lower_hex(part, length))
                && self
                    .boot_id
                    .bytes()
                    .any(|byte| byte != b'0' && byte != b'-'),
            "service identity boot ID is invalid",
        )?;
        let lifetime = utc_time(&self.cleanup_due_at)? - utc_time(&self.created_at)?;
        require(
            lifetime > Duration::zero() && lifetime <= Duration::hours(1),
            "service identity lifetime is outside its bound",
        )
    }
}

impl ServiceOperationBinding {
    /// Validate bounded wire data and retain its canonical representation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        require(
            !bytes.is_empty() && bytes.len() <= MAX_DOCUMENT_BYTES,
            "service operation document exceeds its byte bound",
        )?;
        // Typed deserialization rejects duplicate fields, booleans/floats in
        // integer positions, and unrecognized fields before hashing.
        let wire: WireBinding = serde_json::from_slice(bytes)
            .map_err(|_| "service operation document shape is invalid".to_string())?;
        require(
            wire.schema_version == SCHEMA,
            "service operation schema is unsupported",
        )?;
        wire.identity.validate()?;
        let identity = serde_json::to_value(&wire.identity)
            .map_err(|_| "service identity cannot be encoded".to_string())?;
        require(
            wire.identity_digest == canonical_hash(&identity),
            "service operation identity digest mismatch",
        )?;
        require(
            identifier(&wire.journal_request_id),
            "service operation journal request is invalid",
        )?;
        require(
            (1..=63).contains(&wire.journal_revision) && wire.journal_revision % 2 == 1,
            "service operation requires an odd pending revision",
        )?;
        require(
            [
                &wire.journal_record_hash,
                &wire.reviewed_scope_digest,
                &wire.manager_installation_digest,
                &wire.payload_installation_digest,
            ]
            .iter()
            .all(|value| digest(value)),
            "service operation digest is invalid",
        )?;
        require(
            wire.operation_id
                .strip_prefix("op-")
                .is_some_and(|value| lower_hex(value, 32)),
            "service operation identifier is invalid",
        )?;
        require(
            [
                "create_unit",
                "reload",
                "enable",
                "start",
                "stop",
                "disable",
                "remove_links",
                "remove_unit",
                "reload_after_cleanup",
            ]
            .contains(&wire.operation.as_str()),
            "service operation is not recognized",
        )?;
        let value = serde_json::to_value(&wire)
            .map_err(|_| "service operation cannot be encoded".to_string())?;
        Ok(Self {
            canonical: canonical_json(&value),
            digest: canonical_hash(&value),
        })
    }

    pub fn canonical_json(&self) -> &str {
        &self.canonical
    }

    /// A consistency digest only, never proof of approval or resource ownership.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[cfg(test)]
#[path = "service_operation_binding_tests.rs"]
mod tests;
