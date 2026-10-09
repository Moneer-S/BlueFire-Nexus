//! Temporary controller credentials from an authenticated inherited descriptor.
//! Never included in Debug, task output, ledger entries, argv, or environment.

use chrono::{DateTime, FixedOffset};
use serde_json::{json, Value};

use crate::canonical::{canonical_hash, canonical_json};
use crate::s3_access_scope::{require, Checked};

pub(crate) struct WorkerSecret {
    document: Value,
}

impl WorkerSecret {
    pub(crate) fn from_bytes(
        bytes: &[u8],
        expected_digest: &str,
        now: DateTime<FixedOffset>,
        deadline: DateTime<FixedOffset>,
    ) -> Checked<Self> {
        require(bytes.len() <= 16 * 1024)?;
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "private S3 material unavailable")?;
        require(
            canonical_json(&value).as_bytes() == bytes && canonical_hash(&value) == expected_digest,
        )?;
        let object = value.as_object().ok_or("private S3 material unavailable")?;
        require(
            object.len() == 4
                && ["access_key", "secret_key", "token", "expires_at"]
                    .iter()
                    .all(|name| object.contains_key(*name)),
        )?;
        for (name, maximum) in [
            ("access_key", 128),
            ("secret_key", 128),
            ("token", 12 * 1024),
        ] {
            let text = value[name]
                .as_str()
                .ok_or("private S3 material unavailable")?;
            require(
                (16..=maximum).contains(&text.len())
                    && text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
            )?;
        }
        let expires = DateTime::parse_from_rfc3339(
            value["expires_at"]
                .as_str()
                .ok_or("private S3 material unavailable")?,
        )
        .map_err(|_| "private S3 material unavailable")?;
        require(
            now < deadline && deadline <= expires && (expires - now).num_milliseconds() <= 900_000,
        )?;
        Ok(Self { document: value })
    }

    pub(crate) fn frame(self, request_digest: &str, nonce: &str) -> Vec<u8> {
        let mut bytes = canonical_json(
            &json!({"kind":"credentials", "request_digest":request_digest,
            "nonce":nonce,"credentials":self.document}),
        )
        .into_bytes();
        bytes.push(b'\n');
        bytes
    }
}
