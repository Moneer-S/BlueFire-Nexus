//! Closed worker send previews. No constructor here can issue a permit or debit.

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_hash, canonical_json};
use crate::s3_access_binding::S3WorkerBinding;
use crate::s3_access_policy::encoded;
use crate::s3_access_scope::{require, Checked};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyResource {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionResource {
    role_arn: String,
    session_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BucketResource {
    bucket: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectResource {
    bucket: String,
    key: String,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum Resource {
    Empty(EmptyResource),
    Session(SessionResource),
    Bucket(BucketResource),
    Object(ObjectResource),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Send {
    service: String,
    operation: String,
    role: String,
    method: String,
    host: String,
    resource: Resource,
    payload_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    kind: String,
    request_digest: String,
    sequence: u64,
    send: Send,
    send_digest: String,
}

/// Immutable checked consistency data. A future authority must still durably debit it.
#[derive(Debug, PartialEq, Eq)]
pub struct S3SendPreview {
    canonical: String,
    digest: String,
    sequence: u64,
    is_write: bool,
}

impl S3SendPreview {
    /// One bounded JSON line, tied to the caller's exact next sequence.
    pub fn from_frame(binding: &S3WorkerBinding, bytes: &[u8], next: u64) -> Checked<Self> {
        require(bytes.len() <= 4096 && bytes.last() == Some(&b'\n'))?;
        require(!bytes[..bytes.len() - 1].contains(&b'\n'))?;
        let frame: Frame =
            serde_json::from_slice(bytes).map_err(|_| "S3 send preview shape is invalid")?;
        require(frame.kind == "send" && frame.request_digest == binding.digest())?;
        require(frame.sequence == next && (1..=binding.max_sends()).contains(&next))?;
        let planned = binding.planned_send(next as usize)?;
        require(encoded(&frame.send)? == planned)?;
        let preview = serde_json::json!({
            "kind": "send",
            "request_digest": binding.digest(),
            "sequence": next,
            "send": planned,
        });
        require(frame.send_digest == canonical_hash(&preview))?;
        Ok(Self {
            canonical: canonical_json(&encoded(&frame)?),
            digest: frame.send_digest,
            sequence: next,
            is_write: frame.send.operation == "PutBucketPolicy",
        })
    }

    pub fn canonical_json(&self) -> &str {
        &self.canonical
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn is_write(&self) -> bool {
        self.is_write
    }
}
