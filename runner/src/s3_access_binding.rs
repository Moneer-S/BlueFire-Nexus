//! Unregistered S3 worker consistency binding. No credentials, execution or authority.

use chrono::{DateTime, Duration, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_hash, canonical_json, sha256_hex};
use crate::s3_access_policy::{encoded, PolicyChange};
use crate::s3_access_scope::{digest, lower_hex, require, utc_time, Checked, Scope};

pub const MAX_DOCUMENT_BYTES: usize = 80 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: String,
    launch_id: String,
    request_id: String,
    worker_generation: String,
    runtime_digest: String,
    scope: Scope,
    scope_digest: String,
    operation: String,
    policy_change: Option<PolicyChange>,
    deadline: String,
    max_sends: u64,
    exclusive_writer_digest: Option<String>,
}

/// A finite operation description, not a send permit or execution capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct S3PlannedCall {
    pub service: &'static str,
    pub operation: &'static str,
    pub role: &'static str,
}

impl S3PlannedCall {
    fn new(service: &'static str, operation: &'static str, role: &'static str) -> Self {
        Self {
            service,
            operation,
            role,
        }
    }
}

/// Only constructed through independent closed parsing of the worker's canonical data.
#[derive(Clone)]
pub struct S3WorkerBinding {
    request: Request,
    canonical: String,
    digest: String,
}

fn query_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut encoded, "%{byte:02X}").expect("writing to a String");
        }
    }
    encoded
}

impl S3WorkerBinding {
    pub fn from_json(bytes: &[u8]) -> Checked<Self> {
        require(!bytes.is_empty() && bytes.len() <= MAX_DOCUMENT_BYTES)?;
        // Typed nested deserialization rejects duplicate keys and numeric coercions.
        let request: Request =
            serde_json::from_slice(bytes).map_err(|_| "S3 worker request shape is invalid")?;
        let value = encoded(&request)?;
        let supplied: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "S3 worker request is not JSON")?;
        // Option<T> alone permits absent keys; the wire requires explicit nulls.
        require(value == supplied)?;
        require(request.schema_version == "bluefire.s3-worker-request.v1")?;
        require(lower_hex(&request.launch_id, 64) && lower_hex(&request.request_id, 64))?;
        require(digest(&request.worker_generation) && digest(&request.runtime_digest))?;
        request.scope.validate()?;
        require(canonical_json(&encoded(&request.scope)?).len() <= 32 * 1024)?;
        require(request.scope_digest == canonical_hash(&encoded(&request.scope)?))?;
        let maximum = match request.operation.as_str() {
            "inspect_policy" => 2,
            "apply_policy" | "rollback_policy" | "probe_read" => 4,
            "legitimate_read" => 5,
            _ => return Err("S3 worker operation is unsupported"),
        };
        require((1..=maximum.min(request.scope.limits.api_calls)).contains(&request.max_sends))?;
        let deadline = utc_time(&request.deadline)?;
        require(
            utc_time(&request.scope.created_at)? < deadline
                && deadline <= utc_time(&request.scope.expires_at)?,
        )?;
        if ["apply_policy", "rollback_policy"].contains(&request.operation.as_str()) {
            request
                .policy_change
                .as_ref()
                .ok_or("S3 policy change is absent")?
                .validate(&request.scope)?;
            require(
                request
                    .exclusive_writer_digest
                    .as_ref()
                    .is_some_and(|value| digest(value)),
            )?;
        } else {
            require(request.policy_change.is_none() && request.exclusive_writer_digest.is_none())?;
        }
        Ok(Self {
            canonical: canonical_json(&value),
            digest: canonical_hash(&value),
            request,
        })
    }

    pub fn canonical_json(&self) -> &str {
        &self.canonical
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn max_sends(&self) -> u64 {
        self.request.max_sends
    }

    /// The caller supplies time; this is not a native wall-clock or cancellation gate.
    pub fn assert_current(&self, now: DateTime<FixedOffset>) -> Checked<()> {
        let scope = &self.request.scope;
        require(utc_time(&scope.created_at)? <= now && now < utc_time(&scope.expires_at)?)?;
        let remaining = utc_time(&self.request.deadline)? - now;
        require(
            remaining > Duration::zero()
                && remaining <= Duration::seconds(scope.limits.request_seconds as i64),
        )
    }

    pub fn operation_plan(&self) -> Vec<S3PlannedCall> {
        let selected = self.request.operation.as_str();
        let mut plan = vec![S3PlannedCall::new("sts", "GetCallerIdentity", "controller")];
        if ["probe_read", "legitimate_read"].contains(&selected) {
            let reader = if selected == "probe_read" {
                "probe"
            } else {
                "legitimate"
            };
            plan.push(S3PlannedCall::new("sts", "AssumeRole", "controller"));
            plan.push(S3PlannedCall::new("sts", "GetCallerIdentity", reader));
            plan.push(S3PlannedCall::new("s3", "GetObject", reader));
            if reader == "legitimate" {
                plan.push(S3PlannedCall::new("s3", "GetObject", reader));
            }
        } else {
            plan.push(S3PlannedCall::new("s3", "GetBucketPolicy", "controller"));
            if selected != "inspect_policy" {
                plan.push(S3PlannedCall::new("s3", "PutBucketPolicy", "controller"));
                plan.push(S3PlannedCall::new("s3", "GetBucketPolicy", "controller"));
            }
        }
        plan
    }

    /// Exact safe resource projection for a one-based planned call, never permission.
    pub fn planned_resource(&self, sequence: usize) -> Checked<serde_json::Value> {
        let plan = self.operation_plan();
        require(sequence > 0 && sequence <= plan.len())?;
        let call = &plan[sequence - 1];
        let scope = &self.request.scope;
        match call.operation {
            "GetCallerIdentity" => Ok(serde_json::json!({})),
            "AssumeRole" => {
                let reader = if self.request.operation == "probe_read" {
                    "probe"
                } else {
                    "legitimate"
                };
                let role = if reader == "probe" {
                    &scope.roles.probe
                } else {
                    &scope.roles.legitimate
                };
                Ok(serde_json::json!({
                    "role_arn": role,
                    "session_name": format!("bf-{}-{reader}", &self.request.request_id[..32]),
                }))
            }
            "GetObject" => Ok(
                serde_json::json!({ "bucket": scope.bucket, "key": scope.objects[sequence - 4].key }),
            ),
            _ => Ok(serde_json::json!({ "bucket": scope.bucket })),
        }
    }

    pub fn policy_payload_digest(&self) -> Checked<String> {
        self.request
            .policy_change
            .as_ref()
            .ok_or("S3 policy change is absent")?
            .payload_digest(self.request.operation == "rollback_policy")
    }

    /// Exact safe preview expected from the pinned SDK serializer, not a permit.
    /// No signed headers or credential material enter this projection.
    pub fn planned_send(&self, sequence: usize) -> Checked<serde_json::Value> {
        let resource = self.planned_resource(sequence)?;
        let plan = self.operation_plan();
        let call = &plan[sequence - 1];
        let method = if call.service == "sts" {
            "POST"
        } else if call.operation == "PutBucketPolicy" {
            "PUT"
        } else {
            "GET"
        };
        let payload_digest = if call.operation == "PutBucketPolicy" {
            self.policy_payload_digest()?
        } else {
            let body = match call.operation {
                "GetCallerIdentity" => "Action=GetCallerIdentity&Version=2011-06-15".to_string(),
                "AssumeRole" => format!(
                    "Action=AssumeRole&Version=2011-06-15&RoleArn={}&RoleSessionName={}&DurationSeconds=900",
                    query_component(resource["role_arn"].as_str().ok_or("S3 role is absent")?),
                    query_component(resource["session_name"].as_str().ok_or("S3 session is absent")?),
                ),
                _ => String::new(),
            };
            format!("sha256:{}", sha256_hex(body.as_bytes()))
        };
        Ok(serde_json::json!({
            "service": call.service,
            "operation": call.operation,
            "role": call.role,
            "method": method,
            "host": format!("{}.{}.amazonaws.com", call.service, self.request.scope.region),
            "resource": resource,
            "payload_digest": payload_digest,
        }))
    }
}
