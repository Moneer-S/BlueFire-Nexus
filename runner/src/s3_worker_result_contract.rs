//! Pure ordinary worker-result consistency; no collector dispatch or authority.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canonical::{canonical_hash, canonical_json};
use crate::s3_access_plan::ordinary_plan;
use crate::s3_access_scope::{require, Checked, Scope};
use crate::s3_fixture_binding::FixtureOperation;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyPosition {
    Before,
    After,
    Drift,
    Unknown,
}

const ERROR_CODES: &[&str] = &[
    "AccessDenied",
    "NoSuchKey",
    "NoSuchBucket",
    "ExpiredToken",
    "InvalidToken",
    "InvalidAccessKeyId",
    "SignatureDoesNotMatch",
    "RequestExpired",
    "AuthorizationHeaderMalformed",
    "PermanentRedirect",
    "SlowDown",
    "ServiceUnavailable",
    "InternalError",
    "PreconditionFailed",
    "OtherServiceError",
];

#[cfg(any(target_os = "linux", test))]
pub(crate) fn valid_error(code: &str) -> bool {
    ERROR_CODES.contains(&code)
}

fn fields(row: &Value, names: &str) -> Checked<()> {
    let object = row.as_object().ok_or("invalid S3 worker result")?;
    require(
        object.len() == names.split_whitespace().count()
            && names
                .split_whitespace()
                .all(|name| object.contains_key(name)),
    )
}

pub(crate) struct WorkerResult {
    pub(super) document: Value,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub observed: bool,
    pub all_objects_read: bool,
    pub policy_position: PolicyPosition,
}

pub(crate) fn result_frame(bytes: &[u8]) -> Checked<Value> {
    require(bytes.len() <= 16 * 1024 && bytes.last() == Some(&b'\n'))?;
    let frame: Value = serde_json::from_slice(bytes).map_err(|_| "invalid S3 worker result")?;
    require(canonical_json(&frame).as_bytes() == &bytes[..bytes.len() - 1])?;
    fields(&frame, "kind result")?;
    require(frame["kind"] == "result")?;
    Ok(frame["result"].clone())
}

impl WorkerResult {
    pub(crate) fn document(&self) -> &Value {
        &self.document
    }

    pub(crate) fn from_ordinary_frame(request: &Value, bytes: &[u8], debits: u64) -> Checked<Self> {
        Self::from_ordinary_result(request, &result_frame(bytes)?, debits)
    }

    pub(crate) fn from_ordinary_result(request: &Value, row: &Value, debits: u64) -> Checked<Self> {
        // The caller has already checked this exact canonical request. Rebuild all
        // result context from that one document, not independently supplied fields.
        let operation = request["operation"].as_str().ok_or("invalid S3 binding")?;
        let max_sends = request["max_sends"].as_u64().ok_or("invalid S3 binding")?;
        let request_digest = canonical_hash(request);
        let scope: Scope =
            serde_json::from_value(request["scope"].clone()).map_err(|_| "invalid S3 binding")?;
        let fixture: Option<FixtureOperation> = request
            .get("fixture")
            .map(|value| serde_json::from_value(value.clone()).map_err(|_| "invalid S3 binding"))
            .transpose()?;
        require(
            request["schema_version"]
                == if fixture.is_some() {
                    crate::s3_fixture_binding::REQUEST_SCHEMA
                } else {
                    "bluefire.s3-worker-request.v1"
                },
        )?;
        let plan = ordinary_plan(operation, fixture.as_ref());
        fields(row, "schema_version request_digest outcome data problem send_permits_consumed calls runtime_isolation_proven")?;
        let schema = if fixture.is_some() {
            crate::s3_fixture_binding::RESULT_SCHEMA
        } else {
            "bluefire.s3-worker-result.v1"
        };
        require(
            row["schema_version"] == schema
                && row["request_digest"] == request_digest
                && row["runtime_isolation_proven"] == false,
        )?;
        let consumed = row["send_permits_consumed"]
            .as_u64()
            .ok_or("invalid S3 accounting")?;
        let calls = row["calls"].as_array().ok_or("invalid S3 calls")?;
        require(
            consumed <= debits
                && debits <= max_sends
                && consumed <= plan.len() as u64
                && calls.len() as u64 <= consumed
                && calls.len() <= plan.len(),
        )?;
        for (index, call) in calls.iter().enumerate() {
            fields(
                call,
                if call.get("error_code").is_some() {
                    "operation role request_id http_status error_code"
                } else {
                    "operation role request_id http_status"
                },
            )?;
            let expected = serde_json::to_value(&plan[index]).map_err(|_| "invalid S3 plan")?;
            let id = call["request_id"].as_str().ok_or("invalid S3 request ID")?;
            require(
                (1..=128).contains(&id.len())
                    && id.as_bytes()[0].is_ascii_alphanumeric()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+/=_:.-".contains(&b))
                    && call["operation"] == expected["operation"]
                    && call["role"] == expected["role"],
            )?;
            let status = call["http_status"].as_u64().ok_or("invalid S3 status")?;
            if let Some(code) = call.get("error_code") {
                require(
                    code.as_str().is_some_and(|code| {
                        ERROR_CODES.contains(&code)
                            || (fixture.is_some()
                                && [
                                    "ObjectLockConfigurationNotFoundError",
                                    "ConditionalRequestConflict",
                                ]
                                .contains(&code))
                    }) && (400..=599).contains(&status),
                )?;
            } else {
                require(
                    if fixture.is_some() && call["operation"] == "DeleteObject" {
                        status == 204
                    } else {
                        status == 200 || (status == 204 && call["operation"] == "PutBucketPolicy")
                    },
                )?;
            }
        }
        let outcome = row["outcome"].as_str().ok_or("invalid S3 outcome")?;
        require(["observed", "failed", "reconcile_required"].contains(&outcome))?;
        let mut result = Self {
            document: row.clone(),
            observed: outcome == "observed",
            all_objects_read: false,
            policy_position: PolicyPosition::Unknown,
        };
        if outcome != "observed" {
            require(
                row["data"].is_null()
                    && row["problem"]
                        == if outcome == "failed" {
                            "scoped_operation_failed"
                        } else {
                            "write_outcome_unsettled"
                        },
            )?;
            if outcome == "reconcile_required" {
                require(
                    (["apply_policy", "rollback_policy"].contains(&operation) && consumed >= 3)
                        || (matches!(operation, "prepare_fixture" | "cleanup_fixture")
                            && plan.iter().any(|call| {
                                matches!(call.operation, "PutObject" | "DeleteObject")
                            })
                            && consumed >= 5),
                )?;
            }
            return Ok(result);
        }
        require(
            row["problem"].is_null() && calls.len() == plan.len() && consumed == plan.len() as u64,
        )?;
        let data = &row["data"];
        if fixture.is_some() {
            fixture
                .as_ref()
                .ok_or("fixture operation is absent")?
                .validate_observation(&scope, operation, data, calls)?;
        } else if ["probe_read", "legitimate_read"].contains(&operation) {
            fields(data, "reader objects effective_access_claim")?;
            let probe = operation == "probe_read";
            require(
                data["reader"] == if probe { "probe" } else { "legitimate" }
                    && data["effective_access_claim"] == false,
            )?;
            let objects = data["objects"].as_array().ok_or("invalid S3 objects")?;
            require(objects.len() == if probe { 1 } else { 2 })?;
            result.all_objects_read = true;
            for (index, observed) in objects.iter().enumerate() {
                let expected = &request["scope"]["objects"][index];
                let call = &calls[index + 3];
                if call["error_code"] == "AccessDenied" && call["http_status"] == 403 {
                    require(
                        *observed
                            == json!({"purpose":expected["purpose"],"result":"service_denied"}),
                    )?;
                    result.all_objects_read = false;
                } else {
                    require(
                        call.get("error_code").is_none()
                            && *observed
                                == json!({
                                    "purpose":expected["purpose"],"result":"read",
                                    "sha256":expected["sha256"],"size_bytes":expected["size_bytes"],
                                }),
                    )?;
                }
            }
            require(
                calls[..3]
                    .iter()
                    .all(|call| call.get("error_code").is_none()),
            )?;
        } else {
            fields(data, "policy_digest structural_review")?;
            require(calls.iter().all(|call| call.get("error_code").is_none()))?;
            let digest = data["policy_digest"]
                .as_str()
                .ok_or("invalid S3 policy digest")?;
            require(digest.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }))?;
            let baseline = request["scope"]["policy"]["baseline_digest"]
                .as_str()
                .ok_or("invalid S3 baseline")?;
            let after = request["policy_change"]["after_digest"].as_str();
            result.policy_position = if digest == baseline {
                PolicyPosition::Before
            } else if Some(digest) == after {
                PolicyPosition::After
            } else {
                PolicyPosition::Drift
            };
            let label = match operation {
                "inspect_policy" => {
                    require(digest == baseline)?;
                    "supported_baseline"
                }
                "apply_policy" => {
                    require(Some(digest) == after)?;
                    "exact_readback"
                }
                "rollback_policy" => {
                    require(digest == baseline)?;
                    "exact_readback"
                }
                "reconcile_policy" => match result.policy_position {
                    PolicyPosition::Before => "matched_before",
                    PolicyPosition::After => "matched_after",
                    _ => "drift",
                },
                _ => return Err("invalid S3 policy operation"),
            };
            require(data["structural_review"] == label)?;
        }
        Ok(result)
    }
}
