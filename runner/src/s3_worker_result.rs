//! Closed safe projection of a fixed worker result, never independent AWS audit.

use serde_json::{json, Value};

use crate::canonical::canonical_json;
use crate::s3_access_binding::S3WorkerBinding;
use crate::s3_access_scope::{require, Checked};
use crate::s3_reservation::PolicyPosition;

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
    document: Value,
    pub observed: bool,
    pub all_objects_read: bool,
    pub policy_position: PolicyPosition,
}

impl WorkerResult {
    pub(crate) fn document(&self) -> &Value {
        &self.document
    }

    pub(crate) fn from_frame(
        binding: &S3WorkerBinding,
        bytes: &[u8],
        debits: u64,
    ) -> Checked<Self> {
        Self::from_frame_with_discovery(binding, bytes, debits, None)
    }

    pub(crate) fn from_frame_with_discovery(
        binding: &S3WorkerBinding,
        bytes: &[u8],
        debits: u64,
        discovery: Option<&crate::s3_access_binding::audit::Discovery>,
    ) -> Checked<Self> {
        require(bytes.len() <= 16 * 1024 && bytes.last() == Some(&b'\n'))?;
        let frame: Value = serde_json::from_slice(bytes).map_err(|_| "invalid S3 worker result")?;
        require(canonical_json(&frame).as_bytes() == &bytes[..bytes.len() - 1])?;
        fields(&frame, "kind result")?;
        require(frame["kind"] == "result")?;
        let row = &frame["result"];
        if binding.audit().is_some() {
            let observed =
                crate::s3_access_binding::audit::validate_result(binding, row, debits, discovery)?;
            return Ok(Self {
                document: row.clone(),
                observed,
                all_objects_read: false,
                policy_position: PolicyPosition::Unknown,
            });
        }
        fields(row, "schema_version request_digest outcome data problem send_permits_consumed calls runtime_isolation_proven")?;
        let schema = if binding.fixture().is_some() {
            crate::s3_fixture_binding::RESULT_SCHEMA
        } else {
            "bluefire.s3-worker-result.v1"
        };
        require(
            row["schema_version"] == schema
                && row["request_digest"] == binding.digest()
                && row["runtime_isolation_proven"] == false,
        )?;
        let consumed = row["send_permits_consumed"]
            .as_u64()
            .ok_or("invalid S3 accounting")?;
        let calls = row["calls"].as_array().ok_or("invalid S3 calls")?;
        let plan = binding.operation_plan();
        require(
            consumed <= debits
                && debits <= binding.max_sends()
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
                            || (binding.fixture().is_some()
                                && [
                                    "ObjectLockConfigurationNotFoundError",
                                    "ConditionalRequestConflict",
                                ]
                                .contains(&code))
                    }) && (400..=599).contains(&status),
                )?;
            } else {
                require(
                    if binding.fixture().is_some() && call["operation"] == "DeleteObject" {
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
                    (["apply_policy", "rollback_policy"].contains(&binding.operation())
                        && consumed >= 3)
                        || (matches!(binding.operation(), "prepare_fixture" | "cleanup_fixture")
                            && binding.operation_plan().iter().any(|call| {
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
        let request: Value =
            serde_json::from_str(binding.canonical_json()).map_err(|_| "invalid S3 binding")?;
        let data = &row["data"];
        if binding.fixture().is_some() {
            binding.validate_fixture_observation(data, calls)?;
        } else if ["probe_read", "legitimate_read"].contains(&binding.operation()) {
            fields(data, "reader objects effective_access_claim")?;
            let probe = binding.operation() == "probe_read";
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
            let label = match binding.operation() {
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
