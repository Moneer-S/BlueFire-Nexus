use chrono::{DateTime, FixedOffset};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

use super::json::*;
use super::{acl, scope, Code, Result, MAX_RESULT};

pub(super) struct Packet {
    pub value: Value,
    pub digest: String,
    pub deadline: DateTime<FixedOffset>,
    pub monotonic_deadline: Instant,
    pub output_limit: usize,
}

impl Packet {
    pub fn request(&self) -> &Value {
        &self.value["manifest"]["params"]["ad_smb_request"]
    }
    pub fn current(&self) -> Result<()> {
        if Instant::now() >= self.monotonic_deadline
            || DateTime::<chrono::Utc>::from(std::time::SystemTime::now()) >= self.deadline
        {
            Err(Code::Deadline)
        } else {
            Ok(())
        }
    }
    pub fn validate(value: Value, now: DateTime<FixedOffset>, ingress: Instant) -> Result<Self> {
        exact(
            &value,
            &[
                "schema_version",
                "challenge",
                "task_id",
                "request_hash",
                "manifest",
                "profile",
                "channel_digest",
                "host_role",
                "host_id",
                "client_identity_digest",
                "credential_binding_digest",
                "expected_upn_sha256",
                "prior_local_authentication_ids",
                "remaining_ms",
            ],
        )?;
        ensure(
            value["schema_version"] == "bluefire.ad-smb-worker-request.v1"
                && hex(text(&value["challenge"])?, 64),
        )?;
        let request = &value["manifest"]["params"]["ad_smb_request"];
        request_valid(request)?;
        let deadline = time(&request["deadline"])?;
        ensure(time(&request["requested_at"])? <= now && now < deadline)?;
        let remaining = number(&value["remaining_ms"], 1, 60_000)?;
        let original_remaining = (deadline - now)
            .to_std()
            .map_err(|_| Code::RequestInvalid)?;
        let monotonic_deadline = ingress + Duration::from_millis(remaining).min(original_remaining);
        profile_manifest(&value, request)?;
        let binding = hash(&json!({"manifest":value["manifest"],"profile":value["profile"]}))?;
        ensure(
            value["request_hash"] == binding
                && value["task_id"] == format!("execute-{}", &binding[7..]),
        )?;
        let role = if request["target"].is_null() {
            "member"
        } else {
            "client"
        };
        ensure(
            value["host_role"] == role
                && value["host_id"] == request["host"]["host_id"]
                && value["host_id"] == request["scope"]["hosts"][role]["host_id"]
                && value["channel_digest"] == request["host"]["channel_digest"]
                && value["client_identity_digest"]
                    == request["scope"]["hosts"]["client"]["identity_receipt_digest"],
        )?;
        if role == "member" {
            ensure(
                value["credential_binding_digest"].is_null()
                    && value["expected_upn_sha256"].is_null(),
            )?;
        } else {
            ensure(value["credential_binding_digest"] == request["principal_binding_digest"])?;
            digest(&value["expected_upn_sha256"])?;
        }
        let prior = value["prior_local_authentication_ids"]
            .as_array()
            .ok_or(Code::RequestInvalid)?;
        ensure(prior.len() <= 5 && (role == "client" || prior.is_empty()))?;
        for (index, id) in prior.iter().enumerate() {
            ensure(hex(text(id)?, 16) && id != "0000000000000000" && !prior[..index].contains(id))?;
        }
        let requested_output = number(
            &value["manifest"]["limits"]["max_stdout_bytes"],
            1,
            MAX_RESULT as u64,
        )? as usize;
        let public_bytes = crate::canonical::canonical_json(&value).len();
        // Reserve the existing authenticated channel's envelope and retained public packet.
        let channel_remaining = (4 * 1024 * 1024_usize)
            .checked_sub(4096 + public_bytes + 1024)
            .ok_or(Code::RequestInvalid)?;
        let output_limit = requested_output.min(channel_remaining);
        ensure(output_limit > 0)?;
        let digest = hash(&value)?;
        Ok(Self {
            value,
            digest,
            deadline,
            monotonic_deadline,
            output_limit,
        })
    }
}

pub(super) fn audit_limit(
    output_limit: usize,
    events: usize,
    requested_bytes: usize,
) -> Result<usize> {
    let overhead = events
        .checked_mul(3)
        .and_then(|value| value.checked_add(2048))
        .ok_or(Code::RequestInvalid)?;
    let available = output_limit
        .checked_sub(overhead)
        .ok_or(Code::RequestInvalid)?
        / 6;
    let limit = requested_bytes.min(available);
    ensure(limit > 0)?;
    Ok(limit)
}

fn request_valid(request: &Value) -> Result<()> {
    exact(
        request,
        &[
            "schema_version",
            "request_id",
            "workflow_job_id",
            "operation_job_id",
            "index",
            "phase",
            "step",
            "scope",
            "scope_digest",
            "target",
            "requested_at",
            "deadline",
            "environment_digest",
            "host",
            "principal_binding_digest",
            "review_digest",
            "reviewed_by",
            "change",
        ],
    )?;
    ensure(request["schema_version"] == "bluefire.ad-smb-step.v1")?;
    for name in ["workflow_job_id", "operation_job_id"] {
        ensure(
            text(&request[name])?
                .strip_prefix("job-")
                .is_some_and(|v| hex(v, 32)),
        )?;
    }
    let index = number(&request["index"], 0, 2)?;
    let operation = text(&request["operation_job_id"])?;
    let id = hex::encode(Sha256::digest(format!("{operation}:{index}").as_bytes()));
    ensure(request["request_id"] == id[..32])?;
    let phase = text(&request["phase"])?;
    let expected = match (phase, index) {
        ("inspect", 0) => "inspect_member",
        ("harden", 0) => "harden_share",
        ("rollback", 0) => "rollback_share",
        ("audit", 0) => "collect_audit",
        ("baseline" | "retest", 0) => "read_probe_primary",
        ("baseline" | "retest", 1) => "read_legitimate_primary",
        ("baseline" | "retest", 2) => "read_legitimate_health",
        _ => return Err(Code::RequestInvalid),
    };
    ensure(request["step"] == expected)?;
    let scope = &request["scope"];
    scope::validate(scope)?;
    ensure(request["scope_digest"] == hash(scope)?)?;
    scope::target(request)?;
    let created = time(&scope["created_at"])?;
    let requested = time(&request["requested_at"])?;
    let deadline = time(&request["deadline"])?;
    let expires = time(&scope["expires_at"])?;
    let business =
        chrono::Duration::seconds(number(&scope["limits"]["business_seconds"], 1, 1800)? as i64);
    let phase_deadline = match phase {
        "rollback" => expires,
        "audit" => expires.min(
            created
                + business
                + chrono::Duration::seconds(
                    number(&scope["limits"]["audit_seconds"], 1, 600)? as i64
                ),
        ),
        _ => expires.min(created + business),
    };
    ensure(
        created <= requested
            && requested < deadline
            && deadline <= phase_deadline
            && deadline - requested
                <= chrono::Duration::seconds(
                    number(&scope["limits"]["operation_seconds"], 1, 60)? as i64
                ),
    )?;
    if phase == "audit" {
        ensure(created < requested)?;
    }
    for name in [
        "environment_digest",
        "principal_binding_digest",
        "review_digest",
    ] {
        digest(&request[name])?;
    }
    exact(
        &request["host"],
        &[
            "runner_profile_id",
            "host_id",
            "native_generation",
            "profile_digest",
            "channel_digest",
        ],
    )?;
    identifier(&request["host"]["runner_profile_id"])?;
    for name in [
        "host_id",
        "native_generation",
        "profile_digest",
        "channel_digest",
    ] {
        digest(&request["host"][name])?;
    }
    let reviewer = text(&request["reviewed_by"])?;
    ensure(
        !reviewer.is_empty()
            && reviewer.len() <= 100
            && reviewer.as_bytes()[0].is_ascii_alphanumeric()
            && reviewer
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b' ' | b'-')),
    )?;
    if ["harden", "retest", "rollback"].contains(&phase) {
        acl::validate_change(request)?;
    } else {
        ensure(request["change"].is_null())?;
    }
    Ok(())
}

fn profile_manifest(packet: &Value, request: &Value) -> Result<()> {
    let profile = &packet["profile"];
    exact(
        profile,
        &[
            "schema_version",
            "profile_id",
            "runner_id",
            "platform",
            "sandbox_root",
            "allowed_actions",
            "control_blocked_actions",
            "capabilities",
            "max_safety_tier",
            "approval_required_at_or_above",
            "target_scope",
            "limits",
            "policy_digest",
        ],
    )?;
    ensure(
        profile["schema_version"] == "bluefire.runner-profile.v1"
            && profile["profile_id"] == request["host"]["runner_profile_id"]
            && profile["runner_id"] == "bluefire-rust-runner.v1"
            && profile["platform"] == "windows"
            && profile["allowed_actions"] == json!(["owned.ad.smb_access.v1"])
            && profile["control_blocked_actions"] == json!([])
            && profile["capabilities"] == json!(["ad_smb_access"])
            && profile["max_safety_tier"] == "controlled"
            && profile["approval_required_at_or_above"] == "safe"
            && profile["target_scope"] == json!({"filesystem":[],"network":[]}),
    )?;
    let sandbox = text(&profile["sandbox_root"])?;
    ensure(
        (3..=240).contains(&sandbox.len())
            && sandbox.is_ascii()
            && sandbox.as_bytes()[0].is_ascii_uppercase()
            && &sandbox[1..3] == ":\\"
            && !sandbox
                .bytes()
                .any(|b| b < 32 || matches!(b, b'/' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'))
            && !sandbox[3..]
                .split('\\')
                .any(|p| p == "." || p == ".." || p.contains(':')),
    )?;
    let mut unsealed = profile.clone();
    unsealed["policy_digest"] = json!("");
    ensure(
        profile["policy_digest"] == hash(&unsealed)?
            && profile["policy_digest"] == request["host"]["profile_digest"],
    )?;
    let limits = &profile["limits"];
    let scope_limits = &request["scope"]["limits"];
    exact(
        limits,
        &[
            "timeout_ms",
            "max_stdout_bytes",
            "max_stderr_bytes",
            "max_artifact_bytes",
            "max_files",
        ],
    )?;
    let timeout = number(
        &limits["timeout_ms"],
        1,
        number(&scope_limits["operation_seconds"], 1, 60)? * 1000,
    )?;
    number(&limits["max_stdout_bytes"], 1, MAX_RESULT as u64)?;
    number(&limits["max_stderr_bytes"], 1, 65_536)?;
    number(
        &limits["max_artifact_bytes"],
        1,
        number(&scope_limits["returned_payload_bytes"], 1, 1_048_576)?,
    )?;
    number(&limits["max_files"], 1, 2)?;
    ensure(number(&packet["remaining_ms"], 1, 60_000)? <= timeout)?;
    let manifest = &packet["manifest"];
    let requested_at = time(&request["requested_at"])?
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    let expires_at = time(&request["deadline"])?
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    let mut expected = json!({"schema_version":"bluefire.runner-manifest.v1","request_id":format!("ad-{}",text(&request["request_id"])?),"run_id":request["operation_job_id"],"step_id":request["step"],"behavior_id":"identity.ad.smb_access.v1","action_id":"owned.ad.smb_access.v1","mode":"execute","runner_id":profile["runner_id"],"runner_profile_id":profile["profile_id"],"platform":"windows","requested_at":manifest["requested_at"],"expires_at":manifest["expires_at"],"params":{"ad_smb_request":request},"target_scope":{"filesystem":[],"network":[]},"required_capabilities":["ad_smb_access"],"safety_tier":"controlled","limits":limits,"cleanup_action_id":null,"policy_digest":profile["policy_digest"],"approval":{"approved_by":request["reviewed_by"],"approved_at":manifest["requested_at"],"expires_at":manifest["expires_at"],"request_hash":""},"evidence_refs":[],"request_hash":""});
    ensure(
        time(&manifest["requested_at"])? == time(&request["requested_at"])?
            && time(&manifest["expires_at"])? == time(&request["deadline"])?,
    )?;
    expected["requested_at"] = json!(requested_at);
    expected["expires_at"] = json!(expires_at);
    expected["approval"]["approved_at"] = expected["requested_at"].clone();
    expected["approval"]["expires_at"] = expected["expires_at"].clone();
    let sealed = hash(&expected)?;
    expected["request_hash"] = json!(sealed);
    expected["approval"]["request_hash"] = expected["request_hash"].clone();
    ensure(*manifest == expected)
}
