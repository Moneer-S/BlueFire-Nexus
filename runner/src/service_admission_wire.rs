//! Closed scope/grant verification. No public JSON-to-authority constructor.

use chrono::{DateTime, Duration, FixedOffset};
use serde_json::{json, Value};

use super::{VerifiedServiceAdmission, REFUSAL, SERVICE_ACTION_ID};
use crate::canonical::{canonical_hash, canonical_json, sha256_hex};
use crate::contract::{
    expected_manifest_hash, expected_profile_digest, ExecutionManifest, Platform, RunMode,
    RunnerProfile,
};
use crate::service_operation_binding::ServiceOperationBinding;

pub(super) fn require(ok: bool) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn fields(value: &Value, names: &str) -> Result<(), String> {
    let object = value.as_object().ok_or(REFUSAL)?;
    require(
        object.len() == names.split_whitespace().count()
            && names.split_whitespace().all(|key| object.contains_key(key)),
    )
}

fn text(value: &Value) -> Result<&str, String> {
    value.as_str().ok_or_else(|| REFUSAL.into())
}
fn digest(value: &Value) -> Result<(), String> {
    require(
        text(value)?
            .strip_prefix("sha256:")
            .is_some_and(|s| hex(s, 64)),
    )
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &Value) -> Result<(), String> {
    let s = text(value)?;
    require(
        (1..=128).contains(&s.len())
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
    )
}
fn integer(value: &Value, min: u64, max: u64) -> Result<u64, String> {
    value
        .as_u64()
        .filter(|n| (min..=max).contains(n))
        .ok_or_else(|| REFUSAL.into())
}
fn path(value: &Value) -> Result<(), String> {
    let s = text(value)?;
    require(
        s.starts_with('/')
            && !s.contains('\\')
            && !s.contains('\0')
            && !s.ends_with('/')
            && !s
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == ".."),
    )
}
fn time(value: &Value) -> Result<DateTime<FixedOffset>, String> {
    let s = text(value)?;
    require(
        s.is_ascii() && s.len() == 20 && s.ends_with('Z') && &s[..4] != "0000" && &s[17..19] < "60",
    )?;
    DateTime::parse_from_rfc3339(s).map_err(|_| REFUSAL.into())
}

fn claim_time(value: &Value) -> Result<DateTime<FixedOffset>, String> {
    let s = text(value)?;
    if s.len() == 20 {
        return time(value);
    }
    require(
        s.is_ascii()
            && (22..=27).contains(&s.len())
            && s.ends_with('Z')
            && &s[..4] != "0000"
            && &s[17..19] < "60"
            && s.as_bytes()[19] == b'.'
            && s.as_bytes()[20..s.len() - 1].iter().all(u8::is_ascii_digit),
    )?;
    DateTime::parse_from_rfc3339(s).map_err(|_| REFUSAL.into())
}

fn unit(value: &Value) -> Result<(), String> {
    const TEMPLATE: &str = "[Unit]\nDescription=BlueFire owned user service\n[Service]\nType=simple\nExecStart={payload_path} owned-service-payload --duration-seconds {duration_seconds}\nRuntimeMaxSec={max_runtime_seconds}s\nMemoryMax={memory_max_bytes}\nTasksMax={max_processes}\nKillMode=control-group\nRestart=no\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\n[Install]\nWantedBy=default.target\n";
    require(
        value["template"]["content_digest"]
            == format!("sha256:{}", sha256_hex(TEMPLATE.as_bytes())),
    )?;
    let payload = text(&value["installations"]["payload"]["path"])?;
    require(
        payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._+-".contains(&b)),
    )?;
    let mut rendered = TEMPLATE.replace("{payload_path}", payload);
    for (placeholder, number) in [
        (
            "{duration_seconds}",
            &value["parameters"]["duration_seconds"],
        ),
        (
            "{max_runtime_seconds}",
            &value["limits"]["max_runtime_seconds"],
        ),
        (
            "{memory_max_bytes}",
            &value["parameters"]["memory_max_bytes"],
        ),
        ("{max_processes}", &value["limits"]["max_processes"]),
    ] {
        rendered = rendered.replace(placeholder, &number.to_string());
    }
    require(
        value["unit"]["content_digest"] == format!("sha256:{}", sha256_hex(rendered.as_bytes()))
            && rendered.len() as u64
                <= value["limits"]["max_unit_bytes"].as_u64().ok_or(REFUSAL)?,
    )
}

fn scope(value: &Value) -> Result<(), String> {
    fields(value, "schema_version scenario_id step_id action_id profile_id profile_policy_digest target_scope_digest workspace target manager unit template installations effects parameters limits created_at setup_expires_at cleanup_expires_at")?;
    require(
        value["schema_version"] == "bluefire.owned-user-service-scope.v1"
            && value["action_id"] == SERVICE_ACTION_ID,
    )?;
    for key in ["scenario_id", "step_id", "action_id", "profile_id"] {
        identifier(&value[key])?;
    }
    for key in ["profile_policy_digest", "target_scope_digest"] {
        digest(&value[key])?;
    }
    fields(&value["workspace"], "workspace_id root")?;
    identifier(&value["workspace"]["workspace_id"])?;
    path(&value["workspace"]["root"])?;
    fields(&value["target"], "owner_uid boot_id manager_instance_id")?;
    let uid = integer(&value["target"]["owner_uid"], 1, u32::MAX as u64 - 1)?;
    let boot = text(&value["target"]["boot_id"])?;
    require(
        boot.split('-')
            .zip([8, 4, 4, 4, 12])
            .all(|(s, n)| hex(s, n))
            && boot.len() == 36
            && boot.bytes().any(|b| b != b'0' && b != b'-'),
    )?;
    require(hex(text(&value["target"]["manager_instance_id"])?, 32))?;
    fields(&value["manager"], "kind bus_identity")?;
    require(
        value["manager"]["kind"] == "systemd.user.v1"
            && value["manager"]["bus_identity"] == format!("unix:path=/run/user/{uid}/bus"),
    )?;
    fields(&value["unit"], "nonce name content_digest")?;
    let nonce = text(&value["unit"]["nonce"])?;
    require(
        hex(nonce, 32)
            && nonce != "0".repeat(32)
            && value["unit"]["name"] == format!("bluefire-{nonce}.service"),
    )?;
    digest(&value["unit"]["content_digest"])?;
    fields(&value["template"], "template_id content_digest")?;
    require(value["template"]["template_id"] == "bluefire.user-service.fixed-wait.v1")?;
    digest(&value["template"]["content_digest"])?;
    fields(&value["installations"], "manager payload")?;
    for name in ["manager", "payload"] {
        let installation = &value["installations"][name];
        fields(installation, "installation_id path digest content_sha256")?;
        identifier(&installation["installation_id"])?;
        path(&installation["path"])?;
        digest(&installation["digest"])?;
        digest(&installation["content_sha256"])?;
    }
    fields(&value["effects"], "setup cleanup")?;
    require(
        value["effects"]["setup"] == json!(["create_unit", "reload", "enable", "start"])
            && value["effects"]["cleanup"]
                == json!([
                    "stop",
                    "disable",
                    "remove_links",
                    "remove_unit",
                    "reload_after_cleanup"
                ]),
    )?;
    fields(&value["parameters"], "duration_seconds memory_max_bytes")?;
    fields(&value["limits"], "setup_timeout_seconds cleanup_timeout_seconds max_unit_bytes max_runtime_seconds max_memory_bytes max_processes")?;
    let runtime = integer(&value["limits"]["max_runtime_seconds"], 1, 120)?;
    let memory = integer(
        &value["limits"]["max_memory_bytes"],
        16 * 1024 * 1024,
        512 * 1024 * 1024,
    )?;
    integer(&value["parameters"]["duration_seconds"], 1, runtime)?;
    integer(
        &value["parameters"]["memory_max_bytes"],
        16 * 1024 * 1024,
        memory,
    )?;
    integer(&value["limits"]["max_processes"], 1, 16)?;
    integer(&value["limits"]["max_unit_bytes"], 256, 16 * 1024)?;
    for key in ["setup_timeout_seconds", "cleanup_timeout_seconds"] {
        integer(&value["limits"][key], 1, 60)?;
    }
    let created = time(&value["created_at"])?;
    let setup = time(&value["setup_expires_at"])?;
    let cleanup = time(&value["cleanup_expires_at"])?;
    require(
        created < setup
            && setup <= created + Duration::minutes(5)
            && setup <= cleanup
            && cleanup <= created + Duration::hours(1),
    )?;
    unit(value)
}

fn binding(grant: &Value) -> Result<ServiceOperationBinding, String> {
    let bound = &grant["operation_binding"];
    let parsed = ServiceOperationBinding::from_json(canonical_json(bound).as_bytes())?;
    let scope = &grant["scope"];
    let expected = json!({
        "schema_version": "bluefire.owned-user-service.v1", "authorization_digest": grant["scope_digest"],
        "runner_profile_id": scope["profile_id"], "workspace_id": scope["workspace"]["workspace_id"],
        "target_scope_digest": scope["target_scope_digest"], "owner_uid": scope["target"]["owner_uid"],
        "boot_id": scope["target"]["boot_id"], "manager_id": scope["target"]["manager_instance_id"],
        "unit_nonce": scope["unit"]["nonce"], "unit_content_digest": scope["unit"]["content_digest"],
        "created_at": scope["created_at"], "cleanup_due_at": scope["cleanup_expires_at"]
    });
    require(
        bound["identity"] == expected
            && bound["reviewed_scope_digest"] == grant["scope_digest"]
            && bound["manager_installation_digest"] == scope["installations"]["manager"]["digest"]
            && bound["payload_installation_digest"] == scope["installations"]["payload"]["digest"]
            && grant["execution"]["operation_binding_digest"] == parsed.digest(),
    )?;
    Ok(parsed)
}

pub(super) fn validate(
    admission: &Value,
    expected_issuer: &Value,
    manifest: &Value,
    profile: &Value,
    now: DateTime<FixedOffset>,
) -> Result<VerifiedServiceAdmission, String> {
    fields(admission, "schema_version grant grant_digest issuer")?;
    require(admission["schema_version"] == "bluefire.owned-user-service-admission.v1")?;
    fields(
        &admission["issuer"],
        "runner_id client_id enrollment_generation peer_fingerprint server_instance_id",
    )?;
    fields(
        expected_issuer,
        "runner_id client_id enrollment_generation peer_fingerprint",
    )?;
    let mut issuer = admission["issuer"].clone();
    issuer
        .as_object_mut()
        .ok_or(REFUSAL)?
        .remove("server_instance_id");
    require(issuer == *expected_issuer)?;
    for key in ["runner_id", "client_id", "server_instance_id"] {
        identifier(&admission["issuer"][key])?;
    }
    digest(&issuer["enrollment_generation"])?;
    digest(&issuer["peer_fingerprint"])?;
    let grant = &admission["grant"];
    fields(grant, "schema_version scope scope_digest claim run_id step_id action_id manifest_request_hash execution operation_binding")?;
    require(
        grant["schema_version"] == "bluefire.owned-user-service-grant.v1"
            && admission["grant_digest"] == canonical_hash(grant),
    )?;
    scope(&grant["scope"])?;
    let scope = &grant["scope"];
    require(grant["scope_digest"] == canonical_hash(scope))?;
    fields(
        &grant["execution"],
        "task_id manifest_digest profile_digest operation_binding_digest",
    )?;
    let execution = &grant["execution"];
    let task_id = format!(
        "execute-{}",
        &canonical_hash(&json!({"manifest":manifest,"profile":profile}))[7..]
    );
    require(
        execution["manifest_digest"] == canonical_hash(manifest)
            && execution["profile_digest"] == canonical_hash(profile)
            && execution["task_id"] == task_id,
    )?;
    let claim = &grant["claim"];
    fields(claim, "approval_id state_digest plan_digest target_scope_digest profile_id maximum_tier consumed_at approval_expires_at")?;
    identifier(&claim["approval_id"])?;
    require(text(&claim["approval_id"])?.starts_with("approval-"))?;
    for key in ["state_digest", "plan_digest", "target_scope_digest"] {
        digest(&claim[key])?;
    }
    require(["safe", "controlled", "restricted"].contains(&text(&claim["maximum_tier"])?))?;
    require(
        claim["profile_id"] == scope["profile_id"]
            && claim["target_scope_digest"] == scope["target_scope_digest"],
    )?;
    let created = time(&scope["created_at"])?;
    let setup = time(&scope["setup_expires_at"])?;
    let cleanup = time(&scope["cleanup_expires_at"])?;
    let consumed = claim_time(&claim["consumed_at"])?;
    let expires = claim_time(&claim["approval_expires_at"])?;
    let operation_binding = binding(grant)?;
    let is_setup = ["create_unit", "reload", "enable", "start"]
        .contains(&text(&grant["operation_binding"]["operation"])?);
    require(
        created <= consumed
            && consumed < setup
            && consumed < expires
            && consumed <= now
            && (!is_setup || now < expires)
            && now < if is_setup { setup } else { cleanup },
    )?;
    validate_request(grant, manifest, profile, now, is_setup)?;
    Ok(VerifiedServiceAdmission {
        scope_digest: text(&grant["scope_digest"])?.into(),
        grant_digest: text(&admission["grant_digest"])?.into(),
        task_id,
        enrollment_digest: canonical_hash(expected_issuer),
        runner_profile_id: text(&scope["profile_id"])?.into(),
        target_scope_digest: text(&scope["target_scope_digest"])?.into(),
        workspace_id: text(&scope["workspace"]["workspace_id"])?.into(),
        owner_uid: scope["target"]["owner_uid"].as_u64().ok_or(REFUSAL)? as u32,
        boot_id: text(&scope["target"]["boot_id"])?.into(),
        manager_id: text(&scope["target"]["manager_instance_id"])?.into(),
        unit_nonce: text(&scope["unit"]["nonce"])?.into(),
        unit_content_digest: text(&scope["unit"]["content_digest"])?.into(),
        manager_installation_digest: text(&scope["installations"]["manager"]["digest"])?.into(),
        payload_installation_digest: text(&scope["installations"]["payload"]["digest"])?.into(),
        operation_binding_digest: operation_binding.digest().into(),
        operation_binding: Some(operation_binding),
        created_at: created,
        setup_expires_at: setup,
        cleanup_expires_at: cleanup,
        #[cfg(target_os = "linux")]
        scope: scope.clone(),
        #[cfg(target_os = "linux")]
        installations: Vec::new(),
    })
}

fn validate_request(
    grant: &Value,
    manifest: &Value,
    profile: &Value,
    now: DateTime<FixedOffset>,
    is_setup: bool,
) -> Result<(), String> {
    let typed_manifest: ExecutionManifest =
        serde_json::from_value(manifest.clone()).map_err(|_| REFUSAL)?;
    let typed_profile: RunnerProfile =
        serde_json::from_value(profile.clone()).map_err(|_| REFUSAL)?;
    let scope = &grant["scope"];
    let approval = typed_manifest.approval.as_ref().ok_or(REFUSAL)?;
    let maximum = match text(&grant["claim"]["maximum_tier"])? {
        "safe" => 1,
        "controlled" => 2,
        "restricted" => 3,
        _ => return Err(REFUSAL.into()),
    };
    let timeout = scope["limits"][if is_setup {
        "setup_timeout_seconds"
    } else {
        "cleanup_timeout_seconds"
    }]
    .as_u64()
    .ok_or(REFUSAL)?;
    require(
        typed_manifest.mode == RunMode::Execute
            && typed_manifest.platform == Platform::Linux
            && typed_profile.platform == Platform::Linux
            && typed_manifest.runner_id == typed_profile.runner_id
            && typed_manifest.request_hash == expected_manifest_hash(&typed_manifest)
            && typed_profile.policy_digest == expected_profile_digest(&typed_profile)
            && typed_manifest.policy_digest == typed_profile.policy_digest
            && approval.request_hash == typed_manifest.request_hash
            && approval.approved_at < approval.expires_at
            && approval.approved_at <= now
            && (!is_setup || now < approval.expires_at)
            && typed_manifest.requested_at <= now
            && now < typed_manifest.expires_at
            && typed_manifest.safety_tier.rank() <= maximum
            && typed_manifest.safety_tier.rank() <= typed_profile.max_safety_tier.rank()
            && typed_manifest.limits.timeout_ms <= timeout * 1000
            && typed_profile
                .allowed_actions
                .contains(&SERVICE_ACTION_ID.into())
            && !typed_profile
                .control_blocked_actions
                .contains(&SERVICE_ACTION_ID.into()),
    )?;
    require(
        manifest["action_id"] == SERVICE_ACTION_ID
            && grant["action_id"] == manifest["action_id"]
            && grant["run_id"] == manifest["run_id"]
            && grant["step_id"] == manifest["step_id"]
            && grant["step_id"] == scope["step_id"]
            && grant["manifest_request_hash"] == manifest["request_hash"]
            && scope["profile_id"] == profile["profile_id"]
            && manifest["runner_profile_id"] == profile["profile_id"]
            && scope["workspace"]["root"] == profile["sandbox_root"]
            && manifest["params"] == scope["parameters"],
    )
}
