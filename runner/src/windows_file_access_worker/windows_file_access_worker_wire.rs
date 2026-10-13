use super::{Clock, Code, Protocol, Result, MAX_PUBLIC, MAX_TERMINAL};
use crate::windows_file_access_read::{FileIdentity, ResourceExpectation, ResourceState};
use chrono::{DateTime, FixedOffset, Timelike};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use std::fmt;
use std::time::{Duration, Instant};

pub(super) struct Packet {
    pub protocol: Protocol,
    pub value: Value,
    pub digest: String,
    pub monotonic_deadline: Instant,
    requested: DateTime<FixedOffset>,
    deadline: DateTime<FixedOffset>,
    pub output_limit: usize,
}
impl Packet {
    pub(super) fn request(&self) -> &Value {
        &self.value["manifest"]["params"]["windows_file_read_request"]
    }
    pub(super) fn current(&self, clock: &dyn Clock) -> Result<()> {
        if clock.cancelled() {
            return Err(Code::Cancelled);
        }
        let wall = clock.wall();
        if clock.monotonic() >= self.monotonic_deadline
            || wall < self.requested
            || wall >= self.deadline
        {
            return Err(Code::Deadline);
        }
        Ok(())
    }
    pub(super) fn completion(&self, clock: &dyn Clock) -> Result<String> {
        self.current(clock)?;
        let observed = clock.wall();
        if observed < self.requested || observed >= self.deadline {
            return Err(Code::Deadline);
        }
        let timestamp = observed
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        // Check the actual serialized timestamp. It is never clamped into the
        // original interval following rollback, cancellation or a late return.
        let encoded = time(&Value::String(timestamp.clone()))?;
        if encoded < self.requested || encoded >= self.deadline {
            return Err(Code::Deadline);
        }
        self.current(clock)?;
        Ok(timestamp)
    }
    #[cfg(test)]
    pub(super) fn validate(value: Value, clock: &dyn Clock, ingress: Instant) -> Result<Self> {
        Self::validate_for(Protocol::ReaderV1, value, clock, ingress)
    }
    pub(super) fn validate_for(
        protocol: Protocol,
        value: Value,
        clock: &dyn Clock,
        ingress: Instant,
    ) -> Result<Self> {
        ensure(crate::canonical::canonical_json(&value).len() <= MAX_PUBLIC)?;
        exact(
            &value,
            &[
                "schema_version",
                "challenge",
                "task_id",
                "request_hash",
                "manifest",
                "profile",
                "remaining_ms",
            ],
        )?;
        ensure(
            value["schema_version"] == protocol.request()
                && lower_hex(text(&value["challenge"])?, 64),
        )?;
        documents(&value, protocol)?;
        let manifest = &value["manifest"];
        let deadline = time(&manifest["expires_at"])?;
        let requested = time(&manifest["requested_at"])?;
        let now = clock.wall();
        ensure(requested <= now && now < deadline)?;
        let remaining = number(&value["remaining_ms"], 1, 5000)?;
        ensure(remaining <= number(&manifest["limits"]["timeout_ms"], 1, 5000)?)?;
        let wall_remaining = (deadline - now)
            .to_std()
            .map_err(|_| Code::RequestInvalid)?;
        let monotonic_deadline = ingress
            + Duration::from_millis(remaining)
                .min(wall_remaining)
                .min(Duration::from_secs(5));
        // Top-level request_hash binds BOTH sealed documents. It is distinct
        // from manifest.request_hash, which seals that manifest's authority bytes.
        let transport = hash(&json!({"manifest":value["manifest"],"profile":value["profile"]}));
        ensure(
            value["request_hash"] == transport
                && value["task_id"] == format!("execute-{}", &transport[7..]),
        )?;
        let digest = hash(&value);
        let output_limit = number(
            &manifest["limits"]["max_stdout_bytes"],
            1024,
            MAX_TERMINAL as u64,
        )? as usize;
        let packet = Self {
            protocol,
            value,
            digest,
            monotonic_deadline,
            requested,
            deadline,
            output_limit,
        };
        packet.resource()?;
        packet.current(clock)?;
        Ok(packet)
    }
    pub(super) fn resource(&self) -> Result<ResourceExpectation> {
        let request = self.request();
        let row = &request["resource"];
        let ancestors = row["ancestors"].as_array().ok_or(Code::RequestInvalid)?;
        ensure(ancestors.len() == 4)?;
        let state = match text(&row["state"])? {
            "readable" => ResourceState::Readable,
            "metadata_only" if self.protocol == Protocol::ReaderV1 => ResourceState::MetadataOnly,
            _ => return Err(Code::RequestInvalid),
        };
        ResourceExpectation::new(
            text(&request["generation"])?,
            text(&row["owner_sid"])?,
            text(&row["reader_sid"])?,
            [
                identity(&ancestors[0])?,
                identity(&ancestors[1])?,
                identity(&ancestors[2])?,
                identity(&ancestors[3])?,
            ],
            identity(&row["file_identity"])?,
            number(&row["size_bytes"], 1, 1_048_576)? as usize,
            text(&row["sha256"])?,
            state,
        )
        .map_err(|_| Code::RequestInvalid)
    }
    pub(super) fn binding(&self) -> Value {
        let request = self.request();
        json!({"challenge":self.value["challenge"],"packet_digest":self.digest,
            "task_id":self.value["task_id"],"request_hash":self.value["request_hash"],
            "generation":request["generation"],"control_revision":request["control_revision"],
            "credential_binding_digest":request["credential_binding_digest"]})
    }
}
fn documents(packet: &Value, protocol: Protocol) -> Result<()> {
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
            && profile["runner_id"] == "bluefire-rust-runner.v1"
            && profile["platform"] == "windows"
            && profile["sandbox_root"]
                == format!(
                    "C:\\BlueFire\\EndpointAccess\\{}",
                    text(&packet["manifest"]["params"]["windows_file_read_request"]["generation"])?
                )
            && profile["allowed_actions"] == json!([protocol.action()])
            && profile["control_blocked_actions"] == json!([])
            && profile["capabilities"] == json!([protocol.capability()])
            && profile["max_safety_tier"] == "controlled"
            && profile["approval_required_at_or_above"] == "safe"
            && profile["target_scope"] == json!({"filesystem":[],"network":[]}),
    )?;
    identifier(&profile["profile_id"])?;
    limits(&profile["limits"])?;
    let mut unsealed_profile = profile.clone();
    unsealed_profile["policy_digest"] = json!("");
    ensure(profile["policy_digest"] == hash(&unsealed_profile))?;
    let manifest = &packet["manifest"];
    exact(
        manifest,
        &[
            "schema_version",
            "request_id",
            "run_id",
            "step_id",
            "behavior_id",
            "action_id",
            "mode",
            "runner_id",
            "runner_profile_id",
            "platform",
            "requested_at",
            "expires_at",
            "params",
            "target_scope",
            "required_capabilities",
            "safety_tier",
            "limits",
            "cleanup_action_id",
            "policy_digest",
            "approval",
            "evidence_refs",
            "request_hash",
        ],
    )?;
    exact(&manifest["params"], &["windows_file_read_request"])?;
    let request = &manifest["params"]["windows_file_read_request"];
    exact(
        request,
        &[
            "schema_version",
            "request_id",
            "operation_job_id",
            "generation",
            "control_revision",
            "credential_binding_digest",
            "host",
            "resource",
        ],
    )?;
    ensure(
        request["schema_version"] == protocol.operation_schema()
            && lower_hex(text(&request["request_id"])?, 32)
            && lower_hex(text(&request["generation"])?, 32),
    )?;
    number(&request["control_revision"], 1, i32::MAX as u64)?;
    digest(&request["credential_binding_digest"])?;
    exact(
        &request["host"],
        &[
            "runner_profile_id",
            "profile_digest",
            "native_generation",
            "host_id",
            "channel_digest",
        ],
    )?;
    ensure(
        request["host"]["runner_profile_id"] == profile["profile_id"]
            && request["host"]["profile_digest"] == profile["policy_digest"],
    )?;
    for name in [
        "profile_digest",
        "native_generation",
        "host_id",
        "channel_digest",
    ] {
        digest(&request["host"][name])?;
    }
    exact(
        &request["resource"],
        &[
            "owner_sid",
            "reader_sid",
            "ancestors",
            "file_identity",
            "size_bytes",
            "sha256",
            "state",
        ],
    )?;
    digest(&request["resource"]["sha256"])?;
    ensure(
        manifest["schema_version"] == "bluefire.runner-manifest.v1"
            && manifest["request_id"] == format!("win-read-{}", text(&request["request_id"])?)
            && manifest["step_id"] == protocol.operation()
            && manifest["behavior_id"] == protocol.behavior()
            && manifest["action_id"] == protocol.action()
            && manifest["mode"] == "execute"
            && manifest["runner_id"] == profile["runner_id"]
            && manifest["runner_profile_id"] == profile["profile_id"]
            && manifest["platform"] == "windows"
            && manifest["target_scope"] == profile["target_scope"]
            && manifest["required_capabilities"] == profile["capabilities"]
            && manifest["safety_tier"] == "controlled"
            && manifest["limits"] == profile["limits"]
            && manifest["cleanup_action_id"].is_null()
            && manifest["policy_digest"] == profile["policy_digest"]
            && manifest["evidence_refs"] == json!([]),
    )?;
    let job = text(&request["operation_job_id"])?;
    ensure(
        job.strip_prefix("job-").is_some_and(|v| lower_hex(v, 32)) && manifest["run_id"] == job,
    )?;
    let operation_id =
        crate::canonical::sha256_hex(format!("{job}:{}", protocol.operation()).as_bytes());
    ensure(request["request_id"] == operation_id[..32])?;
    let requested = time(&manifest["requested_at"])?;
    let expires = time(&manifest["expires_at"])?;
    ensure(requested < expires && expires - requested <= chrono::Duration::seconds(5))?;
    exact(
        &manifest["approval"],
        &["approved_by", "approved_at", "expires_at", "request_hash"],
    )?;
    identifier(&manifest["approval"]["approved_by"])?;
    ensure(
        manifest["approval"]["approved_at"] == manifest["requested_at"]
            && manifest["approval"]["expires_at"] == manifest["expires_at"]
            && manifest["approval"]["request_hash"] == manifest["request_hash"],
    )?;
    let mut unsealed = manifest.clone();
    unsealed["request_hash"] = json!("");
    unsealed["approval"]["request_hash"] = json!("");
    ensure(manifest["request_hash"] == hash(&unsealed))
}
fn limits(row: &Value) -> Result<()> {
    exact(
        row,
        &[
            "timeout_ms",
            "max_stdout_bytes",
            "max_stderr_bytes",
            "max_artifact_bytes",
            "max_files",
        ],
    )?;
    number(&row["timeout_ms"], 1, 5000)?;
    number(&row["max_stdout_bytes"], 1024, MAX_TERMINAL as u64)?;
    number(&row["max_stderr_bytes"], 1, 1024)?;
    ensure(row["max_artifact_bytes"] == 1 && row["max_files"] == 1)
}
fn identity(row: &Value) -> Result<FileIdentity> {
    exact(row, &["volume_serial", "file_id"])?;
    let volume = text(&row["volume_serial"])?;
    let id = text(&row["file_id"])?;
    ensure(lower_hex(volume, 16) && lower_hex(id, 32))?;
    Ok(FileIdentity {
        volume_serial: u64::from_str_radix(volume, 16).map_err(|_| Code::RequestInvalid)?,
        file_id: hex::decode(id)
            .map_err(|_| Code::RequestInvalid)?
            .try_into()
            .map_err(|_| Code::RequestInvalid)?,
    })
}
pub(super) fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    let row = value.as_object().ok_or(Code::RequestInvalid)?;
    ensure(row.len() == fields.len() && fields.iter().all(|name| row.contains_key(*name)))
}
fn ensure(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Code::RequestInvalid)
    }
}
pub(super) fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or(Code::RequestInvalid)
}
pub(super) fn number(value: &Value, min: u64, max: u64) -> Result<u64> {
    let value = value.as_u64().ok_or(Code::RequestInvalid)?;
    ensure((min..=max).contains(&value))?;
    Ok(value)
}
fn lower_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(value: &Value) -> Result<()> {
    ensure(
        text(value)?
            .strip_prefix("sha256:")
            .is_some_and(|v| lower_hex(v, 64)),
    )
}
fn identifier(value: &Value) -> Result<()> {
    let v = text(value)?;
    ensure(
        !v.is_empty()
            && v.len() <= 128
            && v.as_bytes()[0].is_ascii_alphanumeric()
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
    )
}
fn time(value: &Value) -> Result<DateTime<FixedOffset>> {
    let value = text(value)?;
    ensure(value.len() <= 40 && value.is_ascii())?;
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| Code::RequestInvalid)?;
    ensure(parsed.nanosecond() < 1_000_000_000 && parsed.nanosecond() % 1000 == 0)?;
    Ok(parsed)
}
pub(super) fn hash(value: &Value) -> String {
    crate::canonical::canonical_hash(value)
}

// Standard serde recursion limits plus byte/count bounds; floating values and
// duplicate keys are refused at every depth before closed-schema validation.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Json;
        impl<'de> Visitor<'de> for Json {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded integer JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut rows = Vec::new();
                while let Some(Strict(row)) = seq.next_element()? {
                    if rows.len() >= 16 {
                        return Err(de::Error::custom("array bound"));
                    }
                    rows.push(row);
                }
                Ok(Strict(rows.into()))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut rows = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if rows.len() >= 32 || rows.contains_key(&key) {
                        return Err(de::Error::custom("object bound or duplicate"));
                    }
                    let Strict(row) = map.next_value()?;
                    rows.insert(key, row);
                }
                Ok(Strict(rows.into()))
            }
        }
        deserializer.deserialize_any(Json)
    }
}
pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC {
        return Err(Code::RequestInvalid);
    }
    serde_json::from_slice::<Strict>(bytes)
        .map(|v| v.0)
        .map_err(|_| Code::RequestInvalid)
}
