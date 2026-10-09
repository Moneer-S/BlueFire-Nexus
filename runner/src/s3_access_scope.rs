//! Closed S3 consistency metadata. Parsing never establishes cloud authority.

use chrono::{DateTime, Duration, FixedOffset};
use serde::{Deserialize, Serialize};

pub(super) type Checked<T> = Result<T, &'static str>;

pub(super) fn require(valid: bool) -> Checked<()> {
    if valid {
        Ok(())
    } else {
        Err("S3 binding is outside its supported contract")
    }
}

pub(super) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|suffix| lower_hex(suffix, 64))
}

pub(super) fn utc_time(value: &str) -> Checked<DateTime<FixedOffset>> {
    let bytes = value.as_bytes();
    // The worker emits Python datetime's canonical UTC form, not arbitrary RFC3339.
    require(bytes.len() == 20 || bytes.len() == 27)?;
    for (index, byte) in bytes.iter().enumerate() {
        let expected = match index {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            index if index == bytes.len() - 1 => Some(b'Z'),
            19 => Some(b'.'),
            _ => None,
        };
        require(expected.map_or_else(|| byte.is_ascii_digit(), |expected| *byte == expected))?;
    }
    require(&value[..4] != "0000" && &value[17..19] < "60")?;
    let parsed =
        DateTime::parse_from_rfc3339(value).map_err(|_| "S3 binding timestamp is invalid")?;
    require(bytes.len() != 27 || &value[20..26] != "000000")?;
    Ok(parsed)
}

pub(super) fn role_arn(value: &str, account: &str) -> bool {
    value
        .strip_prefix(&format!("arn:aws:iam::{account}:role/"))
        .is_some_and(|name| {
            (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+=,.@_-".contains(&byte))
        })
}

fn region(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    parts.len() == 3
        && ["af", "ap", "ca", "eu", "il", "me", "mx", "sa", "us"].contains(&parts[0])
        && [
            "central",
            "east",
            "north",
            "northeast",
            "northwest",
            "south",
            "southeast",
            "southwest",
            "west",
        ]
        .contains(&parts[1])
        && (1..=2).contains(&parts[2].len())
        && parts[2].bytes().all(|byte| byte.is_ascii_digit())
        && !parts[2].starts_with('0')
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Roles {
    pub controller: String,
    pub probe: String,
    pub legitimate: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GeneratedObject {
    pub purpose: String,
    pub key: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyBinding {
    pub probe_sid: String,
    pub legitimate_sid: String,
    pub baseline_digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub api_calls: u64,
    pub business_attempts: u64,
    pub sessions: u64,
    pub session_seconds: u64,
    pub object_bytes: u64,
    pub audit_bytes: u64,
    pub audit_events: u64,
    pub business_seconds: u64,
    pub convergence_seconds: u64,
    pub audit_seconds: u64,
    pub cleanup_seconds: u64,
    pub request_seconds: u64,
    pub policy_changes: u64,
    pub rollbacks: u64,
}

impl Limits {
    fn validate(&self) -> Checked<()> {
        for (value, maximum) in [
            (self.api_calls, 300),
            (self.business_attempts, 6),
            (self.sessions, 6),
            (self.session_seconds, 900),
            (self.object_bytes, 65_536),
            (self.audit_bytes, 20 * 1024 * 1024),
            (self.audit_events, 1000),
            (self.business_seconds, 1800),
            (self.convergence_seconds, 300),
            (self.audit_seconds, 1800),
            (self.cleanup_seconds, 900),
            (self.request_seconds, 30),
            (self.policy_changes, 1),
            (self.rollbacks, 1),
        ] {
            require((1..=maximum).contains(&value))?;
        }
        require(self.session_seconds == 900 && self.convergence_seconds <= self.business_seconds)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    pub schema_version: String,
    pub scope_id: String,
    pub account_id: String,
    pub region: String,
    pub roles: Roles,
    pub bucket: String,
    pub prefix: String,
    pub objects: Vec<GeneratedObject>,
    pub policy: PolicyBinding,
    pub ownership_receipt_digest: String,
    pub created_at: String,
    pub expires_at: String,
    pub limits: Limits,
}

impl Scope {
    pub fn validate(&self) -> Checked<()> {
        require(self.schema_version == "bluefire.s3-access-scope.v1")?;
        require(
            self.scope_id
                .strip_prefix("s3-")
                .is_some_and(|suffix| lower_hex(suffix, 32)),
        )?;
        require(
            self.account_id.len() == 12 && self.account_id.bytes().all(|b| b.is_ascii_digit()),
        )?;
        require(region(&self.region))?;
        let roles = [
            &self.roles.controller,
            &self.roles.probe,
            &self.roles.legitimate,
        ];
        require(roles.iter().all(|role| role_arn(role, &self.account_id)))?;
        require(roles[0] != roles[1] && roles[0] != roles[2] && roles[1] != roles[2])?;
        let bucket = self.bucket.as_bytes();
        require(
            (3..=63).contains(&bucket.len())
                && bucket
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
                && bucket[0] != b'-'
                && bucket[bucket.len() - 1] != b'-'
                && !["xn--", "sthree-", "amzn-s3-demo-"]
                    .iter()
                    .any(|prefix| self.bucket.starts_with(prefix))
                && !["-s3alias", "--ol-s3", "--x-s3", "--table-s3"]
                    .iter()
                    .any(|suffix| self.bucket.ends_with(suffix)),
        )?;
        require(self.prefix == format!("bluefire/{}/", self.scope_id))?;
        self.limits.validate()?;
        require(self.objects.len() == 2)?;
        let mut total = 0;
        for (object, (purpose, name)) in self
            .objects
            .iter()
            .zip([("primary", "records.jsonl"), ("health", "health.jsonl")])
        {
            require(object.purpose == purpose && object.key == format!("{}{name}", self.prefix))?;
            require(digest(&object.sha256))?;
            require((1..=self.limits.object_bytes).contains(&object.size_bytes))?;
            total += object.size_bytes;
        }
        require(total <= self.limits.object_bytes)?;
        require(
            self.policy.probe_sid == format!("BlueFireProbe{}", &self.scope_id[3..])
                && self.policy.legitimate_sid
                    == format!("BlueFireLegitimate{}", &self.scope_id[3..])
                && digest(&self.policy.baseline_digest)
                && digest(&self.ownership_receipt_digest),
        )?;
        let duration = utc_time(&self.expires_at)? - utc_time(&self.created_at)?;
        let maximum =
            self.limits.business_seconds + self.limits.audit_seconds + self.limits.cleanup_seconds;
        require(duration > Duration::zero() && duration <= Duration::seconds(maximum as i64))
    }

    pub fn object_arns(&self) -> Vec<String> {
        self.objects
            .iter()
            .map(|object| format!("arn:aws:s3:::{}/{}", self.bucket, object.key))
            .collect()
    }
}
