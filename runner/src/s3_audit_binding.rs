//! Closed audit workflow consistency data, never admission or a send permit.

use chrono::{DateTime, Datelike, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_hash, canonical_json};
use crate::s3_access_policy::encoded;
use crate::s3_access_scope::{digest, lower_hex, require, role_arn, utc_time, Checked, Scope};

pub(crate) const WORKFLOW_SCHEMA: &str = "bluefire.s3-audit-workflow.v1";
pub(crate) const MAX_WORKFLOW_BYTES: usize = 16 * 1024;
const BATCHES: u64 = 2;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditLimits {
    pub api_calls: u64,
    pub sessions: u64,
    pub files: u64,
    pub sdk_body_bytes: u64,
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub events: u64,
    pub seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkflowLimits {
    pub api_calls: u64,
    pub sessions: u64,
    pub files: u64,
    pub sdk_body_bytes: u64,
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub events: u64,
    pub seconds: u64,
    pub batches: u64,
    pub wire_plus_expansion_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditBudget {
    pub per_batch: AuditLimits,
    pub workflow: WorkflowLimits,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Source {
    schema_version: String,
    audit_source_id: String,
    experiment_scope_digest: String,
    trail_arn: String,
    source_account_id: String,
    event_region: String,
    audit_bucket: String,
    audit_bucket_owner_account_id: String,
    audit_bucket_region: String,
    exact_delivery_root_prefix: String,
    collector_role_arn: String,
    managed_profile_digest: String,
    protected_runtime_digest: String,
    worker_generation: String,
    expires_at: String,
    audit_limits: AuditLimits,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    schema_version: String,
    workflow_job_id: String,
    environment_id: String,
    resource_key: String,
    scope_digest: String,
    source: Source,
    budget: AuditBudget,
}

/// Immutable checked metadata. It carries no enrollment or execution authority.
#[derive(Clone)]
pub(crate) struct AuditWorkflow {
    row: Workflow,
    digest: String,
    source_digest: String,
    expires_at: DateTime<FixedOffset>,
}

fn reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
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
        && parts[2].bytes().all(|b| b.is_ascii_digit())
        && !parts[2].starts_with('0')
}

fn bucket(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && !["xn--", "sthree-", "amzn-s3-demo-"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
        && !["-s3alias", "--ol-s3", "--x-s3", "--table-s3"]
            .iter()
            .any(|suffix| value.ends_with(suffix))
}

impl AuditLimits {
    fn validate(&self) -> Checked<()> {
        require(self.api_calls == 9 && self.sessions == 1)?;
        for (value, maximum) in [
            (self.api_calls, 9),
            (self.sessions, 1),
            (self.files, 4),
            (self.sdk_body_bytes, 393_216),
            (self.compressed_bytes, 262_144),
            (self.expanded_bytes, 1_048_576),
            (self.events, 500),
            (self.seconds, 30),
        ] {
            require((1..=maximum).contains(&value))?;
        }
        Ok(())
    }
}

impl AuditBudget {
    fn derive(scope: &Scope, configured: &AuditLimits) -> Checked<Self> {
        configured.validate()?;
        let limits = &scope.limits;
        let mut per = configured.clone();
        per.api_calls = per.api_calls.min(limits.api_calls / BATCHES);
        per.sessions = per.sessions.min(limits.sessions / BATCHES);
        per.events = per.events.min(limits.audit_events / BATCHES);
        per.seconds = per
            .seconds
            .min(limits.request_seconds)
            .min(limits.audit_seconds / BATCHES);
        per.sdk_body_bytes = per.sdk_body_bytes.min(limits.audit_bytes / BATCHES);
        per.expanded_bytes = per.expanded_bytes.min(limits.audit_bytes / BATCHES);
        per.compressed_bytes = per
            .compressed_bytes
            .min(per.sdk_body_bytes)
            .min(per.files * 65_536);
        per.validate()?;
        require(BATCHES * (per.sdk_body_bytes + per.expanded_bytes) <= limits.audit_bytes)?;
        let workflow = WorkflowLimits {
            api_calls: BATCHES * per.api_calls,
            sessions: BATCHES * per.sessions,
            files: BATCHES * per.files,
            sdk_body_bytes: BATCHES * per.sdk_body_bytes,
            compressed_bytes: BATCHES * per.compressed_bytes,
            expanded_bytes: BATCHES * per.expanded_bytes,
            events: BATCHES * per.events,
            seconds: BATCHES * per.seconds,
            batches: BATCHES,
            wire_plus_expansion_bytes: BATCHES * (per.sdk_body_bytes + per.expanded_bytes),
        };
        require(
            limits.sessions >= 2 * BATCHES + workflow.sessions
                && limits.business_attempts >= (1 + 2) * BATCHES,
        )?;
        Ok(Self {
            per_batch: per,
            workflow,
        })
    }
}

impl Source {
    fn validate(
        &self,
        scope: &Scope,
        scope_digest: &str,
        runtime: &str,
        generation: &str,
    ) -> Checked<DateTime<FixedOffset>> {
        require(
            self.schema_version == "bluefire.s3-audit-source.v1"
                && self.experiment_scope_digest == scope_digest
                && self.source_account_id == scope.account_id
                && self.audit_bucket_owner_account_id == scope.account_id
                && self.event_region == scope.region,
        )?;
        require(
            reference(&self.audit_source_id)
                && region(&self.audit_bucket_region)
                && bucket(&self.audit_bucket),
        )?;
        let trail_prefix = format!(
            "arn:aws:cloudtrail:{}:{}:trail/",
            scope.region, scope.account_id
        );
        let trail_name = self
            .trail_arn
            .strip_prefix(&trail_prefix)
            .ok_or("invalid audit trail")?;
        require((3..=128).contains(&trail_name.len()) && reference(trail_name))?;
        let prefix = &self.exact_delivery_root_prefix;
        let suffix = format!("AWSLogs/{}/CloudTrail/{}/", scope.account_id, scope.region);
        require(
            prefix.len() <= 256
                && !prefix.starts_with('/')
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b)),
        )?;
        let leading = prefix
            .strip_suffix(&suffix)
            .ok_or("invalid audit delivery prefix")?;
        require(
            (leading.is_empty() || leading.ends_with('/'))
                && prefix[..prefix.len() - 1]
                    .split('/')
                    .all(|part| !["", ".", ".."].contains(&part)),
        )?;
        require(
            role_arn(&self.collector_role_arn, &scope.account_id)
                && ![
                    &scope.roles.controller,
                    &scope.roles.probe,
                    &scope.roles.legitimate,
                ]
                .contains(&&self.collector_role_arn),
        )?;
        require(
            digest(&self.managed_profile_digest)
                && digest(runtime)
                && digest(generation)
                && self.protected_runtime_digest == runtime
                && self.worker_generation == generation,
        )?;
        let expires = utc_time(&self.expires_at)?;
        require(
            expires.year() >= 1000
                && utc_time(&scope.created_at)? < expires
                && expires <= utc_time(&scope.expires_at)?,
        )?;
        self.audit_limits.validate()?;
        Ok(expires)
    }
}

impl AuditWorkflow {
    /// Parse canonical producer metadata; no clock, enrollment or reservation is consulted.
    pub(crate) fn from_json(
        bytes: &[u8],
        scope: &Scope,
        runtime_digest: &str,
        worker_generation: &str,
    ) -> Checked<Self> {
        require(!bytes.is_empty() && bytes.len() <= MAX_WORKFLOW_BYTES)?;
        let row: Workflow = serde_json::from_slice(bytes).map_err(|_| "invalid audit workflow")?;
        let supplied: Value =
            serde_json::from_slice(bytes).map_err(|_| "invalid audit workflow")?;
        let document = encoded(&row)?;
        require(document == supplied && canonical_json(&document).len() <= MAX_WORKFLOW_BYTES)?;
        scope.validate()?;
        let scope_digest = canonical_hash(&encoded(scope)?);
        let resource_key = canonical_hash(&serde_json::json!({
            "account_id":scope.account_id,"region":scope.region,"bucket":scope.bucket,
        }));
        require(
            row.schema_version == WORKFLOW_SCHEMA
                && row
                    .workflow_job_id
                    .strip_prefix("job-")
                    .is_some_and(|id| lower_hex(id, 32))
                && reference(&row.environment_id)
                && row.scope_digest == scope_digest
                && row.resource_key == resource_key,
        )?;
        let expires_at =
            row.source
                .validate(scope, &scope_digest, runtime_digest, worker_generation)?;
        let derived = AuditBudget::derive(scope, &row.source.audit_limits)?;
        require(canonical_json(&encoded(&row.budget)?) == canonical_json(&encoded(&derived)?))?;
        Ok(Self {
            digest: canonical_hash(&document),
            source_digest: canonical_hash(&encoded(&row.source)?),
            row,
            expires_at,
        })
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn document(&self) -> Checked<Value> {
        encoded(&self.row)
    }
    pub(crate) fn source_digest(&self) -> &str {
        &self.source_digest
    }
    pub(crate) fn matches_source(&self, value: &Value) -> Checked<()> {
        require(canonical_json(value) == canonical_json(&encoded(&self.row.source)?))
    }
    pub(crate) fn budget(&self) -> &AuditBudget {
        &self.row.budget
    }
    pub(crate) fn workflow_id(&self) -> &str {
        &self.row.workflow_job_id
    }
    pub(crate) fn environment_id(&self) -> &str {
        &self.row.environment_id
    }
    pub(crate) fn resource_key(&self) -> &str {
        &self.row.resource_key
    }
    pub(crate) fn scope_digest(&self) -> &str {
        &self.row.scope_digest
    }
    #[cfg(test)]
    pub(crate) fn managed_profile_digest(&self) -> &str {
        &self.row.source.managed_profile_digest
    }
    #[cfg(test)]
    pub(crate) fn runtime_digest(&self) -> &str {
        &self.row.source.protected_runtime_digest
    }
    #[cfg(test)]
    pub(crate) fn worker_generation(&self) -> &str {
        &self.row.source.worker_generation
    }
    pub(crate) fn source_expires_at(&self) -> &DateTime<FixedOffset> {
        &self.expires_at
    }
}

pub(crate) fn checked_source(
    value: &Value,
    scope: &Scope,
    runtime: &str,
    generation: &str,
) -> Checked<(AuditLimits, DateTime<FixedOffset>)> {
    let source: Source =
        serde_json::from_value(value.clone()).map_err(|_| "invalid audit source")?;
    require(encoded(&source)? == *value)?;
    let expires = source.validate(
        scope,
        &canonical_hash(&encoded(scope)?),
        runtime,
        generation,
    )?;
    Ok((
        AuditBudget::derive(scope, &source.audit_limits)?.per_batch,
        expires,
    ))
}

#[cfg(test)]
#[path = "s3_audit_binding_tests.rs"]
mod tests;
