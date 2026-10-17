//! Pure collector messages. A checked Discovery is not a committed send permit.

use chrono::{Datelike, Duration, SecondsFormat, Timelike};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canonical::{canonical_hash, canonical_json, sha256_hex};
use crate::s3_access_policy::encoded;
use crate::s3_access_scope::{digest, lower_hex, require, utc_time, Checked, Scope};
use crate::s3_audit_binding::{checked_source, AuditWorkflow};
use crate::s3_worker_result::WorkerResult;

use super::{S3PlannedCall, S3WorkerBinding};

pub(crate) const REQUEST_SCHEMA: &str = "bluefire.s3-worker-request.v3";
pub(crate) const RESULT_SCHEMA: &str = "bluefire.s3-worker-result.v3";
pub(crate) const DISCOVERY_SCHEMA: &str = "bluefire.s3-audit-discovery.v1";
pub(crate) const MAX_LINE: usize = 16 * 1024;
pub(crate) const MAX_SEND: usize = 2048;

fn fields(value: &Value, names: &str) -> Checked<()> {
    let row = value.as_object().ok_or("invalid audit object")?;
    require(
        row.len() == names.split_whitespace().count()
            && names.split_whitespace().all(|name| row.contains_key(name)),
    )
}

fn text(value: &Value) -> Checked<&str> {
    value.as_str().ok_or("invalid audit text")
}

fn job(value: &str) -> bool {
    value
        .strip_prefix("job-")
        .is_some_and(|tail| lower_hex(tail, 32))
}

fn request_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_:.-".contains(&b))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalRead {
    reader: String,
    run_id: String,
    manifest_digest: String,
    request_digest: String,
    worker_result_digest: String,
    reservation_digest: String,
    cleanup: String,
    request: Value,
    result: Value,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    schema_version: String,
    workflow_job_id: String,
    operation_job_id: String,
    phase: String,
    outcome_digest: String,
    review_digest: String,
    reads: Vec<OriginalRead>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Collection {
    schema_version: String,
    launch_id: String,
    request_id: String,
    source: Value,
    workflow_job_id: String,
    operation_job_id: String,
    issued_at: String,
    deadline: String,
    original_pair: Pair,
}

impl Collection {
    pub(crate) fn validate(&self, binding: &S3WorkerBinding) -> Checked<()> {
        let scope = binding.scope();
        let (_, expires) = checked_source(
            &self.source,
            scope,
            binding.runtime_digest(),
            binding.worker_generation(),
        )?;
        let pair = &self.original_pair;
        require(
            self.schema_version == "bluefire.s3-audit-collection.v1"
                && lower_hex(&self.launch_id, 64)
                && lower_hex(&self.request_id, 64)
                && self.launch_id == binding.launch_id()
                && self.request_id == binding.request_id()
                && job(&self.workflow_job_id)
                && job(&self.operation_job_id)
                && pair.schema_version == "bluefire.s3-audit-read-pair.v1"
                && pair.workflow_job_id == self.workflow_job_id
                && job(&pair.operation_job_id)
                && pair.workflow_job_id != pair.operation_job_id
                && self.operation_job_id != pair.workflow_job_id
                && self.operation_job_id != pair.operation_job_id
                && matches!(pair.phase.as_str(), "baseline" | "retest")
                && digest(&pair.outcome_digest)
                && digest(&pair.review_digest)
                && pair.reads.len() == 2,
        )?;
        let mut starts = Vec::with_capacity(2);
        for (index, read) in pair.reads.iter().enumerate() {
            let reader = if index == 0 { "probe" } else { "legitimate" };
            require(
                read.reader == reader
                    && read.cleanup == "verified"
                    && read.run_id.is_ascii()
                    && read.run_id.len() == 37
                    && read.run_id.starts_with("run-")
                    && read.run_id.as_bytes()[20] == b'-'
                    && lower_hex(&read.run_id[21..], 16)
                    && chrono::NaiveDateTime::parse_from_str(&read.run_id[4..20], "%Y%m%dT%H%M%SZ")
                        .is_ok()
                    && [
                        &read.manifest_digest,
                        &read.request_digest,
                        &read.worker_result_digest,
                        &read.reservation_digest,
                    ]
                    .iter()
                    .all(|value| digest(value))
                    && read.request["schema_version"] == "bluefire.s3-worker-request.v1"
                    && read.request["operation"] == format!("{reader}_read"),
            )?;
            let original = S3WorkerBinding::from_json(canonical_json(&read.request).as_bytes())?;
            require(
                original.scope_digest() == binding.scope_digest()
                    && original.canonical_json() == canonical_json(&read.request)
                    && original.digest() == read.request_digest
                    && original.runtime_digest() == binding.runtime_digest()
                    && original.worker_generation() == binding.worker_generation()
                    && original.launch_id() != self.launch_id
                    && original.request_id() != self.request_id,
            )?;
            let consumed = read.result["send_permits_consumed"]
                .as_u64()
                .ok_or("invalid original read accounting")?;
            let bytes = format!(
                "{}\n",
                canonical_json(&json!({"kind":"result", "result":read.result}))
            );
            let result = WorkerResult::from_frame(&original, bytes.as_bytes(), consumed)?;
            require(canonical_hash(result.document()) == read.worker_result_digest)?;
            let calls = read.result["calls"]
                .as_array()
                .ok_or("invalid original calls")?;
            let mut ids = std::collections::BTreeSet::new();
            for call in calls.iter().skip(3) {
                require(ids.insert(text(&call["request_id"])?))?;
            }
            require(
                calls.len() <= 3
                    || calls[..3]
                        .iter()
                        .all(|call| call.get("error_code").is_none()),
            )?;
            starts.push(utc_time(&scope.created_at)?.max(
                original.deadline()? - Duration::seconds(scope.limits.request_seconds as i64),
            ));
        }
        let a = &pair.reads[0];
        let b = &pair.reads[1];
        require(
            a.run_id != b.run_id
                && a.manifest_digest != b.manifest_digest
                && a.request_digest != b.request_digest
                && a.reservation_digest != b.reservation_digest
                && a.request["launch_id"] != b.request["launch_id"]
                && a.request["request_id"] != b.request["request_id"],
        )?;
        let issued = utc_time(&self.issued_at)?;
        let end = utc_time(&self.deadline)?;
        let (limits, _) = checked_source(
            &self.source,
            scope,
            binding.runtime_digest(),
            binding.worker_generation(),
        )?;
        let canonical_time = |value: chrono::DateTime<chrono::FixedOffset>| {
            value.to_rfc3339_opts(
                if value.timestamp_subsec_micros() == 0 {
                    SecondsFormat::Secs
                } else {
                    SecondsFormat::Micros
                },
                true,
            )
        };
        require(
            self.issued_at == canonical_time(issued)
                && self.deadline == canonical_time(end)
                && issued.year() >= 1000
                && end.year() >= 1000
                && end == binding.deadline()?
                && starts[0].max(starts[1]) <= issued
                && issued < end
                && end <= expires
                && end <= issued + Duration::seconds(limits.seconds as i64)
                && end
                    <= starts[0].min(starts[1])
                        + Duration::seconds(scope.limits.audit_seconds as i64),
        )?;
        self.list_parameters(scope)?;
        Ok(())
    }

    pub(crate) fn matches_workflow(
        &self,
        workflow: &AuditWorkflow,
        operation_id: &str,
        phase: &str,
    ) -> Checked<()> {
        workflow.matches_source(&self.source)?;
        require(
            workflow.source_digest() == canonical_hash(&self.source)
                && workflow.workflow_id() == self.workflow_job_id
                && self.operation_job_id == operation_id
                && phase == format!("audit_{}", self.original_pair.phase),
        )
    }

    pub(crate) fn matches_prior_runs(&self, runs: &[Value]) -> Checked<()> {
        require(self.original_pair.reads.iter().all(|read| {
            runs.iter()
                .any(|run| run.as_str() == Some(read.run_id.as_str()))
        }))
    }

    pub(crate) fn admission_interval(
        &self,
        issued: chrono::DateTime<chrono::FixedOffset>,
        expires: chrono::DateTime<chrono::FixedOffset>,
    ) -> Checked<()> {
        require(
            utc_time(&self.issued_at)? <= issued
                && issued < expires
                && expires <= utc_time(&self.deadline)?,
        )
    }

    pub(crate) fn assert_current(
        &self,
        binding: &S3WorkerBinding,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> Checked<()> {
        let (limits, _) = checked_source(
            &self.source,
            binding.scope(),
            binding.runtime_digest(),
            binding.worker_generation(),
        )?;
        let end = utc_time(&self.deadline)?;
        require(
            utc_time(&self.issued_at)? <= now
                && now < end
                && end - now <= Duration::seconds(limits.seconds as i64),
        )
    }

    pub(crate) fn source_digest(&self) -> String {
        canonical_hash(&self.source)
    }
    pub(crate) fn phase(&self) -> &str {
        &self.original_pair.phase
    }
    pub(crate) fn host(&self, scope: &Scope, service: &str) -> Checked<String> {
        Ok(format!(
            "{service}.{}.amazonaws.com",
            if service == "s3" {
                text(&self.source["audit_bucket_region"])?
            } else {
                &scope.region
            }
        ))
    }

    pub(crate) fn list_parameters(&self, scope: &Scope) -> Checked<Vec<Value>> {
        let mut lower = utc_time(
            self.original_pair.reads[0].request["deadline"]
                .as_str()
                .ok_or("invalid original deadline")?,
        )?
        .min(utc_time(
            self.original_pair.reads[1].request["deadline"]
                .as_str()
                .ok_or("invalid original deadline")?,
        )?) - Duration::seconds(scope.limits.request_seconds as i64);
        lower = lower
            .max(utc_time(&scope.created_at)?)
            .with_second(0)
            .and_then(|value| value.with_nanosecond(0))
            .ok_or("invalid audit minute")?;
        let issued = utc_time(&self.issued_at)?;
        let mut day = lower.date_naive();
        let last = issued.date_naive();
        require((0..2).contains(&(last - day).num_days()))?;
        let mut rows = Vec::with_capacity(2);
        loop {
            let prefix = format!(
                "{}{}",
                text(&self.source["exact_delivery_root_prefix"])?,
                day.format("%Y/%m/%d/")
            );
            let minute = if day == lower.date_naive() {
                lower.format("%Y%m%dT%H%MZ").to_string()
            } else {
                format!("{}T0000Z", day.format("%Y%m%d"))
            };
            let cursor = format!(
                "{prefix}{}_CloudTrail_{}_{minute}_",
                scope.account_id, scope.region
            );
            require(prefix.len() <= 267 && cursor.len() <= 512)?;
            rows.push(
                json!({"Bucket":self.source["audit_bucket"],"ExpectedBucketOwner":scope.account_id,
                "Prefix":prefix,"StartAfter":cursor,"MaxKeys":16}),
            );
            if day == last {
                break;
            }
            day = day.succ_opt().ok_or("invalid audit date")?;
        }
        Ok(rows)
    }

    pub(crate) fn operation_plan(
        &self,
        scope: &Scope,
        selected: usize,
    ) -> Checked<Vec<S3PlannedCall>> {
        let maximum = self.source["audit_limits"]["files"]
            .as_u64()
            .ok_or("invalid audit files")?;
        require(selected as u64 <= maximum)?;
        let mut plan = vec![
            S3PlannedCall::new("sts", "GetCallerIdentity", "controller"),
            S3PlannedCall::new("sts", "AssumeRole", "controller"),
            S3PlannedCall::new("sts", "GetCallerIdentity", "collector"),
        ];
        for _ in self.list_parameters(scope)? {
            plan.push(S3PlannedCall::new("s3", "ListObjectsV2", "collector"));
        }
        for _ in 0..selected {
            plan.push(S3PlannedCall::new("s3", "GetObject", "collector"));
        }
        Ok(plan)
    }

    pub(crate) fn planned_resource(
        &self,
        binding: &S3WorkerBinding,
        sequence: usize,
        discovery: Option<&Discovery>,
    ) -> Checked<Value> {
        let lists = self.list_parameters(binding.scope())?;
        match sequence {
            1 | 3 => Ok(json!({})),
            2 => Ok(json!({"role_arn":self.source["collector_role_arn"],
                "session_name":format!("bf-{}-collector", &self.request_id[..32])})),
            value if value >= 4 && value < 4 + lists.len() => Ok(lists[value - 4].clone()),
            value if value >= 4 + lists.len() => {
                let committed = discovery.ok_or("audit GetObject requires committed Discovery")?;
                require(
                    committed.document["request_digest"] == binding.digest()
                        && committed.document["collection_digest"]
                            == canonical_hash(&encoded(self)?),
                )?;
                let selected = committed.document["selected"]
                    .as_array()
                    .ok_or("invalid selected audit files")?;
                let item = selected
                    .get(value - 4 - lists.len())
                    .ok_or("audit selected file absent")?;
                Ok(
                    json!({"Bucket":self.source["audit_bucket"],"ExpectedBucketOwner":binding.scope().account_id,
                    "Key":item["key"],"IfMatch":item["etag"],"size_bytes":item["size_bytes"],
                    "discovery_digest":canonical_hash(&committed.document)}),
                )
            }
            _ => Err("invalid audit send sequence"),
        }
    }

    pub(crate) fn planned_send(
        &self,
        binding: &S3WorkerBinding,
        sequence: usize,
        discovery: Option<&Discovery>,
    ) -> Checked<Value> {
        if sequence < 4 + self.list_parameters(binding.scope())?.len() {
            return binding.planned_send(sequence);
        }
        Ok(
            json!({"service":"s3","operation":"GetObject","role":"collector","method":"GET",
            "host":self.host(binding.scope(), "s3")?,
            "resource":self.planned_resource(binding, sequence, discovery)?,
            "payload_digest":format!("sha256:{}", sha256_hex(b""))}),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadReference {
    pub reader: String,
    pub run_id: String,
    pub manifest_digest: String,
    pub request_digest: String,
    pub reservation_digest: String,
    pub worker_result_digest: String,
    pub deadline: String,
}

/// Saved consistency data only. Current admission and original ledger joins are separate.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectionContext {
    pub schema_version: String,
    pub collection_digest: String,
    pub pair_digest: String,
    pub audit_source_digest: String,
    pub original_operation_id: String,
    pub phase: String,
    pub issued_at: String,
    pub deadline: String,
    pub reads: [ReadReference; 2],
}

impl Collection {
    pub(crate) fn context(&self) -> Checked<CollectionContext> {
        let reference = |read: &OriginalRead| -> Checked<ReadReference> {
            Ok(ReadReference {
                reader: read.reader.clone(),
                run_id: read.run_id.clone(),
                manifest_digest: read.manifest_digest.clone(),
                request_digest: read.request_digest.clone(),
                reservation_digest: read.reservation_digest.clone(),
                worker_result_digest: read.worker_result_digest.clone(),
                deadline: text(&read.request["deadline"])?.into(),
            })
        };
        Ok(CollectionContext {
            schema_version: "bluefire.s3-audit-collection-context.v1".into(),
            collection_digest: canonical_hash(&encoded(self)?),
            pair_digest: canonical_hash(&encoded(&self.original_pair)?),
            audit_source_digest: self.source_digest(),
            original_operation_id: self.original_pair.operation_job_id.clone(),
            phase: self.phase().into(),
            issued_at: self.issued_at.clone(),
            deadline: self.deadline.clone(),
            reads: [
                reference(&self.original_pair.reads[0])?,
                reference(&self.original_pair.reads[1])?,
            ],
        })
    }
}

impl CollectionContext {
    pub(crate) fn validate(&self, scope: &Scope, workflow: &AuditWorkflow) -> Checked<()> {
        require(
            self.schema_version == "bluefire.s3-audit-collection-context.v1"
                && digest(&self.collection_digest)
                && digest(&self.pair_digest)
                && self.audit_source_digest == workflow.source_digest()
                && job(&self.original_operation_id)
                && matches!(self.phase.as_str(), "baseline" | "retest"),
        )?;
        let mut starts = Vec::with_capacity(2);
        for (index, read) in self.reads.iter().enumerate() {
            require(
                read.reader == if index == 0 { "probe" } else { "legitimate" }
                    && read.run_id.is_ascii()
                    && read.run_id.len() == 37
                    && read.run_id.starts_with("run-")
                    && read.run_id.as_bytes()[20] == b'-'
                    && lower_hex(&read.run_id[21..], 16)
                    && chrono::NaiveDateTime::parse_from_str(&read.run_id[4..20], "%Y%m%dT%H%M%SZ")
                        .is_ok()
                    && [
                        &read.manifest_digest,
                        &read.request_digest,
                        &read.reservation_digest,
                        &read.worker_result_digest,
                    ]
                    .iter()
                    .all(|value| digest(value)),
            )?;
            let end = utc_time(&read.deadline)?;
            require(utc_time(&scope.created_at)? < end && end <= utc_time(&scope.expires_at)?)?;
            starts.push(
                utc_time(&scope.created_at)?
                    .max(end - Duration::seconds(scope.limits.request_seconds as i64)),
            );
        }
        let a = &self.reads[0];
        let b = &self.reads[1];
        require(
            a.run_id != b.run_id
                && a.manifest_digest != b.manifest_digest
                && a.request_digest != b.request_digest
                && a.reservation_digest != b.reservation_digest,
        )?;
        let issued = utc_time(&self.issued_at)?;
        let end = utc_time(&self.deadline)?;
        require(
            issued.year() >= 1000
                && end.year() >= 1000
                && starts[0].max(starts[1]) <= issued
                && issued < end
                && end <= *workflow.source_expires_at()
                && end <= issued + Duration::seconds(workflow.budget().per_batch.seconds as i64)
                && end
                    <= starts[0].min(starts[1])
                        + Duration::seconds(scope.limits.audit_seconds as i64),
        )?;
        self.list_parameters(scope, workflow)?;
        require(canonical_json(&encoded(self)?).len() <= 4096)
    }

    pub(crate) fn list_parameters(
        &self,
        scope: &Scope,
        workflow: &AuditWorkflow,
    ) -> Checked<Vec<Value>> {
        let document = workflow.document()?;
        self.parameters(scope, &document["source"])
    }

    fn parameters(&self, scope: &Scope, source: &Value) -> Checked<Vec<Value>> {
        let mut lower = utc_time(&self.reads[0].deadline)?.min(utc_time(&self.reads[1].deadline)?)
            - Duration::seconds(scope.limits.request_seconds as i64);
        lower = lower
            .max(utc_time(&scope.created_at)?)
            .with_second(0)
            .and_then(|value| value.with_nanosecond(0))
            .ok_or("invalid audit minute")?;
        let mut day = lower.date_naive();
        let last = utc_time(&self.issued_at)?.date_naive();
        require((0..2).contains(&(last - day).num_days()))?;
        let mut rows = Vec::with_capacity(2);
        loop {
            let prefix = format!(
                "{}{}",
                text(&source["exact_delivery_root_prefix"])?,
                day.format("%Y/%m/%d/")
            );
            let minute = if day == lower.date_naive() {
                lower.format("%Y%m%dT%H%MZ").to_string()
            } else {
                format!("{}T0000Z", day.format("%Y%m%d"))
            };
            let cursor = format!(
                "{prefix}{}_CloudTrail_{}_{minute}_",
                scope.account_id, scope.region
            );
            require(prefix.len() <= 267 && cursor.len() <= 512)?;
            rows.push(
                json!({"Bucket":source["audit_bucket"],"ExpectedBucketOwner":scope.account_id,
                "Prefix":prefix,"StartAfter":cursor,"MaxKeys":16}),
            );
            if day == last {
                break;
            }
            day = day.succ_opt().ok_or("invalid audit date")?;
        }
        Ok(rows)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    request_id: String,
    body_sha256: String,
    projection_digest: String,
    key_count: u64,
    is_truncated: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    kind: String,
    request_digest: String,
    collection_digest: String,
    pair_digest: String,
    reservation_digest: String,
    audit_source_digest: String,
    prefixes: Vec<(String, String)>,
    listings: Vec<Listing>,
    candidates: Vec<(usize, String, u64, String)>,
    selected: Vec<usize>,
    truncated: bool,
    completed_list_count: usize,
    next_send_sequence: usize,
}

fn key(scope: &Scope, value: &str, prefix: &str) -> Checked<()> {
    require(value.len() <= 512 && value.starts_with(prefix))?;
    let filename = value.strip_prefix(prefix).ok_or("invalid audit key")?;
    let head = format!("{}_CloudTrail_{}_", scope.account_id, scope.region);
    let suffix = filename
        .strip_prefix(&head)
        .ok_or("invalid CloudTrail filename")?;
    require(
        suffix.is_ascii()
            && suffix.len() == 39
            && &suffix[14..15] == "_"
            && suffix[15..31]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
            && &suffix[31..] == ".json.gz",
    )?;
    require(suffix.as_bytes()[8] == b'T' && suffix.as_bytes()[13] == b'Z')?;
    let day = chrono::NaiveDate::parse_from_str(&suffix[..8], "%Y%m%d")
        .map_err(|_| "invalid CloudTrail date")?;
    let hour = suffix[9..11]
        .parse::<u32>()
        .map_err(|_| "invalid CloudTrail hour")?;
    let minute = suffix[11..13]
        .parse::<u32>()
        .map_err(|_| "invalid CloudTrail minute")?;
    require(
        day.and_hms_opt(hour, minute, 0).is_some()
            && prefix.ends_with(&day.format("%Y/%m/%d/").to_string()),
    )
}

fn etag(value: &str) -> bool {
    value.is_ascii()
        && (3..=130).contains(&value.len())
        && value.starts_with('"')
        && value.ends_with('"')
        && value[1..value.len() - 1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

/// Deterministically checked metadata. Only a subsequent lease fsync may commit it.
#[derive(Clone, Debug)]
pub(crate) struct Discovery {
    document: Value,
}

impl Discovery {
    #[cfg(test)]
    pub(crate) fn from_frame(
        binding: &S3WorkerBinding,
        bytes: &[u8],
        reservation: &str,
        debits: u64,
    ) -> Checked<Self> {
        let collection = binding.audit().ok_or("audit collection absent")?;
        let context = collection.context()?;
        Self::from_origin(
            binding.scope(),
            &context,
            &collection.source,
            binding.digest(),
            reservation,
            debits,
            bytes,
        )
    }

    pub(crate) fn from_context(
        scope: &Scope,
        workflow: &AuditWorkflow,
        context: &CollectionContext,
        request: &str,
        reservation: &str,
        debits: u64,
        bytes: &[u8],
    ) -> Checked<Self> {
        context.validate(scope, workflow)?;
        Self::from_origin(
            scope,
            context,
            &workflow.document()?["source"],
            request,
            reservation,
            debits,
            bytes,
        )
    }

    fn from_origin(
        scope: &Scope,
        context: &CollectionContext,
        source: &Value,
        request: &str,
        reservation: &str,
        debits: u64,
        bytes: &[u8],
    ) -> Checked<Self> {
        // Both entry points supply the source already checked by binding/workflow validation.
        let limits: crate::s3_audit_binding::AuditLimits =
            serde_json::from_value(source["audit_limits"].clone())
                .map_err(|_| "invalid audit limits")?;
        require(bytes.len() <= MAX_LINE && bytes.last() == Some(&b'\n') && digest(reservation))?;
        let frame: Frame = serde_json::from_slice(bytes).map_err(|_| "invalid audit Discovery")?;
        let value = encoded(&frame)?;
        require(canonical_json(&value).as_bytes() == &bytes[..bytes.len() - 1])?;
        let parameters = context.parameters(scope, source)?;
        require(
            frame.kind == "discovery"
                && frame.request_digest == request
                && frame.collection_digest == context.collection_digest
                && frame.pair_digest == context.pair_digest
                && frame.audit_source_digest == context.audit_source_digest
                && frame.reservation_digest == reservation
                && frame.completed_list_count == parameters.len()
                && frame.next_send_sequence == 4 + parameters.len()
                && debits == 3 + parameters.len() as u64
                && frame.listings.len() == parameters.len()
                && frame.prefixes.len() == parameters.len()
                && frame.candidates.len() <= 32,
        )?;
        let mut objects: Vec<Vec<Value>> = vec![Vec::new(); parameters.len()];
        let mut previous_index = 0;
        for (index, suffix, size, observed_etag) in &frame.candidates {
            require(*index >= previous_index && *index < parameters.len())?;
            previous_index = *index;
            let prefix = text(&parameters[*index]["Prefix"])?;
            let name = format!("{prefix}{suffix}");
            key(scope, &name, prefix)?;
            require(etag(observed_etag) && *size <= 5 * 1024u64.pow(4))?;
            let previous = objects[*index]
                .last()
                .map(|row| text(&row["key"]))
                .transpose()?
                .unwrap_or(text(&parameters[*index]["StartAfter"])?);
            require(previous < name.as_str())?;
            objects[*index].push(json!({"key":name,"etag":observed_etag,"size_bytes":size}));
        }
        let mut ids = std::collections::BTreeSet::new();
        for (index, listing) in frame.listings.iter().enumerate() {
            let prefix = text(&parameters[index]["Prefix"])?;
            let cursor = text(&parameters[index]["StartAfter"])?;
            require(
                frame.prefixes[index] == (prefix.into(), cursor.into())
                    && request_id(&listing.request_id)
                    && ids.insert(&listing.request_id)
                    && digest(&listing.body_sha256)
                    && listing.key_count <= 16
                    && listing.key_count == objects[index].len() as u64,
            )?;
            let original = json!({"prefix":prefix,"start_after":cursor,"request_id":listing.request_id,
                "body_sha256":listing.body_sha256,"http_status":200,"retry_attempts":0,
                "key_count":listing.key_count,"is_truncated":listing.is_truncated,"objects":objects[index]});
            require(canonical_hash(&original) == listing.projection_digest)?;
        }
        let mut selected = Vec::new();
        let mut selected_rows = Vec::new();
        let mut total = 0;
        for (index, (prefix_index, suffix, size, observed_etag)) in
            frame.candidates.iter().enumerate()
        {
            if *size > 0
                && *size <= 64 * 1024
                && selected.len() < limits.files as usize
                && total + size <= limits.compressed_bytes
            {
                selected.push(index);
                selected_rows.push(json!({"key":format!("{}{}", text(&parameters[*prefix_index]["Prefix"])?, suffix),
                    "size_bytes":size,"etag":observed_etag}));
                total += size;
            }
        }
        require(
            frame.selected == selected
                && frame.truncated
                    == (frame.listings.iter().any(|row| row.is_truncated)
                        || selected.len() < frame.candidates.len()),
        )?;
        let projection = json!({"prefixes":frame.prefixes,"listings":frame.listings,"candidates":frame.candidates,
            "selected":frame.selected,"truncated":frame.truncated,"completed_list_count":frame.completed_list_count,
            "next_send_sequence":frame.next_send_sequence});
        require(
            canonical_json(&projection).len() <= 15 * 1024
                && selected_rows
                    .iter()
                    .all(|row| canonical_json(row).len() <= 896),
        )?;
        let document = json!({"schema_version":DISCOVERY_SCHEMA,"request_digest":frame.request_digest,
            "collection_digest":frame.collection_digest,"pair_digest":frame.pair_digest,
            "reservation_digest":reservation,"audit_source_digest":frame.audit_source_digest,
            "resource_key":canonical_hash(&json!({"account_id":scope.account_id,"region":scope.region,"bucket":scope.bucket})),
            "phase":context.phase,"frame_digest":canonical_hash(&value),
            "prefixes":frame.prefixes,"listings":frame.listings,"completed_list_count":frame.completed_list_count,
            "next_send_sequence":frame.next_send_sequence,"candidate_count":frame.candidates.len(),
            "selected":selected_rows,"truncated":frame.truncated});
        require(canonical_json(&document).len() <= 8192)?;
        let mut other = document.clone();
        other
            .as_object_mut()
            .ok_or("invalid audit Discovery")?
            .remove("selected");
        require(canonical_json(&other).len() <= 4096)?;
        let checked = Self { document };
        checked.journal_record()?;
        Ok(checked)
    }

    pub(crate) fn document(&self) -> &Value {
        &self.document
    }

    pub(crate) fn journal_record(&self) -> Checked<Value> {
        let record = json!({"kind":"audit_discovery","reservation_digest":self.document["reservation_digest"],"discovery":self.document});
        // Reserve space for the existing Entry schema, sequence and previous hash.
        let entry = json!({"schema_version":"bluefire.s3-send-entry.v1","sequence":4096,
            "previous_hash":format!("sha256:{}", "f".repeat(64)),"record":record});
        require(canonical_json(&entry).len() < MAX_LINE)?;
        Ok(record)
    }

    pub(crate) fn acknowledgement(&self) -> Value {
        json!({"kind":"discovery_committed","request_digest":self.document["request_digest"],
            "reservation_digest":self.document["reservation_digest"],"discovery_digest":canonical_hash(&self.document),
            "frame_digest":self.document["frame_digest"],"next_send_sequence":self.document["next_send_sequence"]})
    }

    pub(crate) fn from_durable(
        scope: &Scope,
        workflow: &AuditWorkflow,
        context: &CollectionContext,
        request: &str,
        reservation: &str,
        value: &Value,
    ) -> Checked<Self> {
        context.validate(scope, workflow)?;
        require(digest(request) && digest(reservation) && canonical_json(value).len() <= 8192)?;
        fields(value,"schema_version request_digest collection_digest pair_digest reservation_digest audit_source_digest resource_key phase frame_digest prefixes listings completed_list_count next_send_sequence candidate_count selected truncated")?;
        let parameters = context.list_parameters(scope, workflow)?;
        let prefixes: Vec<_> = parameters
            .iter()
            .map(|item| json!([item["Prefix"], item["StartAfter"]]))
            .collect();
        require(
            value["schema_version"] == DISCOVERY_SCHEMA
                && value["request_digest"] == request
                && value["reservation_digest"] == reservation
                && value["collection_digest"] == context.collection_digest
                && value["pair_digest"] == context.pair_digest
                && value["audit_source_digest"] == workflow.source_digest()
                && value["resource_key"] == workflow.resource_key()
                && value["phase"] == context.phase
                && digest(text(&value["frame_digest"])?)
                && value["prefixes"] == json!(prefixes)
                && value["completed_list_count"].as_u64() == Some(parameters.len() as u64)
                && value["next_send_sequence"].as_u64() == Some(4 + parameters.len() as u64),
        )?;
        let listings: Vec<Listing> = serde_json::from_value(value["listings"].clone())
            .map_err(|_| "invalid saved audit listings")?;
        let candidates = value["candidate_count"]
            .as_u64()
            .ok_or("invalid saved candidate count")?;
        require(listings.len() == parameters.len() && candidates <= 32)?;
        let mut ids = std::collections::BTreeSet::new();
        let mut count = 0;
        for listing in &listings {
            require(
                request_id(&listing.request_id)
                    && ids.insert(&listing.request_id)
                    && digest(&listing.body_sha256)
                    && digest(&listing.projection_digest)
                    && listing.key_count <= 16,
            )?;
            count += listing.key_count;
        }
        require(count == candidates)?;
        let selected = value["selected"]
            .as_array()
            .ok_or("invalid saved audit selection")?;
        require(
            selected.len() as u64 <= workflow.budget().per_batch.files
                && selected.len() as u64 <= candidates,
        )?;
        let mut total = 0u64;
        let mut previous = "";
        for item in selected {
            fields(item, "key etag size_bytes")?;
            require(canonical_json(item).len() <= 896)?;
            let name = text(&item["key"])?;
            let tag = text(&item["etag"])?;
            let parameters = parameters
                .iter()
                .find(|row| {
                    row["Prefix"]
                        .as_str()
                        .is_some_and(|prefix| name.starts_with(prefix))
                })
                .ok_or("saved audit key escaped original dated prefixes")?;
            key(scope, name, text(&parameters["Prefix"])?)?;
            let size = item["size_bytes"]
                .as_u64()
                .ok_or("invalid saved audit size")?;
            require(
                previous < name
                    && name > text(&parameters["StartAfter"])?
                    && etag(tag)
                    && (1..=65536).contains(&size),
            )?;
            previous = name;
            total = total.checked_add(size).ok_or("saved audit size overflow")?;
        }
        require(
            total <= workflow.budget().per_batch.compressed_bytes
                && value["truncated"].as_bool()
                    == Some(
                        listings.iter().any(|row| row.is_truncated)
                            || (selected.len() as u64) < candidates,
                    ),
        )?;
        let mut other = value.clone();
        other
            .as_object_mut()
            .ok_or("invalid Discovery")?
            .remove("selected");
        require(canonical_json(&other).len() <= 4096)?;
        let checked = Self {
            document: value.clone(),
        };
        checked.journal_record()?;
        Ok(checked)
    }
}

fn event_id(value: &str) -> bool {
    value.len() == 36
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn worker_outcome(call: Option<&Value>) -> &'static str {
    let Some(call) = call else {
        return "unreported";
    };
    match call.get("error_code").and_then(Value::as_str) {
        None => "service_success",
        Some("AccessDenied") => "service_denied",
        Some("NoSuchKey") => "object_missing",
        Some("NoSuchBucket") => "bucket_missing",
        Some(
            "ExpiredToken"
            | "InvalidToken"
            | "InvalidAccessKeyId"
            | "SignatureDoesNotMatch"
            | "RequestExpired"
            | "AuthorizationHeaderMalformed",
        ) => "credential_error",
        Some(_) => "other_service_error",
    }
}

fn correlation(read: &OriginalRead, value: &Value, delivery: &str, events: u64) -> Checked<()> {
    fields(value, "schema_version request_digest worker_result_digest reads authorized_request_window independent_collection_proven effective_access_claim")?;
    let end = utc_time(text(&read.request["deadline"])?)?;
    let start = utc_time(text(&read.request["scope"]["created_at"])?)?.max(
        end - Duration::seconds(
            read.request["scope"]["limits"]["request_seconds"]
                .as_i64()
                .ok_or("invalid original duration")?,
        ),
    );
    let iso = |value: chrono::DateTime<chrono::FixedOffset>| {
        value.to_rfc3339_opts(
            if value.timestamp_subsec_micros() == 0 {
                SecondsFormat::Secs
            } else {
                SecondsFormat::Micros
            },
            false,
        )
    };
    require(
        value["schema_version"] == "bluefire.s3-audit-correlation.v1"
            && value["request_digest"] == read.request_digest
            && value["worker_result_digest"] == read.worker_result_digest
            && value["independent_collection_proven"] == false
            && value["effective_access_claim"] == false
            && value["authorized_request_window"] == json!({"from":iso(start),"through":iso(end)}),
    )?;
    let rows = value["reads"]
        .as_array()
        .ok_or("invalid audit correlation reads")?;
    let objects = read.request["scope"]["objects"]
        .as_array()
        .ok_or("invalid original objects")?;
    let calls = read.result["calls"]
        .as_array()
        .ok_or("invalid original calls")?;
    require(rows.len() == if read.reader == "probe" { 1 } else { 2 })?;
    for (index, row) in rows.iter().enumerate() {
        fields(row, "purpose reader status worker_outcome worker_request_id audit_event_ids audit_outcomes full_object_bytes_proven")?;
        let call = calls.get(index + 3);
        let outcome = worker_outcome(call);
        require(
            row["purpose"] == objects[index]["purpose"]
                && row["reader"] == read.reader
                && row["worker_outcome"] == outcome
                && row["full_object_bytes_proven"] == false
                && row["worker_request_id"]
                    == call
                        .map(|value| value["request_id"].clone())
                        .unwrap_or(Value::Null),
        )?;
        let ids = row["audit_event_ids"]
            .as_array()
            .ok_or("invalid audit event IDs")?;
        require(ids.len() as u64 <= events)?;
        let mut unique = std::collections::BTreeSet::new();
        for id in ids {
            require(event_id(text(id)?) && unique.insert(text(id)?))?;
        }
        let outcomes = row["audit_outcomes"]
            .as_array()
            .ok_or("invalid audit outcomes")?;
        let mut previous = "";
        for value in outcomes {
            let value = text(value)?;
            require(
                previous < value
                    && [
                        "service_success",
                        "service_denied",
                        "object_missing",
                        "bucket_missing",
                        "credential_error",
                        "other_service_error",
                    ]
                    .contains(&value),
            )?;
            previous = value;
        }
        let status = text(&row["status"])?;
        if ids.is_empty() {
            require(
                outcomes.is_empty()
                    && if call.is_none() {
                        status == "worker_unreported"
                    } else if delivery == "truncated" {
                        status == "truncated"
                    } else if delivery == "unknown" {
                        status == "unknown"
                    } else {
                        ["awaiting_delivery", "unknown"].contains(&status)
                    },
            )?;
        } else {
            require(
                call.is_some()
                    && ["matched", "conflict"].contains(&status)
                    && !outcomes.is_empty()
                    && (status != "matched" || *outcomes == vec![json!(outcome)]),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn validate_result(
    binding: &S3WorkerBinding,
    row: &Value,
    debits: u64,
    committed: Option<&Discovery>,
) -> Checked<bool> {
    fields(row, "schema_version request_digest outcome data problem send_permits_consumed calls runtime_isolation_proven")?;
    require(
        canonical_json(&json!({"kind":"result","result":row})).len() < MAX_LINE
            && canonical_json(row).len() <= 15 * 1024
            && row["schema_version"] == RESULT_SCHEMA
            && row["request_digest"] == binding.digest()
            && row["runtime_isolation_proven"] == false
            && ["observed", "failed"].contains(&text(&row["outcome"])?),
    )?;
    let consumed = row["send_permits_consumed"]
        .as_u64()
        .ok_or("invalid audit send count")?;
    let calls = row["calls"].as_array().ok_or("invalid audit calls")?;
    require(consumed <= debits && debits <= 9 && calls.len() as u64 <= consumed)?;
    let collection = binding.audit().ok_or("audit collection absent")?;
    let observed = row["outcome"] == "observed";
    let mut count = if let Some(discovery) = committed {
        discovery.document["selected"]
            .as_array()
            .ok_or("invalid audit selection")?
            .len()
    } else {
        collection.source["audit_limits"]["files"]
            .as_u64()
            .ok_or("invalid audit files")? as usize
    };
    if observed {
        let committed = committed.ok_or("audit result lacks original committed Discovery")?;
        let data = &row["data"];
        fields(data, "schema_version collection_digest pair_digest audit_source_digest reservation_digest discovery objects usage normalized_digest correlations delivery_state effective_access_claim log_integrity_proven")?;
        require(
            data["schema_version"] == "bluefire.s3-audit-collection-observation.v1"
                && data["collection_digest"] == canonical_hash(&encoded(collection)?)
                && data["pair_digest"] == canonical_hash(&encoded(&collection.original_pair)?)
                && data["audit_source_digest"] == collection.source_digest()
                && data["reservation_digest"] == committed.document["reservation_digest"]
                && data["discovery"] == committed.document
                && digest(text(&data["normalized_digest"])?)
                && data["effective_access_claim"] == false
                && data["log_integrity_proven"] == false,
        )?;
        let delivery = text(&data["delivery_state"])?;
        require(
            ["incomplete", "truncated", "unknown"].contains(&delivery)
                && (committed.document["truncated"] != true || delivery == "truncated"),
        )?;
        let selected = committed.document["selected"]
            .as_array()
            .ok_or("invalid audit selection")?;
        let objects = data["objects"].as_array().ok_or("invalid audit objects")?;
        require(objects.len() == selected.len())?;
        count = objects.len();
        let mut compressed = 0u64;
        let mut expanded = 0u64;
        let mut events = 0u64;
        let (limits, _) = checked_source(
            &collection.source,
            binding.scope(),
            binding.runtime_digest(),
            binding.worker_generation(),
        )?;
        for (index, object) in objects.iter().enumerate() {
            fields(
                object,
                "selected_index compressed_sha256 expanded_sha256 expanded_bytes event_count",
            )?;
            require(
                object["selected_index"].as_u64() == Some(index as u64)
                    && digest(text(&object["compressed_sha256"])?)
                    && digest(text(&object["expanded_sha256"])?),
            )?;
            compressed = compressed
                .checked_add(
                    selected[index]["size_bytes"]
                        .as_u64()
                        .ok_or("invalid compressed size")?,
                )
                .ok_or("audit size overflow")?;
            let size = object["expanded_bytes"]
                .as_u64()
                .ok_or("invalid expanded size")?;
            require(size > 0)?;
            expanded = expanded.checked_add(size).ok_or("audit size overflow")?;
            events = events
                .checked_add(
                    object["event_count"]
                        .as_u64()
                        .ok_or("invalid event count")?,
                )
                .ok_or("audit event overflow")?;
        }
        let usage = &data["usage"];
        fields(
            usage,
            "sdk_body_bytes compressed_bytes expanded_bytes events files",
        )?;
        let wire = usage["sdk_body_bytes"]
            .as_u64()
            .ok_or("invalid SDK bytes")?;
        require(
            wire >= compressed
                && wire <= limits.sdk_body_bytes
                && compressed <= limits.compressed_bytes
                && expanded <= limits.expanded_bytes
                && events <= limits.events
                && count as u64 <= limits.files
                && usage["files"].as_u64() == Some(count as u64)
                && usage["compressed_bytes"].as_u64() == Some(compressed)
                && usage["expanded_bytes"].as_u64() == Some(expanded)
                && usage["events"].as_u64() == Some(events),
        )?;
        fields(&data["correlations"], "probe legitimate")?;
        for read in &collection.original_pair.reads {
            correlation(read, &data["correlations"][&read.reader], delivery, events)?;
        }
    } else {
        require(row["data"].is_null() && row["problem"] == "scoped_operation_failed")?;
    }
    let plan = collection.operation_plan(binding.scope(), count)?;
    require(consumed <= plan.len() as u64)?;
    let mut ids = std::collections::BTreeSet::new();
    for (index, call) in calls.iter().enumerate() {
        fields(
            call,
            if call.get("error_code").is_some() {
                "operation role request_id http_status error_code"
            } else {
                "operation role request_id http_status"
            },
        )?;
        let identifier = text(&call["request_id"])?;
        require(
            call["operation"] == plan[index].operation
                && call["role"] == plan[index].role
                && request_id(identifier)
                && ids.insert(identifier),
        )?;
        let status = call["http_status"]
            .as_u64()
            .ok_or("invalid audit HTTP status")?;
        if let Some(code) = call.get("error_code") {
            require(
                crate::s3_worker_result::valid_error(text(code)?)
                    && (400..=599).contains(&status)
                    && index + 1 == calls.len()
                    && calls.len() as u64 == consumed,
            )?;
        } else {
            require(status == 200)?;
        }
    }
    if observed {
        require(
            row["problem"].is_null()
                && consumed == plan.len() as u64
                && consumed == debits
                && calls.len() == plan.len()
                && calls.iter().all(|call| call.get("error_code").is_none()),
        )?;
        let listings = committed.ok_or("audit Discovery absent")?.document["listings"]
            .as_array()
            .ok_or("invalid listings")?;
        for (index, listing) in listings.iter().enumerate() {
            require(listing["request_id"] == calls[index + 3]["request_id"])?;
        }
    }
    Ok(observed)
}

#[cfg(test)]
#[path = "s3_audit_wire_tests.rs"]
pub(crate) mod tests;
