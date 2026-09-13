use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    archive_tar_schema, authorize_path, begin_receipt, collection_method_schema,
    collection_stage_schema, commit_receipt, parse_params, receipt_paths,
    validated_synthetic_record_object, Action, ActionContext, ActionDescriptor, ActionFailure,
    ActionOutcome, ActionReadiness, ObservationHint, PreparedAction, ACTION_SDK_SCHEMA_VERSION,
    ALL_PLATFORMS, BLUEFIRE_PROVENANCE, MAX_SYNTHETIC_RECORDS, TASK_LIMITS,
};
use crate::contract::{BoundedOutput, Capability, SafetyTier, TaskStatus};
use crate::receiver_auth::valid_lower_hex_32;
use crate::safety::read_file_bounded;

// -------------------------------------------------------------------------
// sandbox.archive.tar.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveTarParams {
    inputs: Vec<String>,
    destination: String,
}

struct ArchiveTarPrepared(ArchiveTarParams, Option<String>, Option<u64>);

fn write_tar_octal(field: &mut [u8], value: u64) -> Result<(), String> {
    let width = field
        .len()
        .checked_sub(1)
        .ok_or_else(|| "tar numeric field has no terminator space".to_string())?;
    let encoded = format!("{value:0width$o}", width = width);
    if encoded.len() > width {
        return Err("tar numeric field exceeds its deterministic width".to_string());
    }
    field[..width].copy_from_slice(encoded.as_bytes());
    field[width] = 0;
    Ok(())
}

fn tar_header(name: &str, size: usize) -> Result<[u8; 512], String> {
    if name.len() > 100 {
        return Err("archive input path exceeds the deterministic ustar name limit".to_string());
    }
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_tar_octal(&mut header[100..108], 0o644)?;
    write_tar_octal(&mut header[108..116], 0)?;
    write_tar_octal(&mut header[116..124], 0)?;
    write_tar_octal(&mut header[124..136], size as u64)?;
    write_tar_octal(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..273].copy_from_slice(b"bluefire");
    header[297..305].copy_from_slice(b"bluefire");
    let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
    let encoded = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(encoded.as_bytes());
    Ok(header)
}

fn build_deterministic_tar(files: &[(String, Vec<u8>)], max_bytes: u64) -> Result<Vec<u8>, String> {
    let mut archive = Vec::new();
    for (name, bytes) in files {
        let padded = bytes.len().div_ceil(512).saturating_mul(512);
        let projected = archive
            .len()
            .saturating_add(512)
            .saturating_add(padded)
            .saturating_add(1_024);
        if projected as u64 > max_bytes {
            return Err("deterministic archive exceeds the artifact byte limit".to_string());
        }
        archive.extend_from_slice(&tar_header(name, bytes.len())?);
        archive.extend_from_slice(bytes);
        archive.resize(archive.len() + padded.saturating_sub(bytes.len()), 0);
    }
    archive.resize(archive.len() + 1_024, 0);
    Ok(archive)
}

impl PreparedAction for ArchiveTarPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let artifact_limit = collection_artifact_limit(context, &self.1);
        if self.0.inputs.is_empty() || self.0.inputs.len() > context.manifest.limits.max_files {
            return Err(ActionFailure::blocked(
                "file_count_limit_blocked",
                "archive inputs are empty or exceed the manifest file limit",
            ));
        }
        let destination = authorize_path(context, &self.0.destination, false)?;
        let mut normalized = Vec::new();
        let mut unique = BTreeSet::new();
        for input in &self.0.inputs {
            let input = authorize_path(context, input, false)?;
            if input == destination {
                return Err(ActionFailure::blocked(
                    "path_rejected",
                    "archive destination cannot also be an input",
                ));
            }
            if !unique.insert(input.clone()) {
                return Err(ActionFailure::refused(
                    "invalid_action_params",
                    "archive inputs must not contain duplicates",
                ));
            }
            normalized.push(input);
        }
        normalized.sort();

        let mut files = Vec::new();
        let mut input_total = 0_u64;
        for input in normalized {
            let path = context
                .root
                .resolve_existing(&input)
                .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
            let remaining = artifact_limit.saturating_sub(input_total);
            let bytes = read_file_bounded(&path, remaining)
                .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
            verify_collection_input(&bytes, &self.1)?;
            input_total = input_total.saturating_add(bytes.len() as u64);
            files.push((input, bytes));
        }
        let archive = build_deterministic_tar(&files, artifact_limit)
            .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
        check_collection_output(archive.len(), self.2)?;
        let target = context
            .root
            .prepare_new_file(&destination)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(
                target.relative.clone(),
                &archive,
                &target.created_directories,
            ),
        )?;
        context
            .root
            .write_new(&target, &archive, &intent)
            .map_err(|error| ActionFailure::failed("archive_write_failed", error))?;
        let receipt_id = commit_receipt(context, &intent)?;
        Ok(ActionOutcome::success(json!({
            "artifact": target.relative,
            "format": "ustar",
            "entry_count": files.len(),
            "input_bytes": input_total,
            "size": archive.len(),
            "sha256": crate::contract::sha256_hex(&archive),
        }))
        .with_receipt(receipt_id))
    }
}

pub(super) struct ArchiveTarAction;
static ARCHIVE_TAR_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.archive.tar.v1",
        version: "1.0.0",
        behavior_ids: &["sandbox.archive.tar.v1"],
        summary: "Create a deterministic uncompressed ustar archive from bounded sandbox files.",
        schema: archive_tar_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Controlled,
        readiness: ActionReadiness::Ready,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "archive_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for ArchiveTarAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &ARCHIVE_TAR_DESCRIPTOR
    }

    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(ArchiveTarPrepared(
            parse_params(params)?,
            None,
            None,
        )))
    }
}

// -------------------------------------------------------------------------
// sandbox.collection.stage.v1

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum BundleFormat {
    Jsonl,
    Json,
}

impl BundleFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Json => "json",
        }
    }

    fn filename(self) -> &'static str {
        match self {
            Self::Jsonl => "bundle.jsonl",
            Self::Json => "bundle.json",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectionStageParams {
    inputs: Vec<String>,
    destination_directory: String,
    bundle_format: BundleFormat,
}

struct CollectionStagePrepared(CollectionStageParams, Option<String>, Option<u64>);

impl PreparedAction for CollectionStagePrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let artifact_limit = collection_artifact_limit(context, &self.1);
        let started = Instant::now();
        let deadline = Duration::from_millis(context.manifest.limits.timeout_ms);
        if self.0.inputs.len() != 1 || self.0.inputs.len() > context.manifest.limits.max_files {
            return Err(ActionFailure::blocked(
                "file_count_limit_blocked",
                "collection requires exactly one bound fixture input within the manifest file limit",
            ));
        }
        let unique_inputs = self.0.inputs.iter().collect::<BTreeSet<_>>();
        if unique_inputs.len() != self.0.inputs.len() {
            return Err(ActionFailure::refused(
                "invalid_action_params",
                "collection inputs must not contain duplicates",
            ));
        }
        let destination = authorize_path(context, &self.0.destination_directory, false)?;
        let bundle_relative = format!("{destination}/{}", self.0.bundle_format.filename());
        let mut input_bytes = 0_u64;
        let mut records = Vec::new();
        let mut fixture_template: Option<String> = None;
        let mut fixture_redacted: Option<bool> = None;
        for input in &self.0.inputs {
            if started.elapsed() >= deadline {
                return Err(ActionFailure::timed_out(
                    "collection_timeout",
                    "collection parsing exceeded its deadline",
                ));
            }
            let normalized = authorize_path(context, input, false)?;
            let source = context
                .root
                .resolve_existing(&normalized)
                .map_err(|error| ActionFailure::failed("collection_input_failed", error))?;
            let remaining = artifact_limit.saturating_sub(input_bytes);
            let bytes = read_file_bounded(&source, remaining)
                .map_err(|error| ActionFailure::failed("collection_input_failed", error))?;
            verify_collection_input(&bytes, &self.1)?;
            input_bytes = input_bytes.saturating_add(bytes.len() as u64);
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                ActionFailure::failed(
                    "collection_parse_failed",
                    "collection input is not UTF-8 JSONL",
                )
            })?;
            let initial_record_count = records.len();
            for (line_index, line) in text.lines().enumerate() {
                if started.elapsed() >= deadline {
                    return Err(ActionFailure::timed_out(
                        "collection_timeout",
                        "collection parsing exceeded its deadline",
                    ));
                }
                if line.trim().is_empty() {
                    return Err(ActionFailure::failed(
                        "collection_parse_failed",
                        format!("collection JSONL record {} is empty", line_index + 1),
                    ));
                }
                if records.len() == MAX_SYNTHETIC_RECORDS {
                    return Err(ActionFailure::blocked(
                        "record_count_limit_blocked",
                        "collection inputs exceed the compiled aggregate record limit",
                    ));
                }
                let record = serde_json::from_str::<Value>(line).map_err(|_| {
                    ActionFailure::failed(
                        "collection_parse_failed",
                        format!("collection JSONL record {} is invalid", line_index + 1),
                    )
                })?;
                let object = validated_synthetic_record_object(
                    record,
                    line_index + 1,
                    records.len() - initial_record_count + 1,
                    "collection_parse_failed",
                )?;
                let template = object["template"]
                    .as_str()
                    .expect("validated synthetic template is a string");
                let is_redacted = object["value"].as_str() == Some("synthetic-redacted");
                if fixture_template
                    .as_deref()
                    .is_some_and(|expected| expected != template)
                    || fixture_redacted.is_some_and(|expected| expected != is_redacted)
                {
                    return Err(ActionFailure::failed(
                        "collection_parse_failed",
                        "collection input mixes templates or redaction states",
                    ));
                }
                fixture_template.get_or_insert_with(|| template.to_string());
                fixture_redacted.get_or_insert(is_redacted);
                records.push(Value::Object(object));
            }
            if records.len() == initial_record_count {
                return Err(ActionFailure::failed(
                    "collection_parse_failed",
                    "collection input contains no JSONL records",
                ));
            }
        }

        let record_count = records.len();
        let mut bundle_bytes = Vec::new();
        match self.0.bundle_format {
            BundleFormat::Jsonl => {
                for record in &records {
                    if started.elapsed() >= deadline {
                        return Err(ActionFailure::timed_out(
                            "collection_timeout",
                            "collection bundling exceeded its deadline",
                        ));
                    }
                    let encoded = crate::contract::canonical_json(record);
                    bundle_bytes.extend_from_slice(encoded.as_bytes());
                    bundle_bytes.push(b'\n');
                    if bundle_bytes.len() as u64 > artifact_limit {
                        return Err(ActionFailure::blocked(
                            "artifact_limit_blocked",
                            "deterministic staging bundle exceeds the manifest artifact limit",
                        ));
                    }
                }
            }
            BundleFormat::Json => {
                bundle_bytes.extend_from_slice(b"{\"records\":[");
                for (index, record) in records.iter().enumerate() {
                    if started.elapsed() >= deadline {
                        return Err(ActionFailure::timed_out(
                            "collection_timeout",
                            "collection bundling exceeded its deadline",
                        ));
                    }
                    if index > 0 {
                        bundle_bytes.push(b',');
                    }
                    let encoded = crate::contract::canonical_json(record);
                    bundle_bytes.extend_from_slice(encoded.as_bytes());
                    if bundle_bytes.len() as u64 > artifact_limit {
                        return Err(ActionFailure::blocked(
                            "artifact_limit_blocked",
                            "deterministic staging bundle exceeds the manifest artifact limit",
                        ));
                    }
                }
                bundle_bytes
                    .extend_from_slice(b"],\"schema_version\":\"bluefire.synthetic-bundle.v1\"}");
                bundle_bytes.push(b'\n');
            }
        }
        if bundle_bytes.len() as u64 > artifact_limit {
            return Err(ActionFailure::blocked(
                "artifact_limit_blocked",
                "deterministic staging bundle exceeds the manifest artifact limit",
            ));
        }
        if started.elapsed() >= deadline {
            return Err(ActionFailure::timed_out(
                "collection_timeout",
                "collection bundling exceeded its deadline",
            ));
        }

        check_collection_output(bundle_bytes.len(), self.2)?;
        let target = context
            .root
            .prepare_new_file(&bundle_relative)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(
                target.relative.clone(),
                &bundle_bytes,
                &target.created_directories,
            ),
        )?;
        context
            .root
            .write_new(&target, &bundle_bytes, &intent)
            .map_err(|error| ActionFailure::failed("collection_write_failed", error))?;
        let receipt_id = commit_receipt(context, &intent)?;
        let digest = crate::contract::sha256_hex(&bundle_bytes);
        Ok(ActionOutcome {
            status: TaskStatus::Success,
            output: json!({
                "artifact": bundle_relative,
                "format": self.0.bundle_format.as_str(),
                "input_count": self.0.inputs.len(),
                "accepted_input_count": self.0.inputs.len(),
                "rejected_input_count": 0,
                "record_count": record_count,
                "sha256": digest,
                "size": bundle_bytes.len(),
                "complete": true,
            }),
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
            receipt_ids: vec![receipt_id],
            cleanup: None,
            error: None,
            limitations: Vec::new(),
        })
    }
}

pub(super) struct CollectionStageAction;
static COLLECTION_STAGE_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.collection.stage.v1",
        version: "2.0.0",
        behavior_ids: &["sandbox.collection.stage.v1"],
        summary: "Aggregate bounded synthetic JSONL records into one deterministic JSON or JSONL bundle.",
        schema: collection_stage_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Controlled,
        readiness: ActionReadiness::Ready,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for CollectionStageAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &COLLECTION_STAGE_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(CollectionStagePrepared(
            parse_params(params)?,
            None,
            None,
        )))
    }
}

// Compatible collection methods bind the identical transformed input digest.
// Legacy action IDs keep their original parameter and result contracts.
pub(super) fn collection_artifact_limit(
    context: &ActionContext<'_>,
    expected: &Option<String>,
) -> u64 {
    context
        .manifest
        .limits
        .max_artifact_bytes
        .min(if expected.is_some() {
            1_048_576
        } else {
            u64::MAX
        })
}

pub(super) fn verify_collection_input(
    bytes: &[u8],
    expected: &Option<String>,
) -> Result<(), ActionFailure> {
    if expected
        .as_ref()
        .is_some_and(|digest| crate::contract::sha256_hex(bytes) != *digest)
    {
        return Err(ActionFailure::blocked(
            "collection_input_identity_mismatch",
            "the independently read collection input differs from the bound discovery artifact",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CollectionStageVariant {
    Primary,
    Heldout,
}

impl CollectionStageVariant {
    pub(super) fn directory(self) -> &'static str {
        match self {
            Self::Primary => "staged/collection",
            Self::Heldout => "staged/variation",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollectionMethodParams {
    pub(super) input: String,
    pub(super) expected_sha256: String,
    pub(super) stage_variant: CollectionStageVariant,
    #[serde(default = "default_collection_byte_limit")]
    pub(super) max_collection_bytes: u64,
}

fn default_collection_byte_limit() -> u64 {
    1_048_576
}

impl CollectionMethodParams {
    pub(super) fn valid_output_limit(&self) -> bool {
        (1..=1_048_576).contains(&self.max_collection_bytes)
    }
}

pub(super) fn check_collection_output(
    size: usize,
    limit: Option<u64>,
) -> Result<(), ActionFailure> {
    if limit.is_some_and(|limit| size as u64 > limit) {
        return Err(ActionFailure::blocked(
            "collection_output_limit",
            "The collection exceeds its reviewed output byte limit; no output file was written.",
        ));
    }
    Ok(())
}

struct CollectionMethodPrepared {
    params: CollectionMethodParams,
    archive: bool,
}

impl PreparedAction for CollectionMethodPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let params = self.params;
        let directory = params.stage_variant.directory();
        let expected = Some(params.expected_sha256.clone());
        let (mut outcome, container) = if self.archive {
            (
                Box::new(ArchiveTarPrepared(
                    ArchiveTarParams {
                        inputs: vec![params.input],
                        destination: format!("{directory}/bundle.tar"),
                    },
                    expected,
                    Some(params.max_collection_bytes),
                ))
                .execute(context)?,
                "ustar",
            )
        } else {
            (
                Box::new(CollectionStagePrepared(
                    CollectionStageParams {
                        inputs: vec![params.input],
                        destination_directory: directory.to_string(),
                        bundle_format: BundleFormat::Jsonl,
                    },
                    expected,
                    Some(params.max_collection_bytes),
                ))
                .execute(context)?,
                "jsonl",
            )
        };
        outcome.output = json!({
            "artifact": outcome.output["artifact"], "container": container,
            "input_count": 1, "source_sha256": params.expected_sha256,
            "size": outcome.output["size"], "sha256": outcome.output["sha256"],
        });
        Ok(outcome)
    }
}

pub(super) struct CollectionMethodAction {
    pub(super) archive: bool,
}

static COLLECTION_RECORDS_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.collection.records.v1", version: "1.0.0",
        behavior_ids: &["sandbox.collection.records.v1"],
        summary: "Validate and canonicalize the bound transformed fixture into a staged JSONL collection.",
        schema: collection_method_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Controlled, readiness: ActionReadiness::Ready, targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_create" }],
        cleanup: Some("sandbox.cleanup.v1"), limits: TASK_LIMITS,
        effects: (true, false, false), receipt: true,
    }
};
static COLLECTION_ARCHIVE_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.collection.archive.v1", version: "1.0.0",
        behavior_ids: &["sandbox.collection.archive.v1"],
        summary: "Archive the identical bound transformed fixture as one deterministic ustar member.",
        schema: collection_method_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Controlled, readiness: ActionReadiness::Ready, targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "archive_create" }],
        cleanup: Some("sandbox.cleanup.v1"), limits: TASK_LIMITS,
        effects: (true, false, false), receipt: true,
    }
};
impl Action for CollectionMethodAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        if self.archive {
            &COLLECTION_ARCHIVE_DESCRIPTOR
        } else {
            &COLLECTION_RECORDS_DESCRIPTOR
        }
    }
    fn prepare(&self, value: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        let params: CollectionMethodParams = parse_params(value)?;
        if params.input != "fixtures/transformed.jsonl"
            || !valid_lower_hex_32(&params.expected_sha256)
            || !params.valid_output_limit()
        {
            return Err(ActionFailure::refused(
                "invalid_action_params",
                "collection requires the exact transformed fixture and a SHA-256 binding",
            ));
        }
        Ok(Box::new(CollectionMethodPrepared {
            params,
            archive: self.archive,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_tar_has_ustar_header_and_stable_bytes() {
        let files = vec![
            ("fixtures/a.txt".to_string(), b"alpha".to_vec()),
            ("fixtures/b.txt".to_string(), b"beta".to_vec()),
        ];
        let first = build_deterministic_tar(&files, 16 * 1024).unwrap();
        let second = build_deterministic_tar(&files, 16 * 1024).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            crate::contract::sha256_hex(&first),
            "15eaefe4c669d3d02649f8edf9ee5c8387cd29237471c132b0ea43948751ea46"
        );
        assert!(build_deterministic_tar(&files, first.len() as u64 - 1).is_err());
        assert!(tar_header(&"x".repeat(101), 0).is_err());
        assert!(write_tar_octal(&mut [0_u8; 2], 8).is_err());
        assert_eq!(&first[257..263], b"ustar\0");
        assert_eq!(first.len() % 512, 0);
        assert!(first[first.len() - 1_024..].iter().all(|byte| *byte == 0));
    }
}
