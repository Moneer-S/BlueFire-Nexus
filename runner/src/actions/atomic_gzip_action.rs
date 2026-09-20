//! Registered gzip method: typed input, artifact publication and receipt ownership.
//! The separate fixed process adapter retains its existing execution boundary.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::collection::{
    check_collection_output, collection_artifact_limit, verify_collection_input,
    CollectionMethodParams,
};
use super::{
    authorize_path, begin_receipt, collection_method_schema, commit_receipt, parse_params,
    receipt_paths, Action, ActionContext, ActionDescriptor, ActionFailure, ActionOutcome,
    ActionProvenance, ActionReadiness, ObservationHint, PreparedAction, ACTION_SDK_SCHEMA_VERSION,
    ALL_PLATFORMS, BLUEFIRE_PROVENANCE, TASK_LIMITS,
};
use crate::contract::{Capability, ErrorRecord, Platform, SafetyTier, TaskStatus};
use crate::receiver_auth::valid_lower_hex_32;
use crate::safety::read_file_bounded;

struct AtomicGzipPrepared(CollectionMethodParams);

pub(super) fn atomic_gzip_failure(error: crate::atomic_gzip::GzipError) -> ActionFailure {
    use crate::atomic_gzip::GzipFailureKind;
    match error.kind {
        GzipFailureKind::Unavailable => {
            ActionFailure::blocked("atomic_gzip_unavailable", error.message)
        }
        GzipFailureKind::Failed => ActionFailure::failed("atomic_gzip_failed", error.message),
        GzipFailureKind::TimedOut => ActionFailure::timed_out("atomic_gzip_timeout", error.message),
    }
}

impl PreparedAction for AtomicGzipPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let started = Instant::now();
        let task_timeout = Duration::from_millis(context.manifest.limits.timeout_ms);
        let params = self.0;
        let limit = collection_artifact_limit(context, &Some(params.expected_sha256.clone()));
        let input = authorize_path(context, &params.input, false)?;
        let destination = authorize_path(
            context,
            &format!("{}/bundle.jsonl.gz", params.stage_variant.directory()),
            false,
        )?;
        let source = context
            .root
            .resolve_existing(&input)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let bytes = read_file_bounded(&source, limit)
            .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
        verify_collection_input(&bytes, &Some(params.expected_sha256.clone()))?;
        let remaining = context
            .manifest
            .expires_at
            .signed_duration_since(crate::contract::utc_now())
            .to_std()
            .map_err(|_| {
                ActionFailure::timed_out("atomic_gzip_timeout", "The sealed gzip deadline elapsed.")
            })?
            .min(task_timeout.saturating_sub(started.elapsed()));
        let compressed = crate::atomic_gzip::compress(
            bytes,
            (limit as usize).min(context.manifest.limits.max_stdout_bytes),
            context.manifest.limits.max_stderr_bytes,
            remaining,
        )
        .map_err(atomic_gzip_failure)?;
        check_collection_output(compressed.bytes.len(), Some(params.max_collection_bytes))
            .map_err(|failure| ActionFailure::failed(failure.code, failure.message))?;
        publish_atomic_gzip(
            context,
            &destination,
            compressed,
            &params.expected_sha256,
            started,
        )
    }
}

// Compression has already executed and been reaped. Publication failures must
// retain that execution fact, even when no output file can be created.
pub(super) fn publish_atomic_gzip(
    context: &ActionContext<'_>,
    destination: &str,
    compressed: crate::atomic_gzip::GzipOutput,
    source_sha256: &str,
    started: Instant,
) -> Result<ActionOutcome, ActionFailure> {
    let task_timeout = Duration::from_millis(context.manifest.limits.timeout_ms);
    if started.elapsed() >= task_timeout
        || crate::contract::utc_now() >= context.manifest.expires_at
    {
        return Err(ActionFailure::timed_out(
            "atomic_gzip_timeout",
            "The sealed gzip deadline elapsed before publication.",
        ));
    }
    let target = context
        .root
        .prepare_new_file(destination)
        .map_err(|error| ActionFailure::failed("path_rejected", error))?;
    let intent = begin_receipt(
        context,
        receipt_paths(
            target.relative.clone(),
            &compressed.bytes,
            &target.created_directories,
        ),
    )?;
    context
        .root
        .write_new(&target, &compressed.bytes, &intent)
        .map_err(|error| ActionFailure::failed("atomic_gzip_write_failed", error))?;
    let receipt = commit_receipt(context, &intent)?;
    let mut outcome = ActionOutcome::success(json!({
        "artifact": target.relative, "container": "gzip", "input_count": 1,
        "source_sha256": source_sha256, "size": compressed.bytes.len(),
        "sha256": crate::contract::sha256_hex(&compressed.bytes),
        "tool": {"executable": compressed.executable, "sha256": compressed.executable_sha256,
                 "arguments": ["-n", "-c"], "source_test": "cde3c2af-3485-49eb-9c1f-0ed60e9cc0af"}
    }))
    .with_receipt(receipt);
    if started.elapsed() >= task_timeout
        || crate::contract::utc_now() >= context.manifest.expires_at
    {
        outcome.status = TaskStatus::TimedOut;
        outcome.error = Some(ErrorRecord {
            code: "atomic_gzip_timeout".to_string(),
            message:
                "The gzip deadline elapsed during publication; the receipt is retained for cleanup."
                    .to_string(),
        });
    }
    Ok(outcome)
}

pub(super) struct AtomicGzipAction;
static ATOMIC_GZIP_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    platforms: &[Platform::Linux],
    provenance: ActionProvenance {
        source: "Atomic Red Team single-file gzip method, constrained BlueFire adaptation",
        reference: "388942adbd9641f4dfdcf079d7efe9a75ec0ac43:cde3c2af-3485-49eb-9c1f-0ed60e9cc0af",
        license: "MIT",
    },
    ..reviewed_descriptor! {
        id: "sandbox.collection.atomic-gzip.v1", version: "1.0.0",
        behavior_ids: &["sandbox.collection.atomic-gzip.v1"],
        summary: "Compress the bound synthetic fixture through one fixed Linux system gzip adapter.",
        schema: collection_method_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite, Capability::ProcessSpawn],
        tier: SafetyTier::Controlled, readiness: ActionReadiness::Ready, targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "archive_create" }],
        cleanup: Some("sandbox.cleanup.v1"), limits: TASK_LIMITS,
        effects: (true, false, true), receipt: true,
    }
};
impl Action for AtomicGzipAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &ATOMIC_GZIP_DESCRIPTOR
    }
    fn prepare(&self, value: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        let params: CollectionMethodParams = parse_params(value)?;
        if params.input != "fixtures/transformed.jsonl"
            || !valid_lower_hex_32(&params.expected_sha256)
            || !params.valid_output_limit()
        {
            return Err(ActionFailure::refused(
                "invalid_action_params",
                "Atomic gzip requires the exact transformed fixture and SHA-256 binding.",
            ));
        }
        Ok(Box::new(AtomicGzipPrepared(params)))
    }
}
