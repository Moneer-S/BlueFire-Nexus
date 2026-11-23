//! Exact generated JSONL bytes resolved by the authenticated composition owner.
//! This action cannot read a historical path or reuse a historical receipt.

use super::*;

const MAX_BYTES: usize = 262_144;
const DESTINATION: &str = "fixtures/input.jsonl";
const CHUNK_CHARS: usize = 16_384;
const MAX_CHUNKS: usize = 32;

fn valid_source_ref(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(valid_lower_hex_32)
}

fn schema() -> Value {
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object",
    "additionalProperties":false,
    "required":["source_ref","payload_hex_chunks","expected_sha256","expected_size"],
    "properties":{
        "source_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
        "payload_hex_chunks":{"type":"array","minItems":1,"maxItems":32,"items":{
            "type":"string","minLength":2,"maxLength":16384,"pattern":"^[0-9a-f]+$"}},
        "expected_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "expected_size":{"type":"integer","minimum":1,"maximum":262144}
    }})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    source_ref: String,
    payload_hex_chunks: Vec<String>,
    expected_sha256: String,
    expected_size: usize,
}

struct Prepared(Params);

impl PreparedAction for Prepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let params = self.0;
        if context.manifest.grant_attempt.is_none() {
            return Err(ActionFailure::refused(
                "retained_grant_required",
                "retained materialization requires a claimed capability attempt",
            ));
        }
        if params.expected_size == 0
            || params.expected_size > MAX_BYTES
            || params.expected_size as u64 > context.manifest.limits.max_artifact_bytes
            || params.payload_hex_chunks.is_empty()
            || params.payload_hex_chunks.len() > MAX_CHUNKS
            || !valid_source_ref(&params.source_ref)
            || !valid_lower_hex_32(&params.expected_sha256)
            || params
                .payload_hex_chunks
                .iter()
                .enumerate()
                .any(|(index, chunk)| {
                    chunk.is_empty()
                        || chunk.len() > CHUNK_CHARS
                        || chunk.len() % 2 != 0
                        || (index + 1 < params.payload_hex_chunks.len()
                            && chunk.len() != CHUNK_CHARS)
                        || !chunk
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            || params
                .payload_hex_chunks
                .iter()
                .map(String::len)
                .sum::<usize>()
                != params.expected_size * 2
        {
            return Err(ActionFailure::refused(
                "retained_source_invalid",
                "retained source identity or byte bounds changed",
            ));
        }
        let mut bytes = Vec::with_capacity(params.expected_size);
        for chunk in &params.payload_hex_chunks {
            bytes.extend(hex::decode(chunk).map_err(|_| {
                ActionFailure::refused(
                    "retained_source_invalid",
                    "retained bytes are not canonical hex",
                )
            })?);
        }
        if crate::contract::sha256_hex(&bytes) != params.expected_sha256 {
            return Err(ActionFailure::refused(
                "retained_source_invalid",
                "retained digest differs from the resolved source",
            ));
        }
        let record_count = validate_reviewed_staged_bundle(&bytes, BundleFormat::Jsonl)?;
        let destination = authorize_path(context, DESTINATION, false)?;
        context.mark_execution_started();
        let target = context
            .root
            .prepare_new_file(&destination)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(target.relative.clone(), &bytes, &target.created_directories),
        )?;
        context
            .root
            .write_new(&target, &bytes, &intent)
            .map_err(|error| ActionFailure::failed("retained_publish_failed", error))?;
        let receipt = commit_receipt(context, &intent)?;
        Ok(ActionOutcome::success(json!({"artifact": target.relative, "sha256": params.expected_sha256,
            "size": bytes.len(), "record_count": record_count, "source_ref":params.source_ref, "format":"jsonl"}))
            .with_receipt(receipt))
    }
}

pub(super) struct RetainedMaterializeAction;
static DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    platforms: &[Platform::Linux],
    ..reviewed_descriptor! {
        id: "sandbox.collection.materialize-retained.v1",
        version: "1.0.0",
        behavior_ids: &["sandbox.collection.materialize-retained.v1"],
        summary: "Publish exact bounded generated JSONL from a sealed same-objective source.",
        schema: schema,
        capabilities: &[Capability::FilesystemWrite],
        tier: SafetyTier::Controlled,
        readiness: ActionReadiness::Ready,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "retained_materialization" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};

impl Action for RetainedMaterializeAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(Prepared(parse_params(params)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_source_reference_is_exact_and_rejects_historical_receipt_input() {
        assert!(valid_source_ref(&format!("sha256:{}", "a".repeat(64))));
        for value in [
            "a".repeat(64),
            format!("sha256:sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "A".repeat(64)),
        ] {
            assert!(!valid_source_ref(&value));
        }
        assert!(RetainedMaterializeAction
            .prepare(json!({
                "source_ref": format!("sha256:{}", "a".repeat(64)), "payload_hex_chunks":["00"],
                "expected_sha256": "a".repeat(64), "expected_size":1,
                "receipt_ids":["b".repeat(64)]
            }))
            .is_err());
    }

    #[test]
    fn retained_materialization_publishes_exact_bytes_with_new_owned_receipt() {
        let path = std::env::temp_dir().join(format!(
            "bluefire-retained-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        let root = SafeRoot::open(&path).unwrap();
        let limits = json!({"timeout_ms":60000,"max_stdout_bytes":8192,"max_stderr_bytes":8192,
            "max_artifact_bytes":1048576,"max_files":32});
        let scope = json!({"filesystem":["fixtures"],"network":[]});
        let profile: RunnerProfile = serde_json::from_value(json!({
            "schema_version":crate::contract::PROFILE_SCHEMA_VERSION,
            "profile_id":"profile:retained-unit","runner_id":"runner:unit","platform":Platform::current(),
            "sandbox_root":path,"allowed_actions":["sandbox.collection.materialize-retained.v1"],
            "capabilities":["filesystem_write"],"max_safety_tier":"controlled","target_scope":scope,
            "limits":limits,"policy_digest":"a".repeat(64)
        })).unwrap();
        let now = crate::contract::utc_now();
        let manifest: ExecutionManifest = serde_json::from_value(json!({
            "schema_version":crate::contract::MANIFEST_SCHEMA_VERSION,
            "request_id":"request:retained-unit","run_id":"run:new-unit","step_id":"reuse",
            "behavior_id":"sandbox.collection.materialize-retained.v1","action_id":"sandbox.collection.materialize-retained.v1",
            "mode":"execute","runner_id":profile.runner_id,"runner_profile_id":profile.profile_id,
            "platform":Platform::current(),"requested_at":now,"expires_at":now+chrono::Duration::minutes(1),
            "params":{},"target_scope":scope,"required_capabilities":["filesystem_write"],
            "safety_tier":"controlled","limits":limits,"cleanup_action_id":"sandbox.cleanup.v1",
            "policy_digest":profile.policy_digest,"request_hash":"b".repeat(64),
            "grant_attempt":{"schema_version":"bluefire.runner-grant-attempt.v1","issuer":"capability-grant-controller.v1",
                "grant_id":format!("grant-{}", "a".repeat(32)),"grant_digest":format!("sha256:{}", "a".repeat(64)),
                "attempt_id":format!("attempt-{}", "b".repeat(32)),"lease_digest":format!("sha256:{}", "c".repeat(64)),
                "compiled_digest":format!("sha256:{}", "d".repeat(64)),"plan_digest":format!("sha256:{}", "e".repeat(64)),
                "native_envelope_digest":format!("sha256:{}", "f".repeat(64)),"run_id":"run:new-unit",
                "issued_at":now,"expires_at":now+chrono::Duration::minutes(1),"request_hash":"b".repeat(64)}
        })).unwrap();
        let context = ActionContext {
            manifest: &manifest,
            profile: &profile,
            root: &root,
            execution_started: Cell::new(false),
        };
        let bytes = b"{\"record_id\":\"synthetic-001\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"synthetic-redacted\"}\n";
        let params = json!({"source_ref":format!("sha256:{}", "a".repeat(64)),"payload_hex_chunks":[hex::encode(bytes)],
            "expected_sha256":crate::contract::sha256_hex(bytes),"expected_size":bytes.len()});
        for (key, value) in [
            ("payload_hex_chunks", json!([""])),
            ("payload_hex_chunks", json!(["A0"])),
            ("payload_hex_chunks", json!(["000"])),
            ("payload_hex_chunks", json!(["00", "00"])),
            ("payload_hex_chunks", json!(vec!["00"; MAX_CHUNKS + 1])),
            (
                "payload_hex_chunks",
                json!(["00".repeat(CHUNK_CHARS / 2 + 1)]),
            ),
            ("expected_size", json!(MAX_BYTES + 1)),
            ("expected_sha256", json!("0".repeat(64))),
        ] {
            let mut invalid = params.clone();
            invalid[key] = value;
            assert!(RetainedMaterializeAction
                .prepare(invalid)
                .unwrap()
                .execute(&context)
                .is_err());
            assert!(!path.join(DESTINATION).exists());
            assert!(!context.execution_started.get());
        }
        let outcome = RetainedMaterializeAction
            .prepare(params.clone())
            .unwrap()
            .execute(&context)
            .unwrap();
        assert_eq!(fs::read(path.join(DESTINATION)).unwrap(), bytes);
        assert_eq!(outcome.receipt_ids.len(), 1);
        let receipt = root.load_receipt(&outcome.receipt_ids[0]).unwrap().unwrap();
        assert_eq!(
            receipt.action_id,
            "sandbox.collection.materialize-retained.v1"
        );
        assert_eq!(receipt.request_hash, manifest.request_hash);
        // Existing destinations are never overwritten or claimed again.
        assert!(RetainedMaterializeAction
            .prepare(params)
            .unwrap()
            .execute(&context)
            .is_err());
        drop(root);
        fs::remove_dir_all(path).unwrap();
    }
}
