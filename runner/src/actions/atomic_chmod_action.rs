//! Numeric permission changes through one reviewed GNU chmod installation.

use super::*;
use crate::native_tool_installations::NativeToolBinding;

pub(crate) const BINDING: NativeToolBinding = NativeToolBinding {
    adapter_id: "sandbox.permission.chmod.v1",
    adapter_version: "1.0.0",
    adapter_contract_digest:
        "sha256:db1c271df09ccd2c781e8b7df4e042fb33e76c90ab8cd621dc8f52dcd3a57dd8",
    tool_id: "gnu.coreutils.chmod.v1",
};
const INPUT: &str = "fixtures/transformed.jsonl";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    source_fixture_id: String,
    source_sha256: String,
    source_receipt_id: String,
    source_size: u64,
    mode: String,
}

fn schema() -> Value {
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
        "type":"object", "additionalProperties":false,
        "required":["source_fixture_id","source_sha256","source_receipt_id","source_size","mode"],
        "properties":{
            "source_fixture_id":{"type":"string","const":"transformed"},
            "source_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "source_receipt_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "source_size":{"type":"integer","minimum":1,"maximum":67108864},
            "mode":{"type":"string","enum":["0600","0640","0660","0666"]}}})
}

pub(super) struct AtomicChmodAction;
static DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    platforms: &[Platform::Linux],
    provenance: ActionProvenance {
        source: "Atomic Red Team numeric chmod method, constrained BlueFire adaptation",
        reference: "6132b92779873cb0d05bef07ba0a480d47eb1cc8:34ca1464-de9d-40c6-8c77-690adf36a135",
        license: "MIT",
    },
    ..reviewed_descriptor! {
        id: "sandbox.permission.chmod.v1", version: "1.0.0",
        behavior_ids: &["sandbox.permission.relax.v1"],
        summary: "Change numeric permission bits on one receipt-owned sample with reviewed GNU chmod.",
        schema: schema, capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite, Capability::ProcessSpawn],
        tier: SafetyTier::Controlled, readiness: ActionReadiness::Structural, targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "permission_change" }],
        cleanup: Some("sandbox.cleanup.v1"), limits: TASK_LIMITS,
        effects: (true, false, true), receipt: true,
    }
};

impl Action for AtomicChmodAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &DESCRIPTOR
    }
    fn native_tool_binding(&self) -> Option<NativeToolBinding> {
        Some(BINDING)
    }
    fn prepare(&self, value: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        let params: Params = parse_params(value)?;
        if params.source_fixture_id != "transformed"
            || !valid_lower_hex_32(&params.source_sha256)
            || !valid_lower_hex_32(&params.source_receipt_id)
            || !(1..=67108864).contains(&params.source_size)
            || !matches!(params.mode.as_str(), "0600" | "0640" | "0660" | "0666")
        {
            return Err(ActionFailure::refused(
                "invalid_action_params",
                "GNU chmod requires a receipt-bound sample and a reviewed permission mode.",
            ));
        }
        Ok(Box::new(Prepared(params)))
    }
}

struct Prepared(Params);
impl PreparedAction for Prepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let started = Instant::now();
        let timeout = context
            .manifest
            .expires_at
            .signed_duration_since(crate::contract::utc_now())
            .to_std()
            .map_err(|_| {
                ActionFailure::timed_out("timed_out", "The reviewed execution deadline elapsed.")
            })?
            .min(Duration::from_millis(context.manifest.limits.timeout_ms))
            .min(Duration::from_secs(5));
        let deadline = started.checked_add(timeout).unwrap_or(started);
        let params = self.0;
        authorize_path(context, INPUT, false)?;
        if params.source_size > context.manifest.limits.max_artifact_bytes {
            return Err(ActionFailure::refused(
                "artifact_limit",
                "The sample exceeds the approved artifact limit.",
            ));
        }
        let installation = context
            .profile
            .native_tool_installations
            .iter()
            .find(|record| record.adapter_id == BINDING.adapter_id)
            .ok_or_else(|| {
                ActionFailure::refused(
                    "native_tool_installation_required",
                    "Review the GNU chmod installation before execution.",
                )
            })?;
        BINDING
            .check_binding(installation, "linux", std::env::consts::ARCH)
            .map_err(|_| {
                ActionFailure::refused(
                    "native_tool_binding_mismatch",
                    "The tool differs from its reviewed method binding.",
                )
            })?;
        let input = context
            .root
            .open_committed_receipt_input_until(
                &params.source_receipt_id,
                &context.profile.profile_id,
                INPUT,
                &params.source_sha256,
                params.source_size,
                deadline,
            )
            .map_err(|_| {
                if Instant::now() >= deadline {
                    ActionFailure::timed_out(
                        "timed_out",
                        "The receipt input check exceeded the reviewed deadline.",
                    )
                } else {
                    ActionFailure::refused(
                        "input_not_owned",
                        "The sample lacks a matching committed creation receipt.",
                    )
                }
            })?;
        let result = crate::atomic_chmod::change_mode(
            installation,
            &input,
            context.root,
            &params.mode,
            deadline.saturating_duration_since(Instant::now()),
            (
                context.manifest.limits.max_stdout_bytes,
                context.manifest.limits.max_stderr_bytes,
            ),
        );
        let changed = match result {
            Ok(value) => value,
            Err(issue) if !issue.executed => {
                return Err(
                    if matches!(issue.code, "timed_out" | "inspection_timeout") {
                        ActionFailure::timed_out(issue.code, issue.message)
                    } else {
                        ActionFailure::refused(issue.code, issue.message)
                    },
                )
            }
            Err(issue) => {
                let mut outcome = ActionOutcome::success(
                    json!({"artifact":INPUT,"tool_executed":true,"final_mode":"unknown"}),
                )
                .with_receipt(params.source_receipt_id);
                outcome.status = if matches!(issue.code, "timed_out" | "inspection_timeout") {
                    TaskStatus::TimedOut
                } else {
                    TaskStatus::Failed
                };
                outcome.error = Some(ErrorRecord {
                    code: issue.code.into(),
                    message: issue.message.into(),
                });
                outcome.limitations.push("The tool started; final effects require independent inspection and receipt cleanup.".into());
                return Ok(outcome);
            }
        };
        let mut outcome = ActionOutcome::success(json!({
            "artifact":INPUT,"sha256":params.source_sha256,"size":params.source_size,
            "requested_mode":params.mode,"before_mode":format!("{:04o}",changed.before_mode),
            "after_mode":format!("{:04o}",changed.after_mode),"exit_code":changed.exit_code,
            "stdout_bytes":changed.stdout_bytes,"stderr_bytes":changed.stderr_bytes,
            "tool":{"installation_digest":changed.installation_digest,
                "adapter_contract_digest":BINDING.adapter_contract_digest,"tool_version":installation.tool_version}
        })).with_receipt(params.source_receipt_id);
        if changed.exit_code != Some(0) {
            outcome.status = TaskStatus::Failed;
            outcome.error = Some(ErrorRecord {
                code: "process_failed".into(),
                message: "GNU chmod exited unsuccessfully; inspect the retained mode observation."
                    .into(),
            });
        } else if format!("{:04o}", changed.after_mode) != params.mode {
            outcome.status = TaskStatus::Partial;
            outcome.error = Some(ErrorRecord {
                code: "objective_not_established".into(),
                message:
                    "GNU chmod completed but the requested permission bits were not established."
                        .into(),
            });
        }
        outcome.limitations.push("Mode bits do not establish effective access; independent filesystem observation is required.".into());
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_reviewed_modes_and_receipt_bound_inputs_are_accepted() {
        let valid = json!({"source_fixture_id":"transformed","source_sha256":"a".repeat(64),
            "source_receipt_id":"b".repeat(64),"source_size":100,"mode":"0660"});
        assert!(AtomicChmodAction.prepare(valid.clone()).is_ok());
        for (key, value) in [
            ("mode", json!("0777")),
            ("source_size", json!(0)),
            ("source_receipt_id", json!("invented")),
            ("source_sha256", json!("a".repeat(63))),
            ("source_fixture_id", json!("/etc/passwd")),
            ("executable", json!("/bin/sh")),
            ("arguments", json!(["--recursive"])),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(AtomicChmodAction.prepare(invalid).is_err(), "{key}");
        }
        assert_eq!(AtomicChmodAction.native_tool_binding(), Some(BINDING));
        assert_eq!(DESCRIPTOR.platforms, &[Platform::Linux]);
    }
}
