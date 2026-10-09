//! Fixed enrolled-reader methods with attempt-local metadata cleanup receipts.

use super::*;

pub(super) struct FileAccessAction {
    pub owner: bool,
}

const PROBE: ActionDescriptor = ActionDescriptor {
    action_id: crate::file_access::PROBE_ACTION,
    platforms: &[Platform::Linux],
    ..reviewed_descriptor! {
        id: "file_access.probe.non_owner.v1", version: "1.0.0",
        behavior_ids: &["file_access.probe.non_owner.v1"],
        summary: "Freshly test one enrolled generated file with its dedicated unprivileged reader.",
        schema: empty_action_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Controlled, readiness: ActionReadiness::Ready, targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "effective_access_probe" }],
        cleanup: Some("sandbox.cleanup.v1"), limits: TASK_LIMITS,
        effects: (true, false, false), receipt: true,
    }
};

static OWNER: ActionDescriptor = ActionDescriptor {
    action_id: crate::file_access::OWNER_ACTION,
    behavior_ids: &["file_access.verify.owner.v1"],
    summary: "Freshly verify the owner's unchanged read of the same enrolled generated file.",
    observation_hints: &[ObservationHint {
        source: "filesystem",
        signal: "legitimate_owner_read",
    }],
    ..PROBE
};

impl Action for FileAccessAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        if self.owner {
            &OWNER
        } else {
            &PROBE
        }
    }

    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        let _: EmptyParams = parse_params(params)?;
        Ok(Box::new(Prepared { owner: self.owner }))
    }
}

struct Prepared {
    owner: bool,
}

impl PreparedAction for Prepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let path = if self.owner {
            "fixtures/access-owner.json"
        } else {
            "fixtures/access-probe.json"
        };
        let path = authorize_path(context, path, false)?;
        let binding = context
            .profile
            .file_access_binding
            .as_ref()
            .ok_or_else(|| {
                ActionFailure::refused("file_access_binding_required", crate::file_access::REFUSAL)
            })?;
        let remaining = context
            .manifest
            .expires_at
            .signed_duration_since(crate::contract::utc_now())
            .to_std()
            .map_err(|_| {
                ActionFailure::timed_out("timed_out", "The file-access request expired.")
            })?;
        let observation = crate::file_access::observe(
            binding,
            &context.manifest.request_hash,
            self.owner,
            remaining.min(Duration::from_millis(context.manifest.limits.timeout_ms)),
            &context.execution_started,
        )
        .map_err(|_| {
            if context.execution_started.get() {
                ActionFailure::failed("file_access_unavailable", crate::file_access::REFUSAL)
            } else {
                ActionFailure::refused("file_access_unavailable", crate::file_access::REFUSAL)
            }
        })?;
        retain_observation(context, &path, observation)
    }
}

fn retain_observation(
    context: &ActionContext<'_>,
    path: &str,
    observation: Value,
) -> Result<ActionOutcome, ActionFailure> {
    context.mark_execution_started();
    let bytes = crate::canonical::canonical_json(&observation).into_bytes();
    if bytes.len() > crate::file_access::MAX_REPORT
        || bytes.len() as u64 > context.manifest.limits.max_artifact_bytes
        || context.manifest.limits.max_files < 1
    {
        return Err(ActionFailure::refused(
            "artifact_limit",
            "The file-access observation exceeds its reviewed report bound.",
        ));
    }
    let target = context
        .root
        .prepare_new_file(path)
        .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
    let intent = begin_receipt(
        context,
        receipt_paths(target.relative.clone(), &bytes, &target.created_directories),
    )?;
    context
        .root
        .write_new(&target, &bytes, &intent)
        .map_err(|_| {
            ActionFailure::failed(
                "file_access_report_failed",
                "The observation report could not be retained.",
            )
        })?;
    let receipt = commit_receipt(context, &intent)?;
    Ok(ActionOutcome::success(json!({"observation":observation,"report":{"path":path,"sha256":crate::contract::sha256_hex(&bytes),"size":bytes.len()}})).with_receipt(receipt))
}

#[cfg(test)]
#[path = "file_access_tests.rs"]
mod tests;
