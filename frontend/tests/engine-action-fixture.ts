import type { EngineExperiment } from "../src/lib/engine-experiment";
import type { EngineActionAcceptance, PreparedEngineAction } from "../src/lib/engine-actions";
export const actionDigest = (character: string) => `sha256:${character.repeat(64)}`;
export function actionWorkspace(): EngineExperiment {
  return {
    schema_version: "bluefire.engine-experiment-workspace.v1", experiment_id: `experiment-${"a".repeat(32)}`, revision: 1, experiment_digest: actionDigest("b"), workspace_digest: actionDigest("c"), selected_context: null,
    objective: { title: "Tenant record isolation", summary: "Controlled local fixture", objective_ref: actionDigest("1") },
    environment: { display_name: "Disposable tenant lab", platform: "linux", disposable: true, environment_id: "fixture", environment_ref: actionDigest("2") },
    current_target: { display_name: "Tenant API", snapshot_ref: actionDigest("3"), captured_at: "2026-11-04T12:00:00Z" },
    engine_setup: { engine: { id: "strix", display_name: "Strix", version: "fixture", revision: "1".repeat(40), package_digest: actionDigest("4"), sandbox_image_digest: actionDigest("5") }, model: { provider: "fixture", id: "controlled-model", test_provider: true, data_destination: "Local test gateway", authorization_digest: actionDigest("6") } },
    authorization: { scope_ref: actionDigest("7"), scope_version: "bluefire.engine-capability-delegation.v1", wall_clock_seconds: 600, action_limit: 40, artifact_byte_limit: 1048576, cost_limit_microunits: 0 },
    actions: [{ kind: "start_baseline", enabled: true, primary: true, label: "Start baseline", reason: null }], limitations: [], defensive_change: null,
    projection: { attempts: [], checks: [], workflow_state: "ready_for_baseline" } as unknown as EngineExperiment["projection"],
  };
}
export function preparedAction(): PreparedEngineAction {
  const workspace = actionWorkspace();
  return {
    schema_version: "bluefire.engine-prepared-action.v1", preparation_id: actionDigest("d"), protected_request_ref: actionDigest("e"), experiment_id: workspace.experiment_id, revision: workspace.revision, workspace_digest: workspace.workspace_digest, experiment_digest: workspace.experiment_digest,
    action_kind: "start_baseline", preparation_kind: "engine_attempt", effect: { kind: "external_engine_attempt", summary: "Start a bounded external-engine baseline in the authorized disposable environment.", changes_target: false, uses_external_engine: true },
    requires_approval: true, approval: { required: true, state: "pending", review_binding_digest: actionDigest("f"), expires_at: "2026-11-04T12:10:00Z" },
    submission: { submission_id: "11111111-1111-4111-8111-111111111111", intent_digest: actionDigest("0") },
    limits: { wall_clock_seconds: 600, action_limit: 40, artifact_byte_limit: 1048576, cost_limit_microunits: 0, target_scope_digest: actionDigest("7"), maximum_tier: "controlled" }, prepared_at: "2026-11-04T12:00:00Z", expires_at: "2026-11-04T12:10:00Z", effects_started_at_preparation: false,
  };
}
export function acceptedAction(): EngineActionAcceptance {
  const prepared = preparedAction();
  return { schema_version: "bluefire.engine-action-acceptance.v1", receipt_id: actionDigest("8"), preparation_id: prepared.preparation_id, protected_request_ref: prepared.protected_request_ref, experiment_id: prepared.experiment_id, action_kind: prepared.action_kind, accepted_at: "2026-11-04T12:01:00Z", job: { job_id: `job-${"9".repeat(32)}`, kind: "engine-attempt" }, transition: null };
}
