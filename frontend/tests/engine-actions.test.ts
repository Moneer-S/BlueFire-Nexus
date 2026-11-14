import { beforeEach, expect, it, vi } from "vitest";
import { request } from "../src/lib/api";
import { engineExperimentApi } from "../src/lib/engine-experiment-api";
import { checkedPreparedEngineAction, checkedEngineActionAcceptance } from "../src/lib/engine-actions";
import { acceptedAction, actionDigest, actionWorkspace, preparedAction } from "./engine-action-fixture";
vi.mock("../src/lib/api", () => ({ request: vi.fn() }));
beforeEach(() => vi.mocked(request).mockReset());
it("posts only the four canonical preparation fields and three submission fields", async () => {
  const workspace = actionWorkspace(), prepared = preparedAction();
  vi.mocked(request).mockResolvedValueOnce(prepared).mockResolvedValueOnce(acceptedAction());
  await engineExperimentApi.prepare({ ...workspace, authority: "must not travel" } as never);
  await engineExperimentApi.submit({ ...prepared, reviewer: "must not travel", action: "forbidden" } as never);
  expect(request).toHaveBeenNthCalledWith(1, `/engine-experiments/${workspace.experiment_id}/actions/prepare`, { method: "POST", body: JSON.stringify({ schema_version: "bluefire.engine-action-prepare-request.v1", expected_revision: 1, expected_digest: workspace.experiment_digest, workspace_digest: workspace.workspace_digest }) });
  expect(request).toHaveBeenNthCalledWith(2, `/engine-experiments/${workspace.experiment_id}/actions/submit`, { method: "POST", body: JSON.stringify({ schema_version: "bluefire.engine-action-submit.v1", preparation_id: prepared.preparation_id, protected_request_ref: prepared.protected_request_ref }) });
});
it("refuses selected or malformed workspaces before posting", async () => {
  await expect(engineExperimentApi.prepare({ ...actionWorkspace(), selected_context: { kind: "engine_attempt" } } as never)).rejects.toThrow(/canonical/);
  await expect(engineExperimentApi.prepare({ ...actionWorkspace(), experiment_id: "invalid" })).rejects.toThrow(/canonical/);
  await expect(engineExperimentApi.submit({ ...preparedAction(), preparation_id: "invalid" })).rejects.toThrow(/identity/);
  expect(request).not.toHaveBeenCalled();
});
it.each([
  { extra: true }, { effects_started_at_preparation: true }, { action_kind: "rollback_defense" }, { revision: 2 }, { workspace_digest: actionDigest("9") },
  { effect: { ...preparedAction().effect, changes_target: true } }, { approval: { ...preparedAction().approval, required: false } },
  { limits: { ...preparedAction().limits, action_limit: 513 } }, { limits: { ...preparedAction().limits, cost_limit_microunits: 1 } },
  { expires_at: "2026-02-31T12:00:00Z" }, { submission: { ...preparedAction().submission, authority: true } },
])("rejects changed preparation envelopes %j", change => {
  expect(() => checkedPreparedEngineAction({ ...preparedAction(), ...change }, actionWorkspace(), "start_baseline")).toThrow(/invalid or changed/);
});
it("validates receipt identity and exact safe fields", () => {
  expect(checkedEngineActionAcceptance(acceptedAction(), preparedAction())).toEqual(acceptedAction());
  for (const change of [{ authority: true }, { preparation_id: actionDigest("0") }, { action_kind: "apply_defense" }, { job: { job_id: "invalid", kind: "engine-attempt" } }, { transition: { revision: 2, digest: actionDigest("1") } }]) expect(() => checkedEngineActionAcceptance({ ...acceptedAction(), ...change }, preparedAction())).toThrow();
});
it("keeps controller review and check envelopes free of engine authority", () => {
  const workspace = actionWorkspace(); workspace.actions[0] = { ...workspace.actions[0]!, kind: "review_defense" };
  const prepared = { ...preparedAction(), action_kind: "review_defense", preparation_kind: "controller_transition", effect: { kind: "defense_review", summary: "Review one bounded defensive change.", changes_target: false, uses_external_engine: false }, requires_approval: false, approval: { required: false, state: "not_required", review_binding_digest: null, expires_at: null }, submission: null, limits: { wall_clock_seconds: null, action_limit: null, artifact_byte_limit: null, cost_limit_microunits: null, target_scope_digest: null, maximum_tier: null } } as const;
  expect(checkedPreparedEngineAction(prepared, workspace, "review_defense")).toEqual(prepared);
  expect(() => checkedPreparedEngineAction({ ...prepared, limits: preparedAction().limits }, workspace, "review_defense")).toThrow();
  expect(checkedEngineActionAcceptance({ ...acceptedAction(), action_kind: "review_defense", job: null, transition: { revision: 2, digest: actionDigest("1") } }, prepared).transition?.revision).toBe(2);
  expect(() => checkedEngineActionAcceptance({ ...acceptedAction(), action_kind: "review_defense", job: null, transition: { revision: 1, digest: actionDigest("1") } }, prepared)).toThrow();
  workspace.actions[0] = { ...workspace.actions[0]!, kind: "repeat_mechanism" };
  const check = { ...prepared, action_kind: "repeat_mechanism", preparation_kind: "controller_job", effect: { ...prepared.effect, kind: "controller_check" }, submission: preparedAction().submission } as const;
  expect(checkedPreparedEngineAction(check, workspace, "repeat_mechanism")).toEqual(check);
  expect(checkedEngineActionAcceptance({ ...acceptedAction(), action_kind: "repeat_mechanism", job: { job_id: acceptedAction().job!.job_id, kind: "engine-controller-check" } }, check).job?.kind).toBe("engine-controller-check");
});
it("uses v2 only for an exact enabled advertised selection", async () => {
  const workspace = actionWorkspace();
  workspace.actions = [
    { kind: "retain_defense", label: "Retain applied defensive change", enabled: true, reason: null, primary: false },
    { kind: "rollback_defense", label: "Roll back defensive change", enabled: true, reason: null, primary: false },
  ];
  const prepared = { ...preparedAction(), action_kind: "retain_defense", preparation_kind: "controller_transition", effect: { kind: "defense_disposition", summary: "Retain the applied defensive change.", changes_target: false, uses_external_engine: false }, requires_approval: false, approval: { required: false, state: "not_required", review_binding_digest: null, expires_at: null }, submission: null, limits: { wall_clock_seconds: null, action_limit: null, artifact_byte_limit: null, cost_limit_microunits: null, target_scope_digest: null, maximum_tier: null } } as const;
  vi.mocked(request).mockResolvedValue(prepared);
  await engineExperimentApi.prepare(workspace, "retain_defense");
  expect(request).toHaveBeenCalledWith(`/engine-experiments/${workspace.experiment_id}/actions/prepare`, { method: "POST", body: JSON.stringify({ schema_version: "bluefire.engine-action-prepare-request.v2", expected_revision: workspace.revision, expected_digest: workspace.experiment_digest, workspace_digest: workspace.workspace_digest, action_kind: "retain_defense" }) });
  await expect(engineExperimentApi.prepare(workspace)).rejects.toThrow(/canonical/);
  await expect(engineExperimentApi.prepare(workspace, "apply_defense")).rejects.toThrow(/canonical/);
  expect(() => checkedPreparedEngineAction(prepared, workspace, "rollback_defense")).toThrow(/invalid or changed/);
});
