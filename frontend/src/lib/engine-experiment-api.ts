import { request } from "./api";
import { checkedEngineExperiment, type EngineExperiment, type EngineWorkspaceSelection } from "./engine-experiment";
import { checkedPreparedEngineAction, checkedEngineActionAcceptance, engineActionLabels, type PreparedActionKind, type PreparedEngineAction } from "./engine-actions";

const EXPERIMENT_ID = /^experiment-[0-9a-f]{32}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const UTC_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?Z$/;
const ATTEMPT_ID = /^engine-attempt-[0-9a-f]{32}$/;
const CHECK_ID = /^controller-check-[0-9a-f]{32}$/;

export interface EngineExperimentHead {
  schema_version: "bluefire.engine-experiment-head.v1";
  experiment_id: string;
  active_revision: number;
  active_digest: string;
  created_at: string;
  updated_at: string;
}

export interface EngineExperimentList {
  schema_version: "bluefire.engine-experiment-list.v1";
  experiments: EngineExperimentHead[];
}

const exact = (value: unknown, fields: readonly string[]): value is Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((field, index) => field === expected[index]);
};

function timestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parts = UTC_TIMESTAMP.exec(value);
  const parsed = Date.parse(value);
  if (!parts || !Number.isFinite(parsed)) return false;
  const date = new Date(parsed);
  return date.getUTCFullYear() === Number(parts[1])
    && date.getUTCMonth() + 1 === Number(parts[2])
    && date.getUTCDate() === Number(parts[3])
    && date.getUTCHours() === Number(parts[4])
    && date.getUTCMinutes() === Number(parts[5])
    && date.getUTCSeconds() === Number(parts[6]);
}

function checkedHead(value: unknown): EngineExperimentHead {
  if (!exact(value, ["schema_version", "experiment_id", "active_revision", "active_digest", "created_at", "updated_at"])
    || value.schema_version !== "bluefire.engine-experiment-head.v1"
    || typeof value.experiment_id !== "string" || !EXPERIMENT_ID.test(value.experiment_id)
    || typeof value.active_digest !== "string" || !DIGEST.test(value.active_digest)
    || typeof value.active_revision !== "number" || !Number.isSafeInteger(value.active_revision) || value.active_revision < 1 || value.active_revision > 10_000
    || !timestamp(value.created_at) || !timestamp(value.updated_at)
    || Date.parse(value.updated_at) < Date.parse(value.created_at)) throw new Error("The saved engine experiment list is invalid.");
  return value as unknown as EngineExperimentHead;
}

export function checkedEngineExperimentList(value: unknown): EngineExperimentList {
  if (!exact(value, ["schema_version", "experiments"]) || value.schema_version !== "bluefire.engine-experiment-list.v1"
    || !Array.isArray(value.experiments) || value.experiments.length > 100) throw new Error("The saved engine experiment list is invalid.");
  const experiments = value.experiments.map(checkedHead);
  if (new Set(experiments.map(item => item.experiment_id)).size !== experiments.length) throw new Error("The saved engine experiment list is invalid.");
  return { schema_version: "bluefire.engine-experiment-list.v1", experiments };
}

export function engineExperimentId(value: unknown): value is string {
  return typeof value === "string" && EXPERIMENT_ID.test(value);
}

function checkedSelection(value?: EngineWorkspaceSelection | null): EngineWorkspaceSelection | null {
  if (value === undefined || value === null) return null;
  const fields = typeof value === "object" && !Array.isArray(value) ? Object.keys(value).sort() : [];
  if (fields.length !== 2 || fields[0] !== "id" || fields[1] !== "kind" || typeof value.id !== "string") throw new Error("The engine workspace selection is invalid.");
  if (value.kind === "engine_attempt" && ATTEMPT_ID.test(value.id)) return { kind: value.kind, id: value.id };
  if (value.kind === "controller_check" && CHECK_ID.test(value.id)) return { kind: value.kind, id: value.id };
  throw new Error(value.kind === "engine_attempt" ? "The engine attempt identity is invalid." : value.kind === "controller_check" ? "The controller check identity is invalid." : "The engine workspace selection is invalid.");
}

export function engineExperimentPath(experimentId: string, selection?: { kind: "engine_attempt" | "controller_check"; id: string } | null): string {
  if (!engineExperimentId(experimentId)) throw new Error("The engine experiment identity is invalid.");
  const selected = checkedSelection(selection);
  const params = new URLSearchParams({ engine_experiment: experimentId });
  if (selected?.kind === "engine_attempt") params.set("attempt", selected.id);
  if (selected?.kind === "controller_check") params.set("check", selected.id);
  return `/composition?${params}`;
}

export const engineExperimentApi = {
  prepare: async (workspace: EngineExperiment, actionKind?: PreparedActionKind) => {
    if (!engineExperimentId(workspace.experiment_id) || workspace.selected_context !== null || !Number.isSafeInteger(workspace.revision) || workspace.revision < 1 || workspace.revision > 10_000 || !DIGEST.test(workspace.experiment_digest) || !DIGEST.test(workspace.workspace_digest)) throw new Error("Reload the canonical engine workspace before reviewing this action.");
    const enabled = workspace.actions.filter(item => item.enabled && Object.hasOwn(engineActionLabels, item.kind));
    const selected = actionKind === undefined ? enabled.length === 1 ? enabled[0] : undefined : enabled.filter(item => item.kind === actionKind).length === 1 ? enabled.find(item => item.kind === actionKind) : undefined;
    if (!selected || !Object.hasOwn(engineActionLabels, selected.kind)) throw new Error("Reload the canonical engine workspace before reviewing this action.");
    const body = actionKind === undefined
      ? { schema_version: "bluefire.engine-action-prepare-request.v1", expected_revision: workspace.revision, expected_digest: workspace.experiment_digest, workspace_digest: workspace.workspace_digest }
      : { schema_version: "bluefire.engine-action-prepare-request.v2", expected_revision: workspace.revision, expected_digest: workspace.experiment_digest, workspace_digest: workspace.workspace_digest, action_kind: actionKind };
    return checkedPreparedEngineAction(await request<unknown>(`/engine-experiments/${workspace.experiment_id}/actions/prepare`, { method: "POST", body: JSON.stringify(body) }), workspace, selected.kind as PreparedActionKind);
  },
  submit: async (prepared: PreparedEngineAction) => {
    if (!engineExperimentId(prepared.experiment_id) || !DIGEST.test(prepared.preparation_id) || !DIGEST.test(prepared.protected_request_ref)) throw new Error("The prepared engine action identity is invalid.");
    return checkedEngineActionAcceptance(await request<unknown>(`/engine-experiments/${prepared.experiment_id}/actions/submit`, { method: "POST", body: JSON.stringify({ schema_version: "bluefire.engine-action-submit.v1", preparation_id: prepared.preparation_id, protected_request_ref: prepared.protected_request_ref }) }), prepared);
  },
  list: async (): Promise<EngineExperimentList> => checkedEngineExperimentList(await request<unknown>("/engine-experiments")),
  workspace: async (experimentId: string, selection?: EngineWorkspaceSelection | null): Promise<EngineExperiment> => {
    if (!engineExperimentId(experimentId)) throw new Error("The engine experiment identity is invalid.");
    const selected = checkedSelection(selection);
    const params = new URLSearchParams();
    if (selected?.kind === "engine_attempt") params.set("attempt", selected.id);
    if (selected?.kind === "controller_check") params.set("check", selected.id);
    const query = params.size ? `?${params}` : "";
    return checkedEngineExperiment(await request<unknown>(`/engine-experiments/${encodeURIComponent(experimentId)}/workspace${query}`), experimentId, selected ?? undefined);
  },
};
