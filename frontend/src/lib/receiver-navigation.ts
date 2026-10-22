import type { RunJob } from "../types";
import { validReceiverAssistanceSelection, type ReceiverAssistanceSelection } from "./receiver-assistance";

export function savedExperimentPath(selection: { scenario_id: string; version: number; digest: string }, receiverJob?: string): string {
  const query = new URLSearchParams({ saved_scenario: selection.scenario_id, version: String(selection.version), digest: selection.digest });
  if (receiverJob && /^job-[0-9a-f]{32}$/.test(receiverJob)) query.set("receiver_job", receiverJob);
  return `/builder?${query}`;
}

export function receiverScenarioSetupPath(selection: ReceiverAssistanceSelection): string | undefined {
  if (!isRepresentableReceiverScenarioSelection(selection)) return;
  const serialized = JSON.stringify(selection);
  if (serialized.length > 6000) return;
  const query = new URLSearchParams({
    receiver: "1",
    receiver_setup: serialized,
  });
  return `/compare?${query}`;
}

export type ReceiverScenarioSetupSelection = Extract<ReceiverAssistanceSelection, { kind: "receiver_scenario" }>;

function isRepresentableReceiverScenarioSelection(value: unknown): value is ReceiverScenarioSetupSelection {
  return validReceiverAssistanceSelection(value) && value.kind === "receiver_scenario"
    && Array.isArray(value.run_intent.collectors)
    && (!value.run_intent.action_implementations || Object.keys(value.run_intent.action_implementations).length > 0);
}

export function receiverSetupSelectionFromSearch(params: URLSearchParams): { present: boolean; setup?: ReceiverScenarioSetupSelection; invalid: boolean } {
  const values = params.getAll("receiver_setup");
  const legacyValues = ["saved_scenario", "version", "digest"].flatMap((name) => params.getAll(name));
  const present = values.length > 0 || legacyValues.length > 0;
  if (!present) return { present: false, invalid: false };
  if (params.getAll("receiver").length !== 1 || params.get("receiver") !== "1" || values.length !== 1 || legacyValues.length || values[0]!.length > 6000) return { present: true, invalid: true };
  try {
    const setup: unknown = JSON.parse(values[0]!);
    if (!isRepresentableReceiverScenarioSelection(setup)) return { present: true, invalid: true };
    return { present: true, setup, invalid: false };
  } catch {
    return { present: true, invalid: true };
  }
}

/** Navigation only. Compare reads and validates the actual owner before any operation. */
export function receiverControlLink(job?: RunJob | null): string | undefined {
  if (!job) return;
  if (job.kind === "receiver.defense" && /^job-[0-9a-f]{32}$/.test(job.job_id)) return `/compare?receiver_job=${encodeURIComponent(job.job_id)}`;
  const marker = job.request?.receiver_defense;
  if (!marker || typeof marker !== "object" || !("parent_job_id" in marker) || typeof marker.parent_job_id !== "string" || !/^job-[0-9a-f]{32}$/.test(marker.parent_job_id)) return;
  return `/compare?receiver_job=${encodeURIComponent(marker.parent_job_id)}`;
}
