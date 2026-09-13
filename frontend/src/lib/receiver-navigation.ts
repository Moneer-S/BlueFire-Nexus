import type { RunJob } from "../types";

export function savedExperimentPath(selection: { scenario_id: string; version: number; digest: string }, receiverJob?: string): string {
  const query = new URLSearchParams({ saved_scenario: selection.scenario_id, version: String(selection.version), digest: selection.digest });
  if (receiverJob && /^job-[0-9a-f]{32}$/.test(receiverJob)) query.set("receiver_job", receiverJob);
  return `/builder?${query}`;
}

/** Navigation only. Compare reads and validates the actual owner before any operation. */
export function receiverControlLink(job?: RunJob | null): string | undefined {
  if (!job) return;
  if (job.kind === "receiver.defense" && /^job-[0-9a-f]{32}$/.test(job.job_id)) return `/compare?receiver_job=${encodeURIComponent(job.job_id)}`;
  const marker = job.request?.receiver_defense;
  if (!marker || typeof marker !== "object" || !("parent_job_id" in marker) || typeof marker.parent_job_id !== "string" || !/^job-[0-9a-f]{32}$/.test(marker.parent_job_id)) return;
  return `/compare?receiver_job=${encodeURIComponent(marker.parent_job_id)}`;
}
