import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { RunJob, RunRecord } from "../types";

/** Read observations without promoting an unfinished job to a finalized result. */
export function useRetainedRun(job: RunJob | null, linkedRun: RunRecord | null) {
  const requested = Boolean(job && !linkedRun && !job.result_ref &&
    ["failed", "interrupted", "cancelled", "completed"].includes(job.state) &&
    ["scenario.run", "scenario.replay"].includes(job.kind) &&
    typeof job.progress.run_id === "string" && job.progress.run_id.length > 0);
  const runId = requested ? String(job!.progress.run_id) : undefined;
  const query = useQuery({
    queryKey: ["retained-run", job?.job_id, runId],
    enabled: requested,
    retry: false,
    queryFn: async () => {
      const record = await api.retainedRunDetail(runId!);
      if (record.run_id !== runId) throw new Error("The retained record does not match this run.");
      return record;
    },
  });
  return { requested, ...query, record: requested && query.data && query.data.run_id === runId ? query.data : null };
}
