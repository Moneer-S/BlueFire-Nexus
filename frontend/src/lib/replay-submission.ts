import { replaySubmittedRequest, type ReplayPreparation, type ReplaySubmissionResolution } from "./api";
import type { RunJob } from "../types";
import { sameJson } from "./replay-review";

export interface PendingReplaySubmission {
  sourceId: string;
  payload: Record<string, unknown>;
  preparation: ReplayPreparation;
  submissionId: string;
}
const storageKey = "bluefire.replay.pending-submission.v1";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const maxCharacters = 1_048_576;

export function readPendingReplay(): PendingReplaySubmission | undefined {
  try {
    const text = sessionStorage.getItem(storageKey);
    if (!text || text.length > maxCharacters) return undefined;
    const value = JSON.parse(text) as PendingReplaySubmission;
    if (!value || typeof value.sourceId !== "string" || !value.sourceId || value.sourceId.length > 200 || [...value.sourceId].some((character) => character.charCodeAt(0) < 32) || !uuid.test(value.submissionId)) return undefined;
    const prepared = value.preparation;
    if (prepared?.schema_version !== "bluefire.replay-preparation.v1" || prepared.replay_extent !== "full" || prepared.binding?.source?.run_id !== value.sourceId ||
      typeof prepared.preparation_id !== "string" || !prepared.preparation_id || !prepared.preparation_context || prepared.effects_started !== false || prepared.approval_created !== false ||
      !value.payload || typeof value.payload !== "object" || Array.isArray(value.payload) ||
      !sameJson(prepared.replay_request, value.payload) || !sameJson(prepared.binding.replay_request, value.payload) || Object.hasOwn(value.payload, "approval")) return undefined;
    return value;
  } catch { return undefined; }
}

export function storePendingReplay(value: PendingReplaySubmission): boolean {
  try {
    // This is a retry receipt, not approval. The service verifies the original
    // preparation and consumes a separate one-time approval for every Execute.
    const text = JSON.stringify(value);
    if (text.length > maxCharacters || Object.hasOwn(value.payload, "approval")) return false;
    // A later attempt must never erase an unresolved request, even if storage
    // contains an unreadable receipt. Retry only the exact original intent.
    const existing = sessionStorage.getItem(storageKey);
    if (existing !== null && !sameJson(readPendingReplay(), value)) return false;
    sessionStorage.setItem(storageKey, text);
    return sameJson(readPendingReplay(), value);
  } catch { return false; }
}

export function settlePendingReplay(job: RunJob): boolean {
  const receipt = readPendingReplay();
  if (!receipt || job.job_id !== `job-${receipt.submissionId.replaceAll("-", "")}` || job.kind !== "scenario.replay" ||
    job.request?.source_run_id !== receipt.sourceId || !sameJson(job.request.replay_request, receipt.payload) ||
    !sameJson(job.request.replay_preparation, receipt.preparation)) return false;
  return clearPendingReplay(receipt.submissionId);
}

export function settleReplayResolution(receipt: PendingReplaySubmission, result: ReplaySubmissionResolution): boolean {
  if (!sameJson(readPendingReplay(), receipt) || result?.schema_version !== "bluefire.replay-submission-resolution.v1" ||
    result.source_run_id !== receipt.sourceId || result.submission_id !== receipt.submissionId ||
    !/^sha256:[0-9a-f]{64}$/.test(result.intent_digest) || !sameJson(result.submitted_request, replaySubmittedRequest(receipt.preparation)) ||
    result.job?.job_id !== `job-${receipt.submissionId.replaceAll("-", "")}` || result.job.kind !== "scenario.replay") return false;
  if (result.outcome === "existing") return settlePendingReplay(result.job);
  const request = result.job.request;
  if (result.outcome !== "closed" || result.job.state !== "cancelled" || result.job.result_ref !== null ||
    result.job.error?.code !== "closed_submission" || result.job.progress?.phase !== "closed_submission" || result.job.progress?.effects_started !== false || result.job.approval_request != null ||
    !sameJson(request, { schema_version: "bluefire.closed-replay-submission.v1", source_run_id: receipt.sourceId,
      submitted_request: result.submitted_request, _submission: { schema_version: "bluefire.job-submission.v1", submission_id: receipt.submissionId, intent_digest: result.intent_digest } })) return false;
  return clearPendingReplay(receipt.submissionId);
}

export function clearPendingReplay(submissionId: string): boolean {
  try {
    if (readPendingReplay()?.submissionId !== submissionId) return false;
    sessionStorage.removeItem(storageKey);
    return sessionStorage.getItem(storageKey) === null;
  } catch { return false; }
}
