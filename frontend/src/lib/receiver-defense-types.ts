import type { RunJob, PreflightReport, RunRecord, Scenario } from "../types";
import type { RunIntent } from "./run-assistance";
import type { ReplayPreparation } from "./api";
// Pinned receiver-defense v1 API. Existing RunJob, RunIntent, PreflightReport,
// ReplayPreparation and RunRecord are the unchanged native frontend contracts.
export type ReceiverPhase = 'baseline' | 'protected' | 'restored'
export type ReceiverPolicy = 'receiver.reviewed-records.v1' | 'receiver.redacted-only.v1'
export type ReceiverTestList = {
  schema_version: 'bluefire.receiver-defense-list.v1'
  jobs: { job_id: string; title: string; status: string; phase: ReceiverPhase | null; updated_at: string | null; native_path: string }[]
  truncated: boolean; next_cursor: string | null
}
export type SavedReceiverScenario = {
  kind: 'saved_scenario'; scenario_id: string; version: number; digest: string
}
export type ReceiverContextRequest = { selection: SavedReceiverScenario; run_intent: RunIntent }
export type ReceiverContext = {
  schema_version: 'bluefire.receiver-defense-context.v1'
  selection: SavedReceiverScenario; run_intent: RunIntent; context_digest: string
  scenario: Scenario; scenario_title: string
  eligible: boolean; reasons: { code: string; message: string }[]
  handoff: null | { stage_step_id: string; handoff_step_id: string; port: number; artifact_type: 'artifact.sandbox.bundle.v1'; container: 'jsonl' }
  policies: { policy_id: ReceiverPolicy; title: string; description: string; digest: string }[]
  availability: { supported: boolean; ready: boolean; reason: string | null; native_path: string | null }
  limitations: string[]
}
export type ReceiverSessionBinding = {
  schema_version: 'bluefire.owned-receiver-session.v1'; launch_id: string
  worker_generation: string; policy: Record<string, unknown>; policy_digest: string
  host: '127.0.0.1'; port: number; receiver_session_id: string; receiver_process_id: number
  creation_identity: string; deadline_ns: number; expires_at_ms: number
  maximum_bytes: number; maximum_decisions: 1; storage: 'memory_only'; review_digest: string
}
export type ReceiverPreparation = {
  schema_version: 'bluefire.receiver-defense-preparation.v1'
  parent_job_id: string; receiver_job_id: string; phase: ReceiverPhase
  context_digest: string; preparation_digest: string; session: ReceiverSessionBinding
  execution_kind: 'scenario.run' | 'scenario.replay'
  run_request: null | ({ scenario: Scenario } & RunIntent)
  replay_preparation: ReplayPreparation | null; preflight: PreflightReport
  baseline_artifact: null | { sha256: string; size_bytes: number }
  approval_created: false; target_effects_started: false; receiver_started: true
}
export type ReceiverDecision = {
  submission_id: string; phase: ReceiverPhase; preparation_digest: string
  decision: 'accept' | 'reject'; reviewed_by: string
}
export type ReceiverCleanup = {
  receiver: 'not_started' | 'active' | 'verified_closed' | 'uncertain'
  run: 'not_started' | 'pending' | 'complete' | 'incomplete' | 'unknown'
}
export type ReceiverPhaseResult = {
  phase: ReceiverPhase; policy_id: ReceiverPolicy; preparation_job_id: string
  execution_job_id: string; execution_kind: 'scenario.run' | 'scenario.replay'
  run_id: string; run: RunRecord; source_binding: Record<string, unknown>
  receiver_observation: Record<string, unknown>
  decision: 'accepted' | 'policy_refused' | 'insufficient_evidence'
  artifact: null | { sha256: string; size_bytes: number }
  cleanup: ReceiverCleanup
}
export type ReceiverPhaseView = {
  phase: ReceiverPhase; policy_id: ReceiverPolicy
  status: 'not_started' | 'preparing' | 'review_ready' | 'awaiting_approval' | 'running' | 'completed' | 'declined' | 'failed' | 'interrupted' | 'stopping' | 'stopped'
  prepare_allowed: boolean; review_ready: boolean
  receiver_job: RunJob | null; preparation: ReceiverPreparation | null
  decision: ReceiverDecision | null; execution_job: RunJob | null
  result: ReceiverPhaseResult | null; cleanup: ReceiverCleanup
  problem: null | { code: string; message: string }
  attempts: ReceiverAttempt[] // Earlier attempts; current attempt remains in the fields above.
}
export type ReceiverAttempt = Omit<ReceiverPhaseView, 'attempts' | 'prepare_allowed' | 'review_ready'>
export type ReceiverDefenseEnvelope = {
  schema_version: 'bluefire.receiver-defense.v1'; job: RunJob; context: ReceiverContext | null
  admission: { accepted: boolean; problem: null | { code: string; message: string } }
  phases: ReceiverPhaseView[] // Exactly baseline, protected, restored, in that order.
  status: 'active' | 'completed' | 'blocked' | 'stopping' | 'stopped'
  next_action: { kind: 'prepare_receiver' | 'review_replay' | 'approve_execute' | 'wait' | 'cleanup_required' | 'completed' | 'stopped'; phase: ReceiverPhase | null; native_path: string | null }
  can_start_new_test: boolean; limitations: string[]
}
// POST /receiver-defense/context ReceiverContextRequest -> ReceiverContext (read-only)
// POST /receiver-defense/jobs {...ReceiverContextRequest, submission_id, context_digest} -> ReceiverDefenseEnvelope
// GET /receiver-defense/jobs/{parent_id} -> ReceiverDefenseEnvelope (read-only)
// POST /receiver-defense/jobs/{parent_id}/prepare {submission_id, phase, reviewed_by} -> ReceiverDefenseEnvelope
// POST /receiver-defense/jobs/{parent_id}/review ReceiverDecision -> ReceiverDefenseEnvelope
// Native execution job review/release uses unchanged POST /jobs/{execution_id}/approve.
// Parent Stop uses unchanged POST /jobs/{parent_id}/cancel. No dedicated effects bypass.
// Job kinds: receiver.defense (owner), receiver.defense.prepare (owned session),
// scenario.run (baseline), scenario.replay (protected/restored).
// No source bytes, session identity, endpoint, arbitrary policy or task ID is supplied
// by these public requests. Prepare spawns the fixed worker and therefore has effects.
