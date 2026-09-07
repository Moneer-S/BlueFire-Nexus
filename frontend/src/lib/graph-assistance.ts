import type { ReactNode } from "react";
import type { RunJob, Scenario } from "../types";
import type { GraphSelection } from "./assistance";
import { parseScenarioDocument } from "./scenario";
import { sameJson } from "./replay-review";

export interface GraphProposal {
  schema_version: "bluefire.graph-ai-proposal.v1"; proposal_job_id: string; proposal_digest: string;
  context_digest: string; catalog_digest: string; base_scenario: GraphSelection["base_scenario"];
  scenario: Scenario; validation: { valid: true }; rationale: string; assumptions: string[]; limitations: string[];
  provider: { effective_provider_id: string; model: string; used_fallback: false; attempts: number };
}
export interface GraphApplication {
  proposal_job_id: string; proposal_digest: string; reviewed_digest: string; operator_modified: boolean;
  scenario_id: string; version: number; digest: string;
}
export interface GraphEnvelope { job: RunJob; proposal: GraphProposal | null; application: GraphApplication | null; review_ready: boolean }
export type GraphDecision = { decision: "reject"; proposal_digest: string }
  | { decision: "accept"; proposal_digest: string; reviewed_digest: string; scenario: Scenario };
export interface GraphValidation { proposal_digest: string; reviewed_digest: string; scenario: Scenario; validation: { valid: true } }
export interface GraphEditorDraft { scenario: Scenario; setScenario: (value: Scenario) => void; dirty: boolean; controls: ReactNode; details: ReactNode; readOnly: boolean; statusLabel?: string; validated?: boolean; description?: string }
export const validGraphJob = (value: string) => /^job-[0-9a-f]{32}$/.test(value);
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
export function graphDocument(value: Scenario): Scenario {
  const { layout: _layout, ...document } = value;
  void _layout;
  return document;
}
export function checkedGraphEnvelope(value: GraphEnvelope, jobId: string): GraphEnvelope {
  if (value.job?.job_id !== jobId || value.job.kind !== "graph.ai.propose") throw new Error("This saved work is not the requested graph proposal.");
  if (typeof value.review_ready !== "boolean") throw new Error("The proposal's review readiness could not be checked.");
  if (value.proposal && (value.proposal.schema_version !== "bluefire.graph-ai-proposal.v1" || value.proposal.proposal_job_id !== jobId || !digest(value.proposal.proposal_digest))) throw new Error("The graph proposal could not be verified.");
  if (value.proposal) parseScenarioDocument(value.proposal.scenario);
  if (value.application && (!value.proposal || value.application.proposal_job_id !== jobId || value.application.proposal_digest !== value.proposal.proposal_digest
    || !digest(value.application.reviewed_digest) || !digest(value.application.digest) || !Number.isSafeInteger(value.application.version) || value.application.version < 1)) throw new Error("The saved experiment does not match its proposal.");
  return value;
}
const key = (job: string) => `bluefire.graph-review.${job}`;
interface GraphReviewDraft { proposal_digest: string; scenario: Scenario; decision?: GraphDecision }
export function readGraphReviewDraft(job: string, proposal: GraphProposal): GraphReviewDraft | undefined {
  try {
    const raw = sessionStorage.getItem(key(job));
    if (!raw || raw.length > 250_000) return;
    const value = JSON.parse(raw) as GraphReviewDraft;
    if (!value || value.proposal_digest !== proposal.proposal_digest) return;
    parseScenarioDocument(value.scenario);
    if (value.scenario.id !== proposal.scenario.id) return;
    if (value.decision && (value.decision.proposal_digest !== proposal.proposal_digest || !["accept", "reject"].includes(value.decision.decision)
      || (value.decision.decision === "accept" && (!digest(value.decision.reviewed_digest) || !sameJson(value.decision.scenario, graphDocument(value.scenario)))))) return;
    return value;
  } catch { return; }
}
export function storeGraphReviewDraft(job: string, value: GraphReviewDraft): boolean {
  try {
    const raw = JSON.stringify(value);
    if (raw.length > 250_000) return false;
    sessionStorage.setItem(key(job), raw);
    return sessionStorage.getItem(key(job)) === raw;
  } catch { return false; }
}
