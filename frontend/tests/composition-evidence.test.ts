import { expect, it, vi } from "vitest";
import { checkedCompositionProposal, compositionApi } from "../src/lib/composition";
import { checkedCompositionEvidenceContext } from "../src/lib/composition-evidence";
import { request } from "../src/lib/api";
import { evidenceFixture } from "./composition-evidence-fixture";
import { ownerId, proposalId } from "./composition-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn() }));

it("captures exactly the loaded historical selection separately from the latest frontier", async () => {
  const { objective, knowledge, context, prior } = evidenceFixture();
  vi.mocked(request).mockResolvedValue(context);
  expect(checkedCompositionEvidenceContext(context, objective.grant.document.grant_id, ownerId, knowledge)).toBe(context);
  await compositionApi.evidenceContext(ownerId, prior, knowledge);
  expect(request).toHaveBeenCalledWith(`/composition/objectives/${ownerId}/proposal-context`, { method: "POST", body: JSON.stringify({ schema_version: "bluefire.composition-evidence-context-query.v1", prior_attempt_id: prior, attempt_ids: knowledge.attempts.map(attempt => attempt.attempt_id), knowledge_digest: knowledge.knowledge_digest }) });
  expect(knowledge.attempts.map(attempt => attempt.attempt_id)).not.toContain(prior);
});

it("accepts a captured v2 result with exact recorded source references", () => {
  const { proposal } = evidenceFixture();
  expect(checkedCompositionProposal(proposal, proposalId, ownerId)).toBe(proposal);
});

it.each([
  ["model context digest", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.model_context_digest = "unbound"; }],
  ["unknown result field", (value: ReturnType<typeof evidenceFixture>) => { Object.assign(value.proposal.proposal!, { refreshed: true }); }],
  ["malformed candidate", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.candidate.steps = []; }],
  ["knowledge digest", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.knowledge_digest = `sha256:${"f".repeat(64)}`; }],
  ["submitted selection", (value: ReturnType<typeof evidenceFixture>) => { (value.proposal.job.request.submitted_request as Record<string, unknown>).attempt_ids = [value.prior]; }],
  ["captured owner", (value: ReturnType<typeof evidenceFixture>) => { value.context.historical_context.attempts[0]!.findings[0]!.record_ref.owner_id = `job-${"f".repeat(32)}`; }],
  ["record reference", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.reconsideration!.reconsidered_choices[0]!.finding_refs[0]!.record_ref = { ...value.knowledge.attempts[0]!.findings[0]!.record_ref, record_hash: `sha256:${"f".repeat(64)}` }; }],
  ["choice digest", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.reconsideration!.reconsidered_choices[0]!.compiled_digest = `sha256:${"f".repeat(64)}`; }],
  ["unknown prerequisite", (value: ReturnType<typeof evidenceFixture>) => { Object.assign(value.proposal.proposal!.reconsideration!.refresh_requirements[0]!, { prerequisite: "model_approved" }); }],
  ["duplicate prerequisite", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.reconsideration!.refresh_requirements[1] = value.proposal.proposal!.reconsideration!.refresh_requirements[0]!; }],
  ["missing reasoning", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.reconsideration!.reconsidered_choices = []; }],
  ["downgraded result", (value: ReturnType<typeof evidenceFixture>) => { value.proposal.proposal!.schema_version = "bluefire.composition-ai-result.v1"; }],
] as const)("rejects mismatched or malformed v2 %s", (_label, mutate) => {
  const value = evidenceFixture(); mutate(value);
  expect(() => checkedCompositionProposal(value.proposal, proposalId, ownerId)).toThrow();
});

it("rejects a context from a different loaded selection", () => {
  const { context, objective, knowledge } = evidenceFixture();
  const changed = { ...knowledge, knowledge_digest: `sha256:${"f".repeat(64)}` };
  expect(() => checkedCompositionEvidenceContext(context, objective.grant.document.grant_id, ownerId, changed)).toThrow();
  expect(() => checkedCompositionEvidenceContext(context, objective.grant.document.grant_id, ownerId, knowledge, knowledge.attempts[0]!.attempt_id)).toThrow();
});

it("allows a reconsidered choice to cite an exact finding from another selected attempt", () => {
  const value = evidenceFixture();
  const knowledge = { ...value.knowledge, ...{ attempts: value.context.historical_context.attempts } };
  const next = structuredClone(knowledge.attempts[0]!);
  const binding = value.objective.attempts[1]!.request.composition_attempt;
  next.attempt_id = binding.attempt_id; next.job_id = value.objective.attempts[1]!.job_id; next.run_id = binding.run_id;
  next.source_binding!.run_id = binding.run_id;
  next.findings[0]!.finding_id = `finding-${"f".repeat(64)}`;
  Object.assign(next.findings[0]!.record_ref, { attempt_id: binding.attempt_id, job_id: next.job_id, run_id: next.run_id });
  value.context.historical_context.attempts.push(next);
  value.context.historical_context.attempt_ids.push(next.attempt_id);
  value.context.historical_context.choices.push({ ...value.context.historical_context.choices[0]!, attempt_id: next.attempt_id });
  value.proposal.proposal!.reconsideration!.reconsidered_choices[0]!.finding_refs = [{ finding_id: next.findings[0]!.finding_id, record_ref: next.findings[0]!.record_ref }];
  expect(checkedCompositionProposal(value.proposal, proposalId, ownerId)).toBe(value.proposal);
});
