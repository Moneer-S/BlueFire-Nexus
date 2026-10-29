import { expect, it } from "vitest";
import { compositionProposalActive } from "../src/lib/composition";
import { proposalFixture } from "./composition-fixture";

it.each(["queued", "planning", "awaiting_approval", "running", "paused", "cancelling"])("keeps a %s job active after its candidate is published", state => {
  const value = proposalFixture();
  value.job.state = state; value.provider_outcome = "candidate"; value.candidate_ready = false;
  expect(compositionProposalActive(value)).toBe(true);
});
it.each(["completed", "failed", "cancelled", "interrupted"])("treats durable %s as terminal even when a provider outcome is pending", state => {
  for (const outcome of ["pending", "requesting", "candidate"]) {
    const value = proposalFixture();
    value.job.state = state; value.provider_outcome = outcome; value.candidate_ready = false;
    expect(compositionProposalActive(value)).toBe(false);
  }
});
it.each(["pending", "requesting"])("preserves %s provider polling until durable terminality is known", outcome => {
  const value = proposalFixture(); value.job.state = "unknown"; value.provider_outcome = outcome;
  expect(compositionProposalActive(value)).toBe(true);
});
it("does not invent active work from an absent or unknown candidate state", () => {
  expect(compositionProposalActive(undefined)).toBe(false);
  const value = proposalFixture(); value.job.state = "unknown";
  expect(compositionProposalActive(value)).toBe(false);
});
