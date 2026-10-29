import { expect, it } from "vitest";
import { checkedCompositionContext, checkedCompositionObjective, checkedCompositionProposal, checkedCompositionReview, compositionCanRevise, compositionPack, compositionRequestPack, RECEIVER_PACK } from "../src/lib/composition";
import { checkedCompositionEvidenceContext } from "../src/lib/composition-evidence";
import { checkedRetainedArtifacts, RECEIVER_RETAINED_PACK } from "../src/lib/composition-retained";
import { controlId, ownerId, proposalId, reviewFixture } from "./composition-fixture";
import { retainedFixture, retainedFreshRecoveryFixture, retainedObjectiveFixture, retainedRequestFixture, retainedReviewFixture } from "./composition-retained-fixture";

it("requires an explicit retained receiver review and keeps old receiver grants unchanged", () => {
  const review = retainedReviewFixture();
  expect(checkedCompositionReview(review, retainedRequestFixture())).toBe(review);
  expect(compositionRequestPack(retainedRequestFixture())).toBe(RECEIVER_RETAINED_PACK);
  expect(compositionPack(reviewFixture())).toBe(RECEIVER_PACK);
  expect(() => checkedCompositionReview(review, { control_owner_id: controlId, question: review.objective.question, limits: null })).toThrow();
  const objective = retainedObjectiveFixture();
  expect(checkedCompositionObjective(objective, ownerId, controlId, RECEIVER_RETAINED_PACK)).toBe(objective);
});
it.each([false, true])("accepts retained v3 graph results with selected history=%s", history => {
  const { objective, context, proposal, knowledge, prior } = retainedFixture(history);
  expect(checkedCompositionObjective(objective, ownerId)).toBe(objective);
  expect(compositionCanRevise(objective.attempts[1]!, objective)).toBe(true);
  if (history) expect(checkedCompositionEvidenceContext(context as import("../src/lib/composition-evidence").CompositionEvidenceContext, objective.grant.document.grant_id, ownerId, knowledge, prior)).toBe(context);
  else expect(checkedCompositionContext(context as import("../src/lib/composition").CompositionContext, objective.grant.document.grant_id, RECEIVER_RETAINED_PACK)).toBe(context);
  expect(checkedCompositionProposal(proposal, proposalId, ownerId)).toBe(proposal);
});
it.each([
  ["unknown source availability", (value: ReturnType<typeof retainedFixture>) => { Object.assign(value.context.retained_artifacts!, { availability: "unknown" }); }],
  ["source tuple field expansion", (value: ReturnType<typeof retainedFixture>) => { Object.assign(value.source, { payload_hex: "private bytes" }); }],
  ["source beyond cap", (value: ReturnType<typeof retainedFixture>) => { value.source.size_bytes = 262_145; }],
  ["source outside available set", (value: ReturnType<typeof retainedFixture>) => { value.proposal.proposal!.candidate.steps[0]!.parameters.source_ref = `sha256:${"f".repeat(64)}`; }],
  ["changed retained policy", (value: ReturnType<typeof retainedFixture>) => { value.context.retained_artifacts = { ...value.context.retained_artifacts!, policy: { ...value.context.retained_artifacts!.policy, max_artifacts_per_attempt: 2 } as never }; }],
  ["invented historical reasoning", (value: ReturnType<typeof retainedFixture>) => { value.proposal.proposal!.reconsideration = { reconsidered_choices: [], refresh_requirements: [] }; }],
  ["downgraded retained result", (value: ReturnType<typeof retainedFixture>) => { value.proposal.proposal!.schema_version = "bluefire.composition-ai-result.v2"; }],
] as const)("rejects %s", (_label, mutate) => {
  const value = retainedFixture(); mutate(value);
  expect(() => checkedCompositionProposal(value.proposal, proposalId, ownerId)).toThrow();
});
it("keeps unavailable custody separate from historical retained continuation", () => {
  const { context, objective } = retainedFixture();
  context.retained_artifacts = { ...context.retained_artifacts!, available_sources: [], availability: "none_available" };
  expect(checkedRetainedArtifacts(context.retained_artifacts)).toBe(context.retained_artifacts);
  expect(() => checkedRetainedArtifacts({ ...context.retained_artifacts, availability: "available" })).toThrow();
  objective.attempts[1]!.progress.settlement = "pending_cleanup";
  expect(compositionCanRevise(objective.attempts[1]!, objective)).toBe(false);
});
it("refuses review when native materialization readiness is not verified", () => {
  const review = retainedReviewFixture(); Object.assign(review.native_materialization!, { readiness: "unknown" });
  expect(() => checkedCompositionReview(review, retainedRequestFixture())).toThrow();
});

it("enforces the selected 256 KiB policy while leaving ordinary limits independent", () => {
  const value = retainedFixture(); value.source.size_bytes = 262_144;
  expect(checkedCompositionProposal(value.proposal, proposalId, ownerId)).toBe(value.proposal);
  const review = retainedReviewFixture();
  review.retention = { ...review.retention!, max_bytes_per_artifact: 1_048_576 } as never;
  expect(() => checkedCompositionReview(review, retainedRequestFixture())).toThrow();
});

it("accepts explicit fresh generation with no available sources and the same verified prior refusal", () => {
  const value = retainedFreshRecoveryFixture();
  expect(checkedCompositionObjective(value.objective, ownerId)).toBe(value.objective);
  expect(checkedCompositionProposal(value.freshProposal, proposalId, ownerId)).toBe(value.freshProposal);
  delete value.objective.attempts[1]!.progress.retained_continuation;
  expect(compositionCanRevise(value.objective.attempts[1]!, value.objective)).toBe(true);
  expect(value.freshProposal.proposal!.prior_attempt_id).toBe(value.prior);
  expect(value.currentContext.retained_artifacts!.available_sources).toEqual([]);
});
