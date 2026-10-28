import { expect, it } from "vitest";
import { checkedFileAccessRetestLinkage } from "../src/lib/file-access-linkage";
import { linkageFixture } from "./file-access-linkage-fixture";

it("accepts exact baseline, reviewed change, and selected attempt bindings", () => {
  const { objective, attempt, value } = linkageFixture();
  expect(checkedFileAccessRetestLinkage(value, objective, attempt)).toBe(value);
});

it("accepts a recomputed result when attempt progress publication is absent", () => {
  const { objective, attempt, value } = linkageFixture();
  delete attempt.progress.verified_result_digest;
  expect(checkedFileAccessRetestLinkage(value, objective, attempt)).toBe(value);
});

it.each(["objective", "attempt", "control", "revision", "resource", "digest"])("rejects a foreign %s binding", field => {
  const { objective, attempt, value } = linkageFixture();
  if (field === "objective") value.objective_owner_id = `job-${"e".repeat(32)}`;
  if (field === "attempt") value.attempt_id = `attempt-${"e".repeat(32)}`;
  if (field === "control") value.control_owner_id = `job-${"e".repeat(32)}`;
  if (field === "revision") value.change.control_revision = 4;
  if (field === "resource") value.change.resource_generation = "different-resource";
  if (field === "digest") value.change.control_digest = `sha256:${"e".repeat(64)}`;
  expect(() => checkedFileAccessRetestLinkage(value, objective, attempt)).toThrow();
});

it("keeps unknown retest evidence unknown and accepts explicit incomplete cleanup", () => {
  for (const state of ["unknown", "incomplete"] as const) {
    const { objective, attempt, value } = linkageFixture(state);
    expect(checkedFileAccessRetestLinkage(value, objective, attempt)).toBe(value);
  }
});

it("accepts an unknown owner read without claiming owner or content preservation", () => {
  const { objective, attempt, value } = linkageFixture("owner-unknown");
  expect(checkedFileAccessRetestLinkage(value, objective, attempt)).toBe(value);
  value.comparison.owner_preserved = true;
  expect(() => checkedFileAccessRetestLinkage(value, objective, attempt)).toThrow();
  value.comparison.owner_preserved = null;
  value.comparison.content_preserved = true;
  expect(() => checkedFileAccessRetestLinkage(value, objective, attempt)).toThrow();
});

it("rejects completed claims when the retest outcome or cleanup contradicts them", () => {
  const { objective, attempt, value } = linkageFixture();
  value.comparison.cleanup_verified = false;
  expect(() => checkedFileAccessRetestLinkage(value, objective, attempt)).toThrow();
});

it("rejects a retest result digest from another saved attempt result", () => {
  const { objective, attempt, value } = linkageFixture();
  value.retest.result_digest = `sha256:${"e".repeat(64)}`;
  expect(() => checkedFileAccessRetestLinkage(value, objective, attempt)).toThrow();
});
