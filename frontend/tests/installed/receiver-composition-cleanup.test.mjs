import assert from "node:assert/strict";
import test from "node:test";
import { receiverCompositionCleanupState } from "./receiver-guards.mjs";

const owner = { job_id: "job-" + "a".repeat(32), state: "completed", progress: { admission: { accepted: true } } };
const attempt = {
  state: "completed", request: { composition_attempt: { parent_job_id: owner.job_id } },
  progress: { settlement: "settled" },
};
const settled = { owner, grant: { status: "revoked", cleanup_state: "settled" }, attempts: [attempt] };

test("composition cleanup waits for revoked grant and terminal settled children", () => {
  assert.equal(receiverCompositionCleanupState(settled), "settled");
  assert.equal(receiverCompositionCleanupState({ ...settled, grant: { status: "revoked", cleanup_state: "pending_cleanup" } }), "unresolved");
  assert.equal(receiverCompositionCleanupState({ ...settled, attempts: [{ ...attempt, state: "running" }] }), "unresolved");
  assert.equal(receiverCompositionCleanupState({ ...settled, attempts: [{ ...attempt, progress: { settlement: "pending_cleanup" } }] }), "unresolved");
  assert.equal(receiverCompositionCleanupState({ ...settled, attempts: [{ ...attempt, progress: null }] }), "unresolved");
  assert.equal(receiverCompositionCleanupState({ ...settled, attempts: [{ ...attempt, request: { composition_attempt: { parent_job_id: "other" } } }] }), "unresolved");
  assert.equal(receiverCompositionCleanupState({ ...settled, attempts: [{ ...attempt, state: "cancelled", progress: {} }] }), "settled");
});

test("missing grant is conclusive only for a completed refused admission", () => {
  assert.equal(receiverCompositionCleanupState({ owner: { ...owner, state: "planning" }, grant: null, attempts: [] }), "unresolved");
  assert.equal(receiverCompositionCleanupState({ owner: { ...owner, progress: {} }, grant: null, attempts: [] }), "unresolved");
  assert.equal(receiverCompositionCleanupState({ owner: { ...owner, progress: { admission: { accepted: false } } }, grant: null, attempts: [] }), "no_grant");
  assert.equal(receiverCompositionCleanupState({ owner: { ...owner, progress: { admission: { accepted: false } } }, grant: null, attempts: [attempt] }), "unresolved");
});
