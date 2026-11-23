import { beforeEach, describe, expect, it } from "vitest";
import { receiverFixture, receiverFixtureId } from "../../tests/receiver-defense-fixture";
import type { ReceiverDefenseEnvelope, ReceiverPhaseView } from "./receiver-defense-types";
import { checkedReceiverTest, clearReceiverPending, readReceiverPending, receiverOutcome, receiverRequestConfirmed, storeReceiverPending, type ReceiverPending } from "./receiver-defense";

const copy = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const fixture = (...args: Parameters<typeof receiverFixture>) => copy(receiverFixture(...args));
const record = (value: unknown) => value as Record<string, unknown>;
const retainedResult = (phase: ReceiverPhaseView) => { phase.receiver_job!.progress.result = copy(phase.result); };

describe("receiver control test response bindings", () => {
  beforeEach(() => sessionStorage.clear());

  it.each(["baseline", "protected", "restored"] as const)("accepts %s native review, approval and verified result", (phase) => {
    for (const stage of ["idle", "prepared", "approval", "completed"] as const) {
      const value = fixture(phase, stage);
      expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
    }
  });

  it.each(["failed", "interrupted", "cancelled"] as const)("keeps a %s preparation without invented evidence readable", (state) => {
    const value = fixture();
    const phase = value.phases[0]!;
    phase.receiver_job!.state = state;
    phase.receiver_job!.progress = {};
    phase.preparation = null;
    phase.status = state === "cancelled" ? "stopped" : state;
    phase.review_ready = false;
    phase.cleanup = { receiver: "uncertain", run: "not_started" };
    value.next_action = { kind: "cleanup_required", phase: "baseline", native_path: null };
    expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
    expect(receiverOutcome(phase)).not.toMatch(/Accepted|Prevented/);
  });

  it("keeps a reserved but unpublished interrupted preparation and its exact retry receipt", () => {
    const value = fixture();
    const phase = value.phases[0]!;
    const body = record(phase.receiver_job!.request!.submitted_request);
    const pending = { kind: "prepare", id: receiverFixtureId, body } as ReceiverPending;
    storeReceiverPending(pending);
    phase.receiver_job = null;
    phase.preparation = null;
    phase.status = "interrupted";
    phase.review_ready = false;
    expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
    expect(receiverRequestConfirmed(value, pending)).toBe(false);
    expect(readReceiverPending()).toEqual(pending);
  });

  it("renders insufficient evidence without interpreting it as policy prevention", () => {
    const value = fixture("protected", "insufficient");
    expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
    expect(receiverOutcome(value.phases[1]!)).toBe("Not enough evidence");
  });

  it("permits the phase-result publication window before the native job result link", () => {
    const value = fixture("protected", "completed");
    value.phases[1]!.execution_job!.result_ref = null;
    value.phases[1]!.execution_job!.state = "running";
    expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
  });

  it.each([
    ["owner request", (v: ReceiverDefenseEnvelope) => { record(v.job.request!.submitted_request).context_digest = `sha256:${"d".repeat(64)}`; }],
    ["prepare kind", (v: ReceiverDefenseEnvelope) => { v.phases[1]!.receiver_job!.kind = "scenario.run"; }],
    ["prepare parent", (v: ReceiverDefenseEnvelope) => { record(v.phases[1]!.receiver_job!.request!.receiver_defense).parent_job_id = "job-other"; }],
    ["prepare exact request", (v: ReceiverDefenseEnvelope) => { record(v.phases[1]!.receiver_job!.request!.submitted_request).reviewed_by = "another operator"; }],
    ["prepare reservation", (v: ReceiverDefenseEnvelope) => { record(record(v.job.progress.phases).protected).receiver_job_id = "job-other"; }],
    ["execution kind", (v: ReceiverDefenseEnvelope) => { v.phases[1]!.execution_job!.kind = "scenario.run"; }],
    ["execution parent", (v: ReceiverDefenseEnvelope) => { record(v.phases[1]!.execution_job!.request!.receiver_defense).parent_job_id = "job-other"; }],
    ["execution submission", (v: ReceiverDefenseEnvelope) => { record(v.phases[1]!.execution_job!.request!._submission).submission_id = "00000000-0000-4000-8000-000000000000"; }],
    ["execution reservation", (v: ReceiverDefenseEnvelope) => { v.phases[1]!.receiver_job!.progress.execution_job_id = "job-other"; }],
    ["replay request", (v: ReceiverDefenseEnvelope) => { record(v.phases[1]!.execution_job!.request!.replay_request).runner_profile_id = "another-profile"; }],
    ["phase policy", (v: ReceiverDefenseEnvelope) => { const p = v.phases[1]!; p.preparation!.session.policy.policy_id = "receiver.reviewed-records.v1"; p.receiver_job!.progress.preparation = copy(p.preparation); p.receiver_job!.progress.session = copy(p.preparation!.session); }],
    ["policy digest", (v: ReceiverDefenseEnvelope) => { v.context!.policies[1]!.digest = `sha256:${"d".repeat(64)}`; v.job.request!.context = copy(v.context); }],
    ["approval navigation", (v: ReceiverDefenseEnvelope) => { v.next_action = { kind: "approve_execute", phase: "protected", native_path: "/runs?job=job-other" }; }],
  ] as const)("refuses mismatched %s", (_label, tamper) => {
    const value = fixture("protected", "approval");
    tamper(value);
    expect(() => checkedReceiverTest(value, receiverFixtureId)).toThrow(/does not match/);
  });

  it.each([
    ["unverified terminal", (p: ReceiverPhaseView) => { p.result!.receiver_observation.state = "insufficient_evidence"; }],
    ["other source", (p: ReceiverPhaseView) => { p.result!.source_binding.run_id = "run-other"; }],
    ["invented observed evidence count", (p: ReceiverPhaseView) => { p.result!.source_binding.observed_count = 12; }],
    ["other run scenario", (p: ReceiverPhaseView) => { p.result!.run.scenario!.id = "other-scenario"; }],
    ["other native result", (p: ReceiverPhaseView) => { p.execution_job!.result_ref = "run-other"; }],
    ["other task", (p: ReceiverPhaseView) => { record(p.result!.receiver_observation.task_binding).task_id = "task-other"; }],
    ["other process generation", (p: ReceiverPhaseView) => { record(p.result!.receiver_observation.process_exit).creation_identity = "other-generation"; }],
    ["failed exit", (p: ReceiverPhaseView) => { record(p.result!.receiver_observation.process_exit).returncode = 1; }],
    ["unauthenticated result", (p: ReceiverPhaseView) => { record(record(p.result!.receiver_observation.terminal).decision).authenticated = false; }],
    ["other policy", (p: ReceiverPhaseView) => { record(record(p.result!.receiver_observation.terminal).decision).policy_id = "receiver.reviewed-records.v1"; }],
    ["other bytes", (p: ReceiverPhaseView) => { p.result!.artifact!.size_bytes += 1; }],
    ["missing summary counts", (p: ReceiverPhaseView) => { delete record(record(p.result!.receiver_observation.terminal).summary).challenges_issued; }],
    ["accepted terminal relabeled as prevention", (p: ReceiverPhaseView) => { record(record(p.result!.receiver_observation.terminal).decision).decision = "accepted"; }],
    ["redacted content relabeled as prevention", (p: ReceiverPhaseView) => { record(record(record(p.result!.receiver_observation.terminal).decision).semantics).retained_record_count = 0; record(record(record(p.result!.receiver_observation.terminal).decision).semantics).redacted_record_count = 2; }],
  ] as const)("does not claim prevention from %s, even with a matching retained result copy", (_label, tamper) => {
    const value = fixture("protected", "completed");
    const phase = value.phases[1]!;
    tamper(phase);
    retainedResult(phase);
    expect(() => checkedReceiverTest(value, receiverFixtureId)).toThrow(/does not match/);
  });

  it("does not silently replace the retained result with a different public result", () => {
    const value = fixture("protected", "completed");
    value.phases[1]!.result!.decision = "accepted";
    expect(() => checkedReceiverTest(value, receiverFixtureId)).toThrow();
  });

  it.each(["protected", "restored"] as const)("refuses a self-consistent %s result over bytes different from the reviewed baseline", (name) => {
    const value = fixture(name, "completed");
    const phase = value.phases.find((item) => item.phase === name)!;
    const differentSha = "e".repeat(64);
    phase.result!.artifact!.sha256 = differentSha;
    record(phase.receiver_job!.progress.task_binding).sha256 = differentSha;
    record(phase.result!.receiver_observation.task_binding).sha256 = differentSha;
    record(record(phase.result!.receiver_observation.terminal).decision).sha256 = differentSha;
    retainedResult(phase);
    expect(() => checkedReceiverTest(value, receiverFixtureId)).toThrow(/does not match/);
  });

  it("confirms only the exact saved creation body", () => {
    const value = fixture();
    const pending = { kind: "create", id: receiverFixtureId, body: copy(value.job.request!.submitted_request) } as ReceiverPending;
    expect(receiverRequestConfirmed(value, pending)).toBe(true);
    record(value.job.request!.submitted_request).submission_id = "00000000-0000-4000-8000-000000000000";
    expect(receiverRequestConfirmed(value, pending)).toBe(false);
  });

  it("retains pending preparation on same-UUID response with another request or parent", () => {
    const value = fixture();
    const pending = { kind: "prepare", id: receiverFixtureId, body: copy(value.phases[0]!.receiver_job!.request!.submitted_request) } as ReceiverPending;
    storeReceiverPending(pending);
    const changed = copy(value);
    record(changed.phases[0]!.receiver_job!.request!.submitted_request).reviewed_by = "other";
    expect(receiverRequestConfirmed(changed, pending)).toBe(false);
    expect(readReceiverPending()).toEqual(pending);
    record(changed.phases[0]!.receiver_job!.request!.submitted_request).reviewed_by = "operator";
    record(changed.phases[0]!.receiver_job!.request!.receiver_defense).parent_job_id = "job-other";
    expect(receiverRequestConfirmed(changed, pending)).toBe(false);
    expect(receiverRequestConfirmed(value, pending)).toBe(true);
    clearReceiverPending(pending);
    expect(readReceiverPending()).toBeUndefined();
  });

  it("recovers an exact earlier attempt without confusing the new reservation", () => {
    const value = fixture();
    const phase = value.phases[0]!;
    const old = Object.fromEntries(Object.entries(copy(phase)).filter(([key]) => !["attempts", "prepare_allowed", "review_ready"].includes(key))) as unknown as ReceiverPhaseView["attempts"][number];
    const pending = { kind: "prepare", id: receiverFixtureId, body: copy(old.receiver_job!.request!.submitted_request) } as ReceiverPending;
    const oldReservation = copy(record(value.job.progress.phases).baseline);
    phase.attempts = [old];
    value.job.progress.attempt_history = [{ phase: "baseline", ...record(oldReservation) }];
    phase.receiver_job = null;
    phase.preparation = null;
    phase.status = "interrupted";
    record(value.job.progress.phases).baseline = { receiver_job_id: "job-50000000000040008000000000000000", prepare_request: { submission_id: "50000000-0000-4000-8000-000000000000", phase: "baseline", reviewed_by: "operator" } };
    expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
    expect(receiverRequestConfirmed(value, pending)).toBe(true);
    delete value.job.progress.attempt_history;
    expect(() => checkedReceiverTest(value, receiverFixtureId)).toThrow();
  });

  function admissionFixture(refused: boolean, unavailable = false): ReceiverDefenseEnvelope {
    const value: ReceiverDefenseEnvelope = fixture("baseline", "idle");
    value.admission = { accepted: false, problem: refused ? { code: "receiver_admission_refused", message: "The reviewed context changed before admission." } : null };
    value.job.progress.admission = copy(value.admission);
    value.job.state = refused ? "failed" : "running";
    value.status = refused ? "blocked" : "active";
    value.next_action = { kind: "wait", phase: "baseline", native_path: null };
    value.phases.forEach((phase) => { phase.prepare_allowed = false; });
    if (unavailable) value.context = null;
    else if (refused) value.context!.context_digest = `sha256:${"d".repeat(64)}`;
    value.job.request!.context = copy(value.context);
    return value;
  }

  it("keeps pending admission readable without exposing receiver preparation", () => {
    const value = admissionFixture(false);
    expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
    expect(value.phases.every((phase) => !phase.prepare_allowed && !phase.review_ready)).toBe(true);
  });

  it.each([false, true])("acknowledges a definitive no-effects admission refusal with unavailable context=%s", (unavailable) => {
    const value = admissionFixture(true, unavailable);
    const pending = { kind: "create", id: receiverFixtureId, body: copy(value.job.request!.submitted_request) } as ReceiverPending;
    storeReceiverPending(pending);
    expect(checkedReceiverTest(value, receiverFixtureId)).toBe(value);
    expect(receiverRequestConfirmed(value, pending)).toBe(true);
    clearReceiverPending(pending);
    expect(readReceiverPending()).toBeUndefined();
    record(value.job.request!.submitted_request).submission_id = "00000000-0000-4000-8000-000000000000";
    expect(receiverRequestConfirmed(value, pending)).toBe(false);
  });

  it.each([
    ["accepted mismatch", (v: ReceiverDefenseEnvelope) => { v.admission = { accepted: true, problem: null }; v.job.progress.admission = copy(v.admission); }],
    ["marker discrepancy", (v: ReceiverDefenseEnvelope) => { v.job.progress.admission = { accepted: true, problem: null }; }],
    ["refusal without failed owner", (v: ReceiverDefenseEnvelope) => { v.job.state = "running"; }],
    ["Prepare allowed", (v: ReceiverDefenseEnvelope) => { v.phases[0]!.prepare_allowed = true; }],
    ["Review allowed", (v: ReceiverDefenseEnvelope) => { v.phases[0]!.review_ready = true; }],
    ["effect navigation", (v: ReceiverDefenseEnvelope) => { v.next_action.kind = "prepare_receiver"; }],
    ["published child", (v: ReceiverDefenseEnvelope) => { v.phases[0]!.receiver_job = fixture().phases[0]!.receiver_job; }],
    ["hidden reservation", (v: ReceiverDefenseEnvelope) => { v.job.progress.phases = { baseline: { receiver_job_id: "job-other" } }; }],
    ["earlier effect attempt", (v: ReceiverDefenseEnvelope) => { v.job.progress.attempt_history = [{ phase: "baseline", receiver_job_id: "job-other" }]; }],
  ] as const)("does not clear an exact pending request for invalid admission: %s", (_label, tamper) => {
    const value = admissionFixture(true);
    const pending = { kind: "create", id: receiverFixtureId, body: copy(value.job.request!.submitted_request) } as ReceiverPending;
    storeReceiverPending(pending);
    tamper(value);
    expect(() => checkedReceiverTest(value, receiverFixtureId)).toThrow();
    expect(receiverRequestConfirmed(value, pending)).toBe(false);
    expect(readReceiverPending()).toEqual(pending);
  });

  it("does not treat null-context pending admission as a definitive refusal", () => {
    expect(() => checkedReceiverTest(admissionFixture(false, true), receiverFixtureId)).toThrow();
  });
});
