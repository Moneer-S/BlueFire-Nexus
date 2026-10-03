import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RetainedReceiverControl } from "../src/components/RetainedReceiverControl";
import { ReceiverTestProgress } from "../src/components/ReceiverTestProgress";
import { ReceiverTestSetup } from "../src/components/ReceiverTestSetup";
import { ReceiverDefensePage } from "../src/pages/ReceiverDefense";
import { ProductProvider } from "../src/state/ProductContext";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { checkedReceiverContext, checkedReceiverTest, readReceiverPending, receiverRequestConfirmed, storeReceiverPending, type ReceiverPending } from "../src/lib/receiver-defense";
import { retainedReceiverFixture } from "./receiver-retained-fixture";

const record = (value: unknown) => value as Record<string, unknown>;

it.each([false, true])("validates the retained policy and changed legitimate-use bytes with linked=%s", (linked) => {
  const value = retainedReceiverFixture("legitimate", "completed", linked);
  expect(checkedReceiverTest(value, value.job.job_id)).toBe(value);
  expect(value.phases.map((phase) => phase.phase)).toEqual(linked ? ["protected", "legitimate"] : ["baseline", "protected", "legitimate"]);
  expect(value.phases.at(-1)!.result!.artifact).not.toEqual(value.phases.find((phase) => phase.phase === "protected")!.result!.artifact);
});

it.each([false, true])("keeps an unpublished reserved preparation readable with linked=%s", (linked) => {
  const value = retainedReceiverFixture(linked ? "protected" : "baseline", "prepared", linked);
  const phase = value.phases[0]!;
  Object.assign(phase, {
    status: "interrupted", receiver_job: null, preparation: null,
    cleanup: { receiver: "not_started", run: "not_started" },
    problem: { code: "receiver_publication_uncertain", message: "The exact reserved preparation is not attached." },
  });
  Object.assign(value.control!, { receiver_state: "unknown", can_retest: false, can_rollback: false });
  expect(checkedReceiverTest(value, value.job.job_id)).toBe(value);
});

it.each([
  ["legacy envelope", (value: ReturnType<typeof retainedReceiverFixture>) => { value.schema_version = "bluefire.receiver-defense.v1"; }],
  ["legacy context", (value: ReturnType<typeof retainedReceiverFixture>) => { value.context.schema_version = "bluefire.receiver-defense-context.v1"; }],
  ["restoration phase", (value: ReturnType<typeof retainedReceiverFixture>) => { value.phases[2]!.phase = "restored"; }],
  ["redaction override", (value: ReturnType<typeof retainedReceiverFixture>) => { value.phases[2]!.preparation!.replay_preparation!.replay_request.parameter_overrides = {}; }],
  ["redaction scenario", (value: ReturnType<typeof retainedReceiverFixture>) => { value.phases[2]!.preparation!.replay_preparation!.scenario.steps.find((step) => step.id === "transform")!.parameters.redact_values = false; }],
  ["additional scenario change", (value: ReturnType<typeof retainedReceiverFixture>) => { value.phases[2]!.preparation!.replay_preparation!.scenario.title = "Another experiment"; }],
  ["baseline lineage", (value: ReturnType<typeof retainedReceiverFixture>) => { value.phases[1]!.preparation!.baseline_reference!.run_id = "run-other"; }],
  ["control scope", (value: ReturnType<typeof retainedReceiverFixture>) => { value.control!.scope = { ...value.control!.scope, run_intent: { ...value.context.run_intent, runner_profile_id: "other" } }; }],
  ["control desired policy", (value: ReturnType<typeof retainedReceiverFixture>) => { value.control!.desired_policy_id = "receiver.reviewed-records.v1"; }],
  ["missing legitimate-use summary", (value: ReturnType<typeof retainedReceiverFixture>) => { delete value.phases[2]!.result!.legitimate_use; }],
  ["legitimate-use baseline", (value: ReturnType<typeof retainedReceiverFixture>) => { value.phases[2]!.result!.legitimate_use!.baseline_run_id = "run-other"; }],
  ["unestablished completed legitimate use", (value: ReturnType<typeof retainedReceiverFixture>) => { value.phases[2]!.result!.legitimate_use!.established = false; }],
  ["established mismatched record count", (value: ReturnType<typeof retainedReceiverFixture>) => { Object.assign(record(record(record(value.phases[2]!.result!.receiver_observation.terminal).decision).semantics), { record_count: 3, redacted_record_count: 3 }); }],
] as const)("rejects a retained response with altered %s", (_label, change) => {
  const value = retainedReceiverFixture();
  change(value);
  expect(() => checkedReceiverTest(value, value.job.job_id)).toThrow(/does not match/);
});

it("rejects changed original-path bytes while allowing the reviewed legitimate variant", () => {
  const value = retainedReceiverFixture();
  const phase = value.phases[1]!;
  const sha = "f".repeat(64);
  phase.result!.artifact = { ...phase.result!.artifact!, sha256: sha };
  record(phase.receiver_job!.progress.task_binding).sha256 = sha;
  record(phase.result!.receiver_observation.task_binding).sha256 = sha;
  record(record(phase.result!.receiver_observation.terminal).decision).sha256 = sha;
  expect(() => checkedReceiverTest(value, value.job.job_id)).toThrow(/does not match/);
});

it("does not accept unredacted semantics under the legitimate-use acceptance claim", () => {
  const value = retainedReceiverFixture();
  const decision = record(record(value.phases[2]!.result!.receiver_observation.terminal).decision);
  Object.assign(record(decision.semantics), { retained_record_count: 1, redacted_record_count: 1 });
  expect(() => checkedReceiverTest(value, value.job.job_id)).toThrow(/does not match/);
});

it("preserves accepted records with failed legitimate use and keeps Stop and cleanup readable", async () => {
  const value = retainedReceiverFixture();
  const phase = value.phases[2]!;
  Object.assign(record(record(record(phase.result!.receiver_observation.terminal).decision).semantics), { record_count: 3, redacted_record_count: 3 });
  phase.result!.legitimate_use!.established = false;
  phase.status = "failed";
  phase.problem = { code: "receiver_result_insufficient", message: "The receiver accepted a different number of redacted records from the baseline." };
  value.status = "blocked";
  value.next_action = { kind: "cleanup_required", phase: "legitimate", native_path: null };
  Object.assign(value.control!, { status: "verified", can_retest: false });
  expect(checkedReceiverTest(value, value.job.job_id)).toBe(value);
  vi.spyOn(api, "receiverTest").mockResolvedValue(value);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[`/compare?receiver_job=${value.job.job_id}`]}><ReceiverDefensePage /></MemoryRouter></ProductProvider></QueryClientProvider>);
  expect(await screen.findByText("Legitimate use not established")).toBeVisible();
  expect(screen.getAllByText("Accepted by the receiver").length).toBeGreaterThan(1);
  expect(screen.getByText(phase.problem.message)).toBeVisible();
  expect(screen.getByRole("button", { name: "Stop control test" })).toBeEnabled();
  expect(screen.getAllByText("Receiver shutdown verified").length).toBeGreaterThan(0);
  expect(screen.queryByText("Saved test status unavailable")).not.toBeInTheDocument();
});

it("accepts ineligible retained context without a compatible control descriptor", () => {
  const context = retainedReceiverFixture().context;
  context.eligible = false;
  context.control = null;
  expect(checkedReceiverContext(context)).toBe(context);
  context.eligible = true;
  expect(() => checkedReceiverContext(context)).toThrow(/does not match/);
});

it("keeps comparison as the default and requests retained mode only after selecting it", async () => {
  const context = retainedReceiverFixture().context;
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [{ scenario_id: context.selection.scenario_id, version: context.selection.version, digest: context.selection.digest, title: context.scenario_title, created_at: "2026-10-02T12:00:00Z", document: context.scenario }] });
  const check = vi.spyOn(api, "receiverContext").mockImplementation(async (request) => ({
    schema_version: request.workflow ? "bluefire.receiver-defense-context.v2" : "bluefire.receiver-defense-context.v1",
    ...request, context_digest: context.context_digest, scenario: context.scenario, scenario_title: context.scenario_title,
    eligible: false, reasons: [{ code: "setup", message: "Review the environment." }], handoff: null, policies: [], limitations: [],
    availability: { supported: true, ready: true, reason: null, native_path: null }, ...(request.workflow ? { control: null } : {}),
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><ReceiverTestSetup disabled={false} onStart={vi.fn()} /></MemoryRouter></ProductProvider></QueryClientProvider>);
  const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText("Saved experiment", { exact: false }), `${context.selection.scenario_id}:${context.selection.version}:${context.selection.digest}`);
  await waitFor(() => expect(check).toHaveBeenCalled());
  expect(check.mock.calls[0]![0].workflow).toBeUndefined();
  await user.click(screen.getByRole("radio", { name: "Retain redaction and verify legitimate use" }));
  await waitFor(() => expect(check.mock.lastCall![0].workflow).toBe("retained_redaction"));
  expect(screen.queryByRole("button", { name: "Coordinate with Assistant" })).not.toBeInTheDocument();
});

it("recovers only the exact durable rollback receipt", () => {
  const value = retainedReceiverFixture();
  const body = { submission_id: "80000000-0000-4000-8000-000000000000", control_digest: value.control!.control_digest, decision: "rollback" as const, reviewed_by: "operator" };
  const pending: ReceiverPending = { kind: "control", id: value.job.job_id, body };
  storeReceiverPending(pending);
  expect(readReceiverPending()).toEqual(pending);
  expect(receiverRequestConfirmed(value, pending)).toBe(false);
  Object.assign(value.control!, { status: "rolled_back", desired_policy_id: "receiver.reviewed-records.v1", rollback: body, can_retest: false, can_rollback: false });
  value.job.progress.control_rollback = body;
  expect(checkedReceiverTest(value, value.job.job_id)).toBe(value);
  expect(receiverRequestConfirmed(value, pending)).toBe(true);
  expect(receiverRequestConfirmed(value, { ...pending, body: { ...body, reviewed_by: "another" } })).toBe(false);
});

function mountControl(value = retainedReceiverFixture()) {
  const onStart = vi.fn(), onRollback = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { onStart, onRollback, user: userEvent.setup(), ...render(<QueryClientProvider client={client}><MemoryRouter><RetainedReceiverControl envelope={value} disabled={false} onStart={onStart} onRollback={onRollback} /></MemoryRouter></QueryClientProvider>) };
}

it("labels legitimate-use review without claiming an unchanged byte replay", () => {
  const value = retainedReceiverFixture("legitimate", "prepared");
  render(<MemoryRouter><ReceiverTestProgress envelope={value} disabled={false} onPrepare={vi.fn()} onReview={vi.fn()} /></MemoryRouter>);
  expect(screen.getByRole("heading", { name: "Legitimate redacted use", level: 2 })).toBeVisible();
  expect(screen.getByText(/This reviewed variant changes the staged bytes/)).toBeVisible();
  expect(screen.queryByText("Replay must match the staged artifact independently recorded in the baseline.")).not.toBeInTheDocument();
});

it("requires scope acknowledgement to save a fresh linked retest without preparing or approving runs", async () => {
  const retest = retainedReceiverFixture("protected", "idle", true);
  const context = vi.spyOn(api, "receiverContext").mockImplementation(async (request) => ({ ...retest.context, source_control: request.source_control }));
  const prepare = vi.spyOn(api, "prepareReceiver"), approve = vi.spyOn(api, "approveJob");
  const { user, onStart } = mountControl();
  await user.click(screen.getByRole("button", { name: "Review fresh retest" }));
  const save = await screen.findByRole("button", { name: "Save fresh retest" });
  expect(save).toBeDisabled();
  await user.click(screen.getByRole("checkbox"));
  await user.click(save);
  await waitFor(() => expect(onStart).toHaveBeenCalledOnce());
  expect(context.mock.calls[0]![0]).toMatchObject({ workflow: "retained_redaction", source_control: { job_id: retainedReceiverFixture().job.job_id } });
  expect(onStart.mock.calls[0]![0]).toMatchObject({ workflow: "retained_redaction", source_control: { job_id: retainedReceiverFixture().job.job_id } });
  expect(prepare).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
});

it("requires acknowledgement and a reviewer before rolling back the policy owner's exact digest", async () => {
  const value = retainedReceiverFixture();
  const { user, onRollback } = mountControl(value);
  expect(screen.getByText("Stopped; no active receiver")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Review policy rollback" }));
  const rollback = screen.getByRole("button", { name: "Roll back retained policy" });
  expect(rollback).toBeDisabled();
  await user.type(screen.getByLabelText("Rollback reviewed by"), "lab operator");
  expect(rollback).toBeDisabled();
  await user.click(screen.getByRole("checkbox")); await user.click(rollback);
  expect(onRollback).toHaveBeenCalledWith(value.job.job_id, expect.objectContaining({ control_digest: value.control!.control_digest, decision: "rollback", reviewed_by: "lab operator" }));
});

it("keeps fresh retest outcomes distinct from the linked baseline", () => {
  mountControl(retainedReceiverFixture("legitimate", "completed", true));
  expect(screen.getByRole("link", { name: "original baseline" })).toHaveAttribute("href", "/runs/run-baseline");
  expect(screen.getByText(/only this test's new runs establish its outcomes/)).toBeVisible();
});

it("compares a linked fresh protected run against its original baseline", () => {
  const value = retainedReceiverFixture("legitimate", "completed", true);
  render(<MemoryRouter><ReceiverTestProgress envelope={value} disabled={false} onPrepare={vi.fn()} onReview={vi.fn()} /></MemoryRouter>);
  const protectedRun = value.phases[0]!.result!.run_id;
  expect(screen.getByRole("link", { name: "Compare baseline and protected run" })).toHaveAttribute("href", `/compare?source=run-baseline&replay=${protectedRun}`);
});

it("retains an uncertain rollback and retries its exact request before clearing it", async () => {
  const value = retainedReceiverFixture();
  let saved = value;
  vi.spyOn(api, "receiverTest").mockImplementation(async () => saved);
  const rollback = vi.spyOn(api, "rollbackReceiverControl").mockRejectedValueOnce(new Error("Response unavailable")).mockImplementation(async (_id, body) => {
    saved = structuredClone(value);
    Object.assign(saved.control!, { status: "rolled_back", desired_policy_id: "receiver.reviewed-records.v1", rollback: body, can_retest: false, can_rollback: false });
    saved.job.progress.control_rollback = body;
    return saved;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[`/compare?receiver_job=${value.job.job_id}`]}><ReceiverDefensePage /></MemoryRouter></ProductProvider></QueryClientProvider>);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Review policy rollback" }));
  await user.type(screen.getByLabelText("Rollback reviewed by"), "operator");
  await user.click(screen.getByRole("checkbox"));
  await user.click(screen.getByRole("button", { name: "Roll back retained policy" }));
  await screen.findByText("Request not confirmed");
  const pending = readReceiverPending();
  expect(pending?.kind).toBe("control");
  await user.click(screen.getByRole("button", { name: "Retry this exact request" }));
  await screen.findByText("Retained policy rolled back");
  await waitFor(() => expect(readReceiverPending()).toBeUndefined());
  expect(rollback).toHaveBeenCalledTimes(2);
  expect(rollback.mock.calls[1]).toEqual(rollback.mock.calls[0]);
});
