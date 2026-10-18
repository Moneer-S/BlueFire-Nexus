import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { S3AccessPage } from "../src/pages/S3Access";
import { readS3Pending, readS3Stops, s3Api, storeS3Pending, storeS3Stop, type S3Exercise, type S3Pending, type S3Review } from "../src/lib/s3-access";
import { s3Environment, s3Exercise, s3Hash, s3Observed, s3Operation, s3Owner, s3Review, s3Run } from "./s3-access-fixture";
import { collectedReview } from "./s3-audit-collected-fixture";

beforeEach(() => {
  vi.spyOn(s3Api, "environments").mockResolvedValue({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: "No S3 environment is enrolled." });
  vi.spyOn(s3Api, "list").mockResolvedValue({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [], truncated: false });
  vi.spyOn(s3Api, "read").mockResolvedValue(s3Exercise());
  vi.spyOn(s3Api, "review").mockResolvedValue(s3Review());
  vi.spyOn(s3Api, "send").mockRejectedValue(new Error("Submission not confirmed"));
  vi.spyOn(s3Api, "control").mockRejectedValue(new Error("Control not confirmed"));
});

function mount(owner = s3Owner) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, user: userEvent.setup(), ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[owner ? `/s3-access?exercise=${owner}` : "/s3-access"]}><S3AccessPage /></MemoryRouter></QueryClientProvider>) };
}

it("shows actual missing enrollment without offering cloud dispatch", async () => {
  mount("");
  expect(await screen.findByText("No S3 environment is enrolled.")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Open exercise" })).not.toBeInTheDocument();
  expect(s3Api.send).not.toHaveBeenCalled();
});

it.each(["Temporary access has not been imported on the enrolled host.", "Temporary access has expired on the enrolled host."])("keeps an unavailable environment visible: %s", async problem => {
  vi.mocked(s3Api.environments).mockResolvedValue({ schema_version: "bluefire.s3-environments.v1", environments: [{ environment: s3Environment, available: false, problem, context_digest: s3Hash }], problem: null });
  mount("");
  expect(await screen.findByText(problem)).toBeVisible();
  expect(screen.getByRole("button", { name: "Open exercise" })).toBeDisabled();
  expect(s3Api.send).not.toHaveBeenCalled();
  expect(s3Api.review).not.toHaveBeenCalled();
});

it("requires fresh explicit reviewer and unchecked approval before a stage", async () => {
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Inspect policy" }));
  const confirm = await screen.findByRole("button", { name: "Confirm stage" });
  expect(confirm).toBeDisabled();
  await user.type(screen.getByLabelText("Reviewed by"), "operator");
  expect(confirm).toBeDisabled();
  await user.click(screen.getByRole("checkbox"));
  await user.click(confirm);
  await waitFor(() => expect(s3Api.send).toHaveBeenCalledOnce());
  expect(vi.mocked(s3Api.send).mock.calls[0]![0]).toMatchObject({ owner: s3Owner, kind: "stage", request: { phase: "inspect", review_digest: s3Hash, reviewed_by: "operator" } });
  expect(readS3Pending()).not.toBeNull();
});

it("shows the protected follow-up capacity separately from this stage's reservation", async () => {
  const value = s3Exercise(); value.allowed_phases = ["apply"];
  const review = s3Review("apply");
  review.reserved = { api_calls: 4, business_attempts: 0, sessions: 0, policy_changes: 1, rollbacks: 0 };
  review.required_remaining = { api_calls: 21, business_attempts: 3, sessions: 2, policy_changes: 1, rollbacks: 1 };
  review.policy_change = { before: { Statement: [] }, after: { Statement: [] } };
  vi.mocked(s3Api.read).mockResolvedValue(value);
  vi.mocked(s3Api.review).mockResolvedValue(review);
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Apply reviewed change" }));
  expect(await screen.findByRole("heading", { name: "Fresh checks and recovery allowance" })).toBeVisible();
  expect(screen.getByText("Held within the existing limits, not spent by this stage.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Confirm stage" })).toBeDisabled();
  expect(s3Api.send).not.toHaveBeenCalled();
});

it("reload reads saved evidence without submitting, reviewing or recovering automatically", async () => {
  vi.mocked(s3Api.read).mockResolvedValue(s3Observed());
  mount();
  expect(await screen.findByRole("link", { name: "Run evidence 1" })).toHaveAttribute("href", `/runs/${s3Run}`);
  expect(screen.getByText("Synthetic")).toBeVisible();
  const canary = screen.getByRole("heading", { name: "Canary object" }).closest("article")!;
  expect(within(canary).getByText("Read")).toBeVisible();
  expect(screen.getByText("No live defensive effectiveness has been independently verified.")).toBeVisible();
  expect(s3Api.send).not.toHaveBeenCalled();
  expect(s3Api.review).not.toHaveBeenCalled();
  expect(s3Api.control).not.toHaveBeenCalled();
});

it("retains saved evidence and disables new stages after a failed refresh", async () => {
  vi.mocked(s3Api.read).mockResolvedValueOnce(s3Observed()).mockRejectedValue(new Error("Unavailable"));
  const { user } = mount();
  await screen.findByRole("link", { name: "Run evidence 1" });
  await user.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByText("Saved status unavailable")).toBeVisible();
  expect(screen.getByRole("link", { name: "Run evidence 1" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Inspect policy" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Stop new work" })).toBeEnabled();
});

it("retains uncertain Stop across reload without repeating it automatically", async () => {
  storeS3Stop(s3Owner);
  mount();
  expect(await screen.findByRole("button", { name: "Retry stop" })).toBeEnabled();
  expect(await screen.findByRole("button", { name: "Inspect policy" })).toBeDisabled();
  expect(s3Api.control).not.toHaveBeenCalled();
});

it("still sends Stop if local storage cannot retain it", async () => {
  const { user } = mount();
  await screen.findByRole("button", { name: "Inspect policy" });
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage unavailable"); });
  await user.click(screen.getByRole("button", { name: "Stop new work" }));
  await waitFor(() => expect(s3Api.control).toHaveBeenCalledWith(s3Owner, "stop"));
  expect(screen.getByRole("button", { name: "Inspect policy" })).toBeDisabled();
});

it("clears the local stop marker only after saved stop confirmation", async () => {
  storeS3Stop(s3Owner);
  const stopped = s3Exercise(); stopped.stopped = true; stopped.allowed_phases = [];
  vi.mocked(s3Api.control).mockResolvedValue(stopped);
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Retry stop" }));
  await waitFor(() => expect(readS3Stops()).toEqual([]));
  expect(screen.getByRole("button", { name: "Stopped" })).toBeDisabled();
});

it("recovers original saved results only through a deliberate command", async () => {
  const pending = s3Exercise(); pending.allowed_phases = []; pending.saved_result_recovery_available = true;
  pending.active_job = { job_id: s3Operation, state: "failed", request: { s3_access: { workflow_job_id: s3Owner, phase: "inspect", review: { review_digest: s3Hash } } } };
  vi.mocked(s3Api.read).mockResolvedValue(pending);
  const { user } = mount();
  const recover = await screen.findByRole("button", { name: "Recover saved results" });
  expect(s3Api.control).not.toHaveBeenCalled();
  await user.click(recover);
  await waitFor(() => expect(s3Api.control).toHaveBeenCalledWith(s3Owner, "recover"));
  expect(s3Api.send).not.toHaveBeenCalled();
});

it("can stop an active recovery operation while new work remains stopped", async () => {
  const pending = s3Exercise(); pending.stopped = true; pending.allowed_phases = [];
  pending.active_job = { job_id: s3Operation, state: "running", request: { s3_access: { workflow_job_id: s3Owner, phase: "rollback", review: { review_digest: s3Hash } } } };
  vi.mocked(s3Api.read).mockResolvedValue(pending);
  vi.mocked(s3Api.control).mockResolvedValue(pending);
  const { user, client } = mount();
  await user.click(await screen.findByRole("button", { name: "Stop current operation" }));
  await waitFor(() => expect(s3Api.control).toHaveBeenCalledWith(s3Owner, "stop"));
  expect(await screen.findByRole("button", { name: "Retry stop" })).toBeEnabled();
  expect(readS3Stops()).toEqual([s3Owner]);
  expect(screen.getByText("Original operation in progress")).toBeVisible();
  expect(screen.queryByText("Restored policy")).not.toBeInTheDocument();
  const terminal = { ...pending, active_job: null };
  client.setQueryData(["s3-exercise", s3Owner], terminal);
  await waitFor(() => expect(readS3Stops()).toEqual([]));
  expect(screen.getByRole("button", { name: "Stopped" })).toBeDisabled();
  expect(s3Api.send).not.toHaveBeenCalled();
});

it("retains an uncertain recovery stop on reload without replaying cancellation", async () => {
  storeS3Stop(s3Owner);
  const pending = s3Exercise(); pending.stopped = true; pending.allowed_phases = [];
  pending.active_job = { job_id: s3Operation, state: "running", request: { s3_access: { workflow_job_id: s3Owner, phase: "reconcile", review: { review_digest: s3Hash } } } };
  vi.mocked(s3Api.read).mockResolvedValue(pending);
  mount();
  expect(await screen.findByRole("button", { name: "Retry stop" })).toBeEnabled();
  expect(readS3Stops()).toEqual([s3Owner]);
  expect(screen.getByText("Stop confirmation pending")).toBeVisible();
  expect(s3Api.control).not.toHaveBeenCalled();
  expect(s3Api.send).not.toHaveBeenCalled();
});

it("does not replay a retained uncertain submission on reload", async () => {
  storeS3Pending({ kind: "stage", owner: s3Owner, operation: s3Operation, request: { submission_id: "22222222-2222-2222-2222-222222222222", phase: "inspect", review_digest: s3Hash, reviewed_by: "operator" } });
  mount();
  expect(await screen.findByText("Submission confirmation pending")).toBeVisible();
  expect(await screen.findByRole("button", { name: "Inspect policy" })).toBeDisabled();
  expect(s3Api.send).not.toHaveBeenCalled();
});

it("uses the latest baseline facts after an explicit fresh read stage", async () => {
  const value = s3Observed();
  value.operations.push({ ...structuredClone(value.operations[0]!), operation_job_id: `job-${"5".repeat(32)}`, outcome: { ...value.operations[0]!.outcome, facts: [] } });
  vi.mocked(s3Api.read).mockResolvedValue(value);
  mount();
  const comparison = await screen.findByRole("region", { name: "Access comparison" });
  expect(within(comparison).getAllByText("Not observed")).toHaveLength(6);
});

it("compares fresh denial with both legitimate reads without an independent success claim", async () => {
  const value = s3Observed();
  const retest = structuredClone(value.operations[0]!);
  retest.phase = "retest";
  retest.operation_job_id = `job-${"5".repeat(32)}`;
  retest.run_ids = [`run-20261009T000001Z-${"7".repeat(16)}`, `run-20261009T000001Z-${"8".repeat(16)}`];
  retest.outcome.state = "denied_with_legitimate_reads";
  retest.outcome.facts[0]!.result = "service_denied";
  value.operations.push(retest);
  value.policy_state = "hardened";
  value.allowed_phases = ["rollback", "reconcile"];
  vi.mocked(s3Api.read).mockResolvedValue(value);
  mount();
  const comparison = await screen.findByRole("region", { name: "Access comparison" });
  expect(within(comparison).getByText("Service denied")).toBeVisible();
  expect(within(comparison).getAllByText("Read")).toHaveLength(5);
  const target = new URL(within(comparison).getByRole("link", { name: "Compare saved runs" }).getAttribute("href")!, "http://localhost");
  expect(target.pathname).toBe("/compare");
  expect(target.searchParams.getAll("compare_run")).toEqual([...value.operations[0]!.run_ids, ...retest.run_ids]);
  expect(screen.getByText("No live defensive effectiveness has been independently verified.")).toBeVisible();
  expect(s3Api.send).not.toHaveBeenCalled();
});

it("never sends a malformed saved exercise reference", async () => {
  mount("../another-endpoint");
  expect(await screen.findByText("This saved exercise link is invalid.")).toBeVisible();
  expect(s3Api.read).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: "Stop new work" })).not.toBeInTheDocument();
});

it("shows an enrolled but unavailable environment without a misleading connection claim", async () => {
  vi.mocked(s3Api.environments).mockResolvedValue({ schema_version: "bluefire.s3-environments.v1", environments: [{ environment: s3Environment, available: false, problem: "Protected runtime is unavailable.", context_digest: s3Hash }], problem: null });
  mount("");
  expect(await screen.findByText("Protected runtime is unavailable.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Open exercise" })).toBeDisabled();
  expect(screen.queryByText("Connected")).not.toBeInTheDocument();
});

function auditExercise(): S3Exercise {
  const source = structuredClone(collectedReview.source);
  const pair = structuredClone(collectedReview.original_pair);
  const value = s3Exercise();
  value.schema_version = "bluefire.s3-exercise.v3";
  value.environment = { ...value.environment, scope: structuredClone(pair.reads[0].request.scope) as S3Exercise["environment"]["scope"], audit_source: structuredClone(source) };
  value.operations = [{ ...s3Observed().operations[0]!, operation_job_id: pair.operation_job_id, review_digest: pair.review_digest, outcome_digest: pair.outcome_digest, run_ids: pair.reads.map(read => read.run_id) }];
  value.operations[0]!.outcome.provenance = "runner_reported";
  value.allowed_phases = ["audit_baseline"];
  const workflow = { ...Object.fromEntries(Object.entries(source.audit_limits).map(([key, amount]) => [key, amount * 2])), batches: 2, wire_plus_expansion_bytes: (source.audit_limits.sdk_body_bytes! + source.audit_limits.expanded_bytes!) * 2 };
  value.audit_collection = {
    schema_version: "bluefire.s3-audit-workspace.v1", source, source_digest: s3Hash, workflow_digest: s3Hash,
    budget: { per_batch: { ...source.audit_limits }, workflow },
    reserved: Object.fromEntries(Object.keys(workflow).map(key => [key, 0])), held: { ...workflow },
    slots: [
      { phase: "baseline", stage: "audit_baseline", state: "ready", problem: null, operation_job_id: null, review_id: null, original_pair: pair },
      { phase: "retest", stage: "audit_retest", state: "unavailable", problem: "original_pair_unavailable", operation_job_id: null, review_id: null, original_pair: null },
    ],
  };
  return value;
}

function finalizedRecheckExercise(): S3Exercise {
  const value = auditExercise();
  const workspace = value.audit_collection!;
  value.allowed_phases = []; value.audit = "not_collected"; value.saved_result_recovery_available = true;
  value.operations.push({ ...structuredClone(value.operations[0]!), phase: "audit_baseline", operation_job_id: s3Operation, run_ids: [collectedReview.collection_run_id], outcome: { ...value.operations[0]!.outcome, facts: [], policy_observation: null, state: "failed", cleanup: "unknown", complete: false, audit: "not_collected" } });
  Object.assign(workspace.slots[0], { state: "failed", problem: "phase_consumed", operation_job_id: s3Operation, review_id: null });
  workspace.reserved = Object.fromEntries(Object.entries(workspace.budget.workflow).map(([key, amount]) => [key, amount / 2]));
  workspace.held = { ...workspace.reserved };
  return value;
}

function auditReview(value: S3Exercise): S3Review {
  const workspace = value.audit_collection!;
  const pair = workspace.slots[0].original_pair!;
  const prefix = `${workspace.source.exact_delivery_root_prefix}2026/10/11/`;
  const reserved = { api_calls: 9, business_attempts: 0, sessions: 1, policy_changes: 0, rollbacks: 0 };
  return { ...s3Review("audit_baseline"), schema_version: "bluefire.s3-stage-review.v3", fixture_lifecycle: null, reserved, required_remaining: { ...reserved }, prior_run_ids: pair.reads.map(read => read.run_id), audit_collection: {
    schema_version: "bluefire.s3-audit-stage-review.v1", source: structuredClone(workspace.source), source_digest: workspace.source_digest, original_pair: structuredClone(pair), pair_digest: s3Hash,
    listing_date: "2026-10-11", collection_expires_at: "2026-10-11T21:00:00Z",
    list_parameters: [{ Bucket: workspace.source.audit_bucket, ExpectedBucketOwner: workspace.source.source_account_id, Prefix: prefix, StartAfter: `${prefix}123456789012_CloudTrail_us-east-1_20261011T2044Z_`, MaxKeys: 16 }],
  } };
}

it("shows both collection slots and original paired evidence without issuing collection work", async () => {
  const value = auditExercise(); vi.mocked(s3Api.read).mockResolvedValue(value);
  mount();
  const baseline = await screen.findByRole("article", { name: "Baseline audit slot" });
  expect(within(baseline).getByText("Ready")).toBeVisible();
  expect(within(baseline).getByRole("link", { name: "Probe original read" })).toHaveAttribute("href", `/runs/${collectedReview.original_pair.reads[0].run_id}`);
  expect(within(baseline).getByRole("link", { name: "Legitimate original read" })).toHaveAttribute("href", `/runs/${collectedReview.original_pair.reads[1].run_id}`);
  const retest = screen.getByRole("article", { name: "Retest audit slot" });
  expect(within(retest).getByText("Unavailable")).toBeVisible();
  expect(screen.getByRole("button", { name: "Collect baseline audit" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Collect retest audit" })).not.toBeInTheDocument();
  expect(s3Api.review).not.toHaveBeenCalled(); expect(s3Api.send).not.toHaveBeenCalled();
});

it.each(["collection_not_enabled", "historical_authority_absent"] as const)("does not enable a collection when the retained slot says %s", async problem => {
  const value = auditExercise();
  Object.assign(value.audit_collection!.slots[0], { state: "unavailable", problem });
  vi.mocked(s3Api.read).mockResolvedValue(value);
  const { user } = mount();
  const button = await screen.findByRole("button", { name: "Collect baseline audit" });
  expect(button).toBeDisabled(); await user.click(button);
  expect(s3Api.review).not.toHaveBeenCalled(); expect(s3Api.send).not.toHaveBeenCalled();
});

it("does not close an affordable audit stage for an apply budget warning", async () => {
  const value = auditExercise(); value.problem = "apply_budget_warning";
  vi.mocked(s3Api.read).mockResolvedValue(value); mount();
  expect(await screen.findByRole("button", { name: "Collect baseline audit" })).toBeEnabled();
  expect(s3Api.review).not.toHaveBeenCalled(); expect(s3Api.send).not.toHaveBeenCalled();
});

it("requires backend allowed phases even for a ready collection slot", async () => {
  const value = auditExercise(); value.allowed_phases = [];
  vi.mocked(s3Api.read).mockResolvedValue(value); mount();
  await screen.findByRole("article", { name: "Baseline audit slot" });
  expect(screen.queryByRole("button", { name: "Collect baseline audit" })).not.toBeInTheDocument();
  expect(s3Api.review).not.toHaveBeenCalled(); expect(s3Api.send).not.toHaveBeenCalled();
});

it("reviews exact collection source, prefix, original window and budgets before explicit confirmation", async () => {
  const value = auditExercise(); const review = auditReview(value);
  vi.mocked(s3Api.read).mockResolvedValue(value); vi.mocked(s3Api.review).mockResolvedValue(review);
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Collect baseline audit" }));
  const details = await screen.findByLabelText("Audit collection review");
  expect(within(details).getByText(review.audit_collection!.source.audit_bucket)).toBeVisible();
  expect(within(details).getByText(review.audit_collection!.list_parameters[0]!.Prefix)).toBeVisible();
  expect(within(details).getByText(review.audit_collection!.list_parameters[0]!.StartAfter)).toBeVisible();
  expect(within(details).getByText("2026-10-11T21:00:00Z")).toBeVisible();
  expect(within(details).getAllByText("Original deadline: 2026-10-11T20:44:50Z")).toHaveLength(2);
  expect(within(details).getByText("393216")).toBeVisible();
  expect(within(details).getByText("Authenticated source retrieval. Integrity and complete delivery remain unverified.")).toBeVisible();
  const confirm = screen.getByRole("button", { name: "Confirm stage" }); expect(confirm).toBeDisabled();
  await user.type(screen.getByLabelText("Reviewed by"), "operator"); expect(confirm).toBeDisabled();
  await user.click(screen.getByRole("checkbox")); await user.click(confirm);
  await waitFor(() => expect(s3Api.send).toHaveBeenCalledOnce());
  expect(vi.mocked(s3Api.send).mock.calls[0]![0]).toMatchObject({ kind: "stage", owner: s3Owner, request: { phase: "audit_baseline", review_digest: review.review_digest, reviewed_by: "operator" } });
  expect(readS3Pending()?.request.submission_id).toBe(vi.mocked(s3Api.send).mock.calls[0]![0].request.submission_id);
});

it.each(["source", "pair", "readiness"] as const)("clears an open review when same-revision %s binding changes", async change => {
  const value = auditExercise();
  vi.mocked(s3Api.read).mockResolvedValue(value); vi.mocked(s3Api.review).mockResolvedValue(auditReview(value));
  const { user, client } = mount();
  await user.click(await screen.findByRole("button", { name: "Collect baseline audit" }));
  await screen.findByRole("button", { name: "Confirm stage" });
  await user.type(screen.getByLabelText("Reviewed by"), "operator"); await user.click(screen.getByRole("checkbox"));
  const changed = structuredClone(value);
  if (change === "source") changed.audit_collection!.source_digest = `sha256:${"7".repeat(64)}`;
  else if (change === "pair") changed.audit_collection!.slots[0].original_pair!.review_digest = s3Hash;
  else changed.allowed_phases = [];
  client.setQueryData(["s3-exercise", s3Owner], changed);
  await waitFor(() => expect(screen.queryByRole("button", { name: "Confirm stage" })).not.toBeInTheDocument());
  expect(s3Api.send).not.toHaveBeenCalled();
});

it("retains a collection's exact pending identity and only retries it deliberately", async () => {
  const value = auditExercise(); vi.mocked(s3Api.read).mockResolvedValue(value);
  const pending: S3Pending = { kind: "stage", owner: s3Owner, operation: s3Operation, request: { submission_id: "22222222-2222-2222-2222-222222222222", phase: "audit_baseline", review_digest: s3Hash, reviewed_by: "operator" } };
  storeS3Pending(pending); const { user } = mount();
  expect(await screen.findByText("Submission confirmation pending")).toBeVisible();
  expect(await screen.findByRole("button", { name: "Collect baseline audit" })).toBeDisabled();
  expect(s3Api.send).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Retry exact submission" }));
  await waitFor(() => expect(s3Api.send).toHaveBeenCalledTimes(1));
  expect(vi.mocked(s3Api.send).mock.calls[0]?.[0]).toEqual(pending);
  expect(readS3Pending()).toEqual(pending);
});

it("stops an interrupted original collection and recovers only its saved result", async () => {
  const value = auditExercise(); value.allowed_phases = []; value.saved_result_recovery_available = true;
  value.active_job = { job_id: s3Operation, state: "interrupted", request: { s3_access: { workflow_job_id: s3Owner, phase: "audit_baseline", review: { review_digest: s3Hash } } } };
  Object.assign(value.audit_collection!.slots[0], { state: "reserved", problem: "phase_consumed", operation_job_id: s3Operation });
  vi.mocked(s3Api.read).mockResolvedValue(value); const { user } = mount();
  const recover = await screen.findByRole("button", { name: "Recover saved results" });
  expect(s3Api.control).not.toHaveBeenCalled(); expect(s3Api.send).not.toHaveBeenCalled();
  await user.click(recover); await waitFor(() => expect(s3Api.control).toHaveBeenCalledWith(s3Owner, "recover"));
  const stop = screen.getByRole("button", { name: "Stop current operation" });
  await waitFor(() => expect(stop).toBeEnabled()); await user.click(stop);
  await waitFor(() => expect(s3Api.control).toHaveBeenCalledWith(s3Owner, "stop"));
  expect(readS3Stops()).toEqual([s3Owner]); expect(s3Api.send).not.toHaveBeenCalled();
});

it("manually checks a finalized original collection task without releasing its cleanup block", async () => {
  const value = finalizedRecheckExercise();
  vi.mocked(s3Api.read).mockResolvedValue(value); vi.mocked(s3Api.control).mockResolvedValue(value);
  const { user } = mount();
  const button = await screen.findByRole("button", { name: "Check original task" });
  expect(screen.getByText("Cleanup unresolved")).toBeVisible();
  expect(screen.getByRole("link", { name: "Original collection run evidence 1" })).toHaveAttribute("href", `/runs/${collectedReview.collection_run_id}`);
  expect(screen.queryByRole("button", { name: "Inspect policy" })).not.toBeInTheDocument();
  expect(s3Api.control).not.toHaveBeenCalled(); expect(s3Api.send).not.toHaveBeenCalled(); expect(s3Api.review).not.toHaveBeenCalled();
  await user.click(button);
  await waitFor(() => expect(s3Api.control).toHaveBeenCalledTimes(1));
  expect(s3Api.control).toHaveBeenCalledWith(s3Owner, "recover");
  expect(await screen.findByText("Original task checked; cleanup remains unresolved.", { exact: true })).toBeVisible();
  expect(screen.getByRole("button", { name: "Check original task" })).toBeEnabled();
  expect(screen.getByText("Cleanup unresolved")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Inspect policy" })).not.toBeInTheDocument();
  expect(s3Api.send).not.toHaveBeenCalled(); expect(s3Api.review).not.toHaveBeenCalled();
});

it("does not check a finalized task automatically on reload", async () => {
  vi.mocked(s3Api.read).mockResolvedValue(finalizedRecheckExercise());
  const first = mount();
  expect(await screen.findByRole("button", { name: "Check original task" })).toBeEnabled();
  expect(s3Api.control).not.toHaveBeenCalled();
  first.unmount();
  mount();
  expect(await screen.findByRole("button", { name: "Check original task" })).toBeEnabled();
  expect(s3Api.control).not.toHaveBeenCalled();
});

it("does not show a late original-task check success on a different saved exercise", async () => {
  const otherOwner = `job-${"9".repeat(32)}`;
  const original = finalizedRecheckExercise();
  const other = finalizedRecheckExercise(); other.workflow_job_id = otherOwner;
  for (const slot of other.audit_collection!.slots) {
    if (slot.original_pair) slot.original_pair.workflow_job_id = otherOwner;
  }
  vi.mocked(s3Api.read).mockImplementation(identifier => Promise.resolve(identifier === s3Owner ? original : other));
  vi.mocked(s3Api.list).mockResolvedValue({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [
    { workflow_job_id: s3Owner, name: "Original exercise", bucket: s3Environment.scope.bucket, policy_state: "uncertain", updated_at: "2026-01-01T00:00:00Z" },
    { workflow_job_id: otherOwner, name: "Other exercise", bucket: s3Environment.scope.bucket, policy_state: "uncertain", updated_at: "2026-01-01T00:00:00Z" },
  ], truncated: false });
  let resolveRecheck!: (value: S3Exercise) => void;
  const recheckPromise = new Promise<S3Exercise>(resolve => { resolveRecheck = resolve; });
  vi.mocked(s3Api.control).mockReturnValueOnce(recheckPromise);
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Check original task" }));
  await waitFor(() => expect(s3Api.control).toHaveBeenCalledTimes(1));

  await user.click(screen.getByRole("link", { name: "Saved exercises" }));
  await user.click(await screen.findByRole("link", { name: /Other exercise/ }));
  await screen.findByRole("heading", { name: "Remove unintended read access" });
  expect(screen.queryByText("Original task checked; cleanup remains unresolved.", { exact: true })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Check original task" })).toBeDisabled();

  await act(async () => { resolveRecheck(original); await recheckPromise; });
  await waitFor(() => expect(screen.getByRole("button", { name: "Check original task" })).toBeEnabled());
  expect(screen.queryByText("Original task checked; cleanup remains unresolved.", { exact: true })).not.toBeInTheDocument();
  expect(s3Api.control).toHaveBeenCalledTimes(1);
});

it("does not show a late original-task check failure on a different saved exercise", async () => {
  const otherOwner = `job-${"9".repeat(32)}`;
  const original = finalizedRecheckExercise();
  const other = finalizedRecheckExercise(); other.workflow_job_id = otherOwner;
  for (const slot of other.audit_collection!.slots) {
    if (slot.original_pair) slot.original_pair.workflow_job_id = otherOwner;
  }
  vi.mocked(s3Api.read).mockImplementation(identifier => Promise.resolve(identifier === s3Owner ? original : other));
  vi.mocked(s3Api.list).mockResolvedValue({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [
    { workflow_job_id: s3Owner, name: "Original exercise", bucket: s3Environment.scope.bucket, policy_state: "uncertain", updated_at: "2026-01-01T00:00:00Z" },
    { workflow_job_id: otherOwner, name: "Other exercise", bucket: s3Environment.scope.bucket, policy_state: "uncertain", updated_at: "2026-01-01T00:00:00Z" },
  ], truncated: false });
  let rejectRecheck!: (reason: Error) => void;
  const recheckPromise = new Promise<S3Exercise>((_resolve, reject) => { rejectRecheck = reject; });
  vi.mocked(s3Api.control).mockReturnValueOnce(recheckPromise);
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Check original task" }));
  await waitFor(() => expect(s3Api.control).toHaveBeenCalledTimes(1));

  await user.click(screen.getByRole("link", { name: "Saved exercises" }));
  await user.click(await screen.findByRole("link", { name: /Other exercise/ }));
  await screen.findByRole("heading", { name: "Remove unintended read access" });
  expect(screen.getByText("Cleanup unresolved")).toBeVisible();

  await act(async () => { rejectRecheck(new Error("Original task unavailable")); await recheckPromise.catch(() => undefined); });
  await waitFor(() => expect(screen.getByRole("button", { name: "Check original task" })).toBeEnabled());
  expect(screen.queryByText("Original task check failed")).not.toBeInTheDocument();
  expect(screen.queryByText("Control request not confirmed")).not.toBeInTheDocument();
  expect(screen.queryByText("Original task checked; cleanup remains unresolved.", { exact: true })).not.toBeInTheDocument();
  expect(screen.getByText("Cleanup unresolved")).toBeVisible();
  expect(s3Api.control).toHaveBeenCalledTimes(1);
});

it("keeps unresolved cleanup visible after a failed original task check", async () => {
  vi.mocked(s3Api.read).mockResolvedValue(finalizedRecheckExercise());
  vi.mocked(s3Api.control).mockRejectedValue(new Error("Original task unavailable"));
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Check original task" }));
  expect(await screen.findByText("Original task check failed")).toBeVisible();
  expect(screen.getByText("Cleanup unresolved")).toBeVisible();
  expect(screen.queryByText("Original task checked; cleanup remains unresolved.", { exact: true })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Check original task" })).toBeEnabled();
  expect(s3Api.control).toHaveBeenCalledTimes(1);
  expect(s3Api.send).not.toHaveBeenCalled(); expect(s3Api.review).not.toHaveBeenCalled();
});

it("keeps completed collection evidence distinct from independent effectiveness", async () => {
  const value = auditExercise(); value.allowed_phases = []; value.audit = "authenticated_retrieval";
  value.operations.push({ ...structuredClone(value.operations[0]!), phase: "audit_baseline", operation_job_id: s3Operation, run_ids: [collectedReview.collection_run_id], outcome: { ...value.operations[0]!.outcome, facts: [], policy_observation: null, audit: "authenticated_retrieval" } });
  Object.assign(value.audit_collection!.slots[0], { state: "completed", problem: "phase_consumed", operation_job_id: s3Operation, review_id: s3Operation });
  vi.mocked(s3Api.read).mockResolvedValue(value); mount();
  const baseline = await screen.findByRole("article", { name: "Baseline audit slot" });
  expect(within(baseline).getByRole("link", { name: "Baseline collection run" })).toHaveAttribute("href", `/runs/${collectedReview.collection_run_id}`);
  expect(screen.getByText("Authenticated source retrieval; integrity unverified")).toBeVisible();
  expect(screen.getByText("No live defensive effectiveness has been independently verified.")).toBeVisible();
  expect(s3Api.send).not.toHaveBeenCalled();
});
