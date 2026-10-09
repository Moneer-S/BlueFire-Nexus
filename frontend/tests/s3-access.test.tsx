import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { S3AccessPage } from "../src/pages/S3Access";
import { readS3Pending, readS3Stops, s3Api, storeS3Pending, storeS3Stop } from "../src/lib/s3-access";
import { s3Environment, s3Exercise, s3Hash, s3Observed, s3Operation, s3Owner, s3Review, s3Run } from "./s3-access-fixture";

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
