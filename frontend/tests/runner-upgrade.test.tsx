import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RunnerUpgradeReview } from "../src/components/RunnerUpgradeReview";
import { ExecuteRunnerReadiness } from "../src/components/ExecuteRunnerReadiness";
import { api, ApiError } from "../src/lib/api";
import type { RunnerUpgradeReview as Review } from "../src/lib/runner-upgrade";
import type { RunnerLifecycleStatus } from "../src/types";
import { runnerUpgradeReview, upgradeDigest } from "./runner-upgrade-fixtures";

const profile = "selected-execute.v1";
const stopped: RunnerLifecycleStatus = { schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "bluefire-rust-runner.v1", profile_id: profile, loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null };
function mount(status = stopped) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const onBusy = vi.fn();
  const view = render(<QueryClientProvider client={client}><RunnerUpgradeReview profileId={profile} status={status} onBusy={onBusy}/></QueryClientProvider>);
  return { ...view, client, onBusy };
}

it("reviews exact artifacts and retained history before explicitly applying without starting work", async () => {
  const review = vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue(runnerUpgradeReview());
  const apply = vi.spyOn(api, "bootstrapRunner").mockResolvedValue(stopped);
  const start = vi.spyOn(api, "startRunner"); const submit = vi.spyOn(api, "submitRun");
  const revoke = vi.spyOn(api, "revokeRunner"); const remove = vi.spyOn(api, "removeRunner");
  const user = userEvent.setup(); mount();
  expect(review).not.toHaveBeenCalled(); expect(apply).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  const confirm = await screen.findByRole("button", { name: "Apply reviewed runner upgrade" });
  expect(screen.getByRole("heading", { name: "Update runner and keep history" })).toBeVisible();
  expect(screen.getByText("Completed executions retained").nextElementSibling).toHaveTextContent("2");
  expect(screen.getByText("Durable results retained").nextElementSibling).toHaveTextContent("2");
  expect(screen.getByText(/different verified artifact/)).toBeVisible();
  expect(screen.getByText(/Activation has not completed/)).toBeVisible();
  expect(review).toHaveBeenCalledExactlyOnceWith(profile); expect(apply).not.toHaveBeenCalled();
  await user.click(confirm);
  await waitFor(() => expect(apply).toHaveBeenCalledExactlyOnceWith(profile, true, upgradeDigest));
  expect(await screen.findByText(/Runner upgrade applied/)).toBeVisible();
  expect(start).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled(); expect(revoke).not.toHaveBeenCalled(); expect(remove).not.toHaveBeenCalled();
});

it("retains review blockers and never offers apply or an automatic retry", async () => {
  const detail = "An execution receipt still needs cleanup.";
  const review = vi.spyOn(api, "reviewRunnerUpgrade").mockRejectedValue(new ApiError("Upgrade review refused.", "runner_upgrade_review_refused", [detail], 409));
  const apply = vi.spyOn(api, "bootstrapRunner");
  const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  expect(await screen.findByText(detail)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Apply reviewed runner upgrade" })).not.toBeInTheDocument();
  expect(review).toHaveBeenCalledTimes(1); expect(apply).not.toHaveBeenCalled();
});

it("consumes a stale review locally and requires a new explicit review before another apply", async () => {
  const review = vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue(runnerUpgradeReview());
  const apply = vi.spyOn(api, "bootstrapRunner").mockRejectedValue(new ApiError("The review is stale.", "runner_bootstrap_refused", ["Runner history changed after review."], 409));
  const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  await user.click(await screen.findByRole("button", { name: "Apply reviewed runner upgrade" }));
  expect(await screen.findByText("Runner history changed after review.")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Apply reviewed runner upgrade" })).not.toBeInTheDocument();
  expect(apply).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Refresh upgrade review" }));
  await screen.findByRole("button", { name: "Apply reviewed runner upgrade" });
  expect(review).toHaveBeenCalledTimes(2); expect(apply).toHaveBeenCalledTimes(1);
});

it.each([
  ["runner identity", (review: Review) => { review.candidate.runner_id = "another-runner.v1"; }],
  ["scope compatibility", (review: Review) => { Object.assign(review.compatibility, { same_profiles: false }); }],
  ["preservation", (review: Review) => { Object.assign(review.preservation, { ledger: false }); }],
  ["activation", (review: Review) => { Object.assign(review.staging, { activated: true }); }],
  ["history count", (review: Review) => { review.history.durable_results = -1; }],
  ["review digest", (review: Review) => { review.review_digest = "unbound"; }],
  ["protocol identity", (review: Review) => { review.candidate.receipt_protocol = "another-protocol"; }],
])("refuses an incomplete or unsafe %s response", async (_label, mutate) => {
  const payload = runnerUpgradeReview(); mutate(payload);
  vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue(payload);
  const apply = vi.spyOn(api, "bootstrapRunner"); const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  expect(await screen.findByText(/review is incomplete or does not match/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Apply reviewed runner upgrade" })).not.toBeInTheDocument();
  expect(apply).not.toHaveBeenCalled();
});

it("discards a late review after profile selection changes and does not reuse it on return", async () => {
  let finish!: (review: Review) => void;
  vi.spyOn(api, "reviewRunnerUpgrade").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const apply = vi.spyOn(api, "bootstrapRunner"); const user = userEvent.setup();
  const view = mount();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  const show = (selected: string) => view.rerender(<QueryClientProvider client={view.client}><RunnerUpgradeReview profileId={selected} status={{ ...stopped, profile_id: selected }} onBusy={view.onBusy}/></QueryClientProvider>);
  show("another-execute.v1");
  await act(async () => finish(runnerUpgradeReview()));
  expect(screen.queryByRole("button", { name: "Apply reviewed runner upgrade" })).not.toBeInTheDocument();
  show(profile);
  expect(screen.queryByRole("button", { name: "Apply reviewed runner upgrade" })).not.toBeInTheDocument();
  expect(apply).not.toHaveBeenCalled();
});

it("closes a review without activating its staged candidate", async () => {
  vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue(runnerUpgradeReview());
  const apply = vi.spyOn(api, "bootstrapRunner"); const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  await user.click(await screen.findByRole("button", { name: "Close review" }));
  expect(screen.queryByRole("button", { name: "Apply reviewed runner upgrade" })).not.toBeInTheDocument();
  expect(apply).not.toHaveBeenCalled();
});

it("also applies an explicitly reviewed upgrade when no execution history exists", async () => {
  const review = runnerUpgradeReview();
  review.history = { ...review.history, total_rows: 0, execute_rows: 0, completed_executions: 0, undispatched_executions: 0, durable_results: 0, ledger_generation: null };
  vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue(review);
  const apply = vi.spyOn(api, "bootstrapRunner").mockResolvedValue(stopped); const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  await user.click(await screen.findByRole("button", { name: "Apply reviewed runner upgrade" }));
  await waitFor(() => expect(apply).toHaveBeenCalledExactlyOnceWith(profile, true, upgradeDigest));
});

it("shows an interrupted activation as an exact recovery transition, not a completed update", async () => {
  vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue({ ...runnerUpgradeReview(), recovery_required: true });
  const apply = vi.spyOn(api, "bootstrapRunner"); const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  expect(await screen.findByText(/An interrupted upgrade must be completed/)).toBeVisible();
  expect(screen.getByRole("rowheader", { name: "Previously installed runner" })).toBeVisible();
  expect(screen.queryByText(/Runner upgrade applied/)).not.toBeInTheDocument();
  expect(apply).not.toHaveBeenCalled();
});

it("offers exact reviewed recovery only when the service verifies an absent process and active enrollment", async () => {
  const review = vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue({ ...runnerUpgradeReview(), recovery_required: true });
  const apply = vi.spyOn(api, "bootstrapRunner").mockResolvedValue(stopped);
  const user = userEvent.setup(); mount({ ...stopped, state: "unavailable", upgrade_recovery_required: true });
  expect(review).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Review runner upgrade" }));
  await user.click(await screen.findByRole("button", { name: "Apply reviewed runner upgrade" }));
  await waitFor(() => expect(apply).toHaveBeenCalledExactlyOnceWith(profile, true, upgradeDigest));
});

it.each([
  { ...stopped, state: "ready", process: "authenticated" },
  { ...stopped, state: "stale", process: "stale" },
  { ...stopped, profile_id: "another-execute.v1" },
  { ...stopped, state: "unavailable" },
  { ...stopped, state: "unavailable", upgrade_recovery_required: true as const, process: "unavailable" },
])("cannot request upgrade for a running, stale or different profile", status => {
  const review = vi.spyOn(api, "reviewRunnerUpgrade"); mount(status);
  expect(screen.queryByRole("button", { name: "Review runner upgrade" })).not.toBeInTheDocument();
  expect(review).not.toHaveBeenCalled();
});

it("safely stops and reviews the selected runner inside Execute readiness", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...stopped, state: "ready", process: "authenticated", health: { accepting_execute: true } });
  const stop = vi.spyOn(api, "stopRunner").mockImplementation(async () => { status.mockResolvedValue(stopped); return stopped; });
  const review = vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue(runnerUpgradeReview());
  const apply = vi.spyOn(api, "bootstrapRunner").mockResolvedValue(stopped);
  const start = vi.spyOn(api, "startRunner"); const user = userEvent.setup();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ExecuteRunnerReadiness profileId={profile}/></MemoryRouter></QueryClientProvider>);
  await screen.findByText("Runner authenticated");
  await user.click(screen.getByText("Preflight reports a missing runner method?"));
  await user.click(screen.getByRole("button", { name: "Stop runner safely" }));
  await user.click(await screen.findByRole("button", { name: "Review runner upgrade" }));
  await user.click(await screen.findByRole("button", { name: "Apply reviewed runner upgrade" }));
  await waitFor(() => expect(apply).toHaveBeenCalledExactlyOnceWith(profile, true, upgradeDigest));
  expect(stop).toHaveBeenCalledExactlyOnceWith(profile); expect(review).toHaveBeenCalledExactlyOnceWith(profile); expect(start).not.toHaveBeenCalled();
});
