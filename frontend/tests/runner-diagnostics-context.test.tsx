import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { api, ApiError } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { RunnersPage } from "../src/pages/CatalogPages";
import { ExecuteRunnerReadiness, RunnerInventoryRecovery } from "../src/components/ExecuteRunnerReadiness";
import type { RunnerLifecycleStatus } from "../src/types";
import { runnerUpgradeReview, upgradeDigest } from "./runner-upgrade-fixtures";

beforeEach(() => { vi.spyOn(api, "reviewRunnerUpgrade").mockResolvedValue(runnerUpgradeReview()); });

const profile = "sandbox-execute.v1";
const stopped: RunnerLifecycleStatus = { schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "bluefire-rust-runner.v1", profile_id: profile, loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null };

function mount(entry: string, component = <RunnersPage />) {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "runners", resources: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}>{component}</MemoryRouter></QueryClientProvider>);
  return client;
}

it("does not select or probe the first enrolled profile when diagnostics has no experiment context", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue(stopped);
  const bootstrap = vi.spyOn(api, "bootstrapRunner");
  mount("/runners");
  expect(await screen.findByText("Choose an experiment profile")).toBeVisible();
  expect(screen.getByRole("combobox", { name: "Experiment runner profile" })).toHaveValue("");
  expect(status).not.toHaveBeenCalled();
  expect(bootstrap).not.toHaveBeenCalled();
});

it("keeps the experiment profile through status and explicit upgrade without expanding trust", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue(stopped);
  const upgrade = vi.spyOn(api, "bootstrapRunner").mockResolvedValue({ ...stopped, profile_id: "gate11-windows-cancellation-witness.v1" });
  const revoke = vi.spyOn(api, "revokeRunner");
  const remove = vi.spyOn(api, "removeRunner");
  const user = userEvent.setup();
  mount(`/runners?profile=${profile}`);
  await user.click(await screen.findByRole("button", { name: "Review runner upgrade" }));
  expect(upgrade).not.toHaveBeenCalled();
  await screen.findByRole("button", { name: "Apply reviewed runner upgrade" });
  expect(screen.getByText(/sandbox, enrollment, permitted profiles and protocol contracts match/i)).not.toBeVisible();
  await user.click(screen.getByText("Exact artifacts and history binding"));
  expect(screen.getByText(/sandbox, enrollment, permitted profiles and protocol contracts match/i)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Apply reviewed runner upgrade" }));
  await waitFor(() => expect(upgrade).toHaveBeenCalledExactlyOnceWith(profile, true, upgradeDigest));
  expect(screen.getByRole("combobox", { name: "Experiment runner profile" })).toHaveValue(profile);
  expect(status.mock.calls.every(([selected]) => selected === profile)).toBe(true);
  expect(revoke).not.toHaveBeenCalled(); expect(remove).not.toHaveBeenCalled();
});

it("retains the actual prior-history refusal and never retries or removes history", async () => {
  vi.spyOn(api, "runnerStatus").mockResolvedValue(stopped);
  const reason = "Runner upgrade is blocked by prior execution recovery history.";
  const upgrade = vi.spyOn(api, "bootstrapRunner").mockRejectedValue(new ApiError("Managed runner bootstrap was refused.", "runner_bootstrap_refused", [reason], 409));
  const start = vi.spyOn(api, "startRunner");
  const user = userEvent.setup(); mount(`/runners?profile=${profile}`);
  await user.click(await screen.findByRole("button", { name: "Review runner upgrade" }));
  await user.click(await screen.findByRole("button", { name: "Apply reviewed runner upgrade" }));
  expect(await screen.findByText(reason)).toBeVisible();
  expect(screen.getByText(/keep the runner stopped when upgrade is refused/i)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Refresh" }));
  expect(upgrade).toHaveBeenCalledTimes(1); expect(start).not.toHaveBeenCalled();
});

it("does not adopt another profile's authenticated status or silently replace an unavailable linked profile", async () => {
  vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...stopped, profile_id: "gate11-windows-cancellation-witness.v1", state: "ready", process: "authenticated", health: { accepting_execute: true } });
  mount(`/runners?profile=${profile}`);
  expect(await screen.findByText("Managed status unavailable")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Stop safely" })).not.toBeInTheDocument();
});

it("keeps diagnostics reachable with profile context while authenticated and explains method preflight", async () => {
  vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...stopped, state: "ready", process: "authenticated", health: { accepting_execute: true } });
  mount("/builder", <ExecuteRunnerReadiness profileId={profile} />);
  expect(await screen.findByText("Runner authenticated")).toBeVisible();
  expect(screen.getByRole("link", { name: "Open runner diagnostics" })).toHaveAttribute("href", `/runners?profile=${profile}`);
  expect(screen.getByText(/Preflight still checks whether its actual methods support/i)).toBeVisible();
  expect(screen.getByText("Preflight reports a missing runner method?")).toBeVisible();
});

it("offers profile-bound recovery for an actual missing-inventory finding without retrying execution", () => {
  const start = vi.spyOn(api, "startRunner");
  const submit = vi.spyOn(api, "submitRun");
  mount("/runs", <RunnerInventoryRecovery profileId={profile} problems={["Runner inventory is missing enabled action(s): sandbox.collection.atomic-gzip.v1"]} />);
  expect(screen.getByRole("link", { name: "Review runner update for this profile" })).toHaveAttribute("href", `/runners?profile=${profile}`);
  expect(screen.getByText(/Keep this experiment unstarted/)).toBeVisible();
  expect(start).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
});


it("keeps a pending upgrade refusal bound to the submitted profile after navigation", async () => {
  const otherProfile = "sandbox-observe-only.v1";
  vi.spyOn(api, "runnerStatus").mockImplementation(async (selected) => ({ ...stopped, profile_id: selected ?? profile }));
  let rejectUpgrade!: (error: Error) => void;
  const upgrade = vi.spyOn(api, "bootstrapRunner").mockImplementation(() => new Promise((_resolve, reject) => { rejectUpgrade = reject; }));
  const user = userEvent.setup();
  mount(`/runners?profile=${profile}`, <><Link to={`/runners?profile=${otherProfile}`}>Other profile</Link><Link to={`/runners?profile=${profile}`}>Original profile</Link><RunnersPage /></>);
  await user.click(await screen.findByRole("button", { name: "Review runner upgrade" }));
  await user.click(await screen.findByRole("button", { name: "Apply reviewed runner upgrade" }));
  await waitFor(() => expect(upgrade).toHaveBeenCalledExactlyOnceWith(profile, true, upgradeDigest));
  await user.click(screen.getByRole("link", { name: "Other profile" }));
  const reason = "Runner upgrade is blocked by prior execution recovery history.";
  await act(async () => rejectUpgrade(new ApiError("Managed runner bootstrap was refused.", "runner_bootstrap_refused", [reason], 409)));
  expect(screen.getByRole("combobox", { name: "Experiment runner profile" })).toHaveValue(otherProfile);
  expect(screen.queryByText(reason)).not.toBeInTheDocument();
  await user.click(screen.getByRole("link", { name: "Original profile" }));
  expect(await screen.findByText(reason)).toBeVisible();
  expect(upgrade).toHaveBeenCalledTimes(1);
});
