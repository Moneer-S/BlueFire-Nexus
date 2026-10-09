import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExecuteRunnerReadiness } from "../src/components/ExecuteRunnerReadiness";
import { api, ApiError } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { RunnersPage } from "../src/pages/CatalogPages";
import type { RunnerLifecycleStatus } from "../src/types";

vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), DEMO_MODE: false }));
const enrolledId = "sandbox-execute.v1";
const addedId = "gzip-execute.v1";
const profile = demoCatalog.runner_profiles.find((item) => item.id === enrolledId)!;
const catalog = { ...demoCatalog, runner_profiles: [profile, { ...profile, id: addedId }] };
const stopped: RunnerLifecycleStatus = {
  schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped",
  runner_id: "bluefire-rust-runner.v1", profile_id: enrolledId, loopback_only: true,
  enrollment: "active", process: "absent", runner: null, health: null,
};
const notEnrolled: RunnerLifecycleStatus = {
  ...stopped, state: "unavailable", profile_id: addedId, process: "unavailable",
  profile_enrollment: { state: "not_enrolled", enrolled_profile_ids: [enrolledId] },
};

function mount(component = <RunnersPage />) {
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "runners", resources: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/runners?profile=${addedId}`]}>{component}</MemoryRouter></QueryClientProvider>);
}

it("guides explicit trust replacement through an actual enrolled profile without widening it", async () => {
  let phase: "active" | "revoked" | "absent" | "renewed" = "active";
  const status = vi.spyOn(api, "runnerStatus").mockImplementation(async (selected) => {
    if (phase === "absent") return { ...stopped, state: "unbootstrapped", enrollment: "absent", profile_id: null };
    if (phase === "renewed") return { ...stopped, profile_id: selected! };
    return selected === addedId ? notEnrolled : { ...stopped, enrollment: phase };
  });
  const revoke = vi.spyOn(api, "revokeRunner").mockImplementation(async () => { phase = "revoked"; return { ...stopped, enrollment: "revoked" }; });
  const remove = vi.spyOn(api, "removeRunner").mockImplementation(async () => { phase = "absent"; return { ...stopped, state: "unbootstrapped", enrollment: "absent", profile_id: null }; });
  const bootstrap = vi.spyOn(api, "bootstrapRunner").mockImplementation(async () => { phase = "renewed"; return { ...stopped, profile_id: addedId }; });
  const start = vi.spyOn(api, "startRunner");
  const stop = vi.spyOn(api, "stopRunner");
  const upgrade = vi.spyOn(api, "reviewRunnerUpgrade");
  const submit = vi.spyOn(api, "submitRun");
  const user = userEvent.setup();
  mount();
  expect(await screen.findByText("This profile is not enrolled")).toBeVisible();
  expect(screen.getByText(/Removal clears runner transport history/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Verify & enroll" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start authenticated host" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Revoke trust" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review runner upgrade" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Refresh" }));
  await waitFor(() => expect(status).toHaveBeenCalledTimes(2));
  expect(bootstrap).not.toHaveBeenCalled(); expect(revoke).not.toHaveBeenCalled(); expect(remove).not.toHaveBeenCalled();
  const enrolled = screen.getByRole("link", { name: "Inspect enrolled profile: Workspace actions" });
  expect(enrolled).toHaveAttribute("href", `/runners?profile=${enrolledId}`);
  await user.click(enrolled);
  await user.click(await screen.findByRole("button", { name: "Revoke trust" }));
  expect(revoke).toHaveBeenCalledExactlyOnceWith();
  await user.click(await screen.findByRole("button", { name: "Remove revoked trust" }));
  const dialog = screen.getByRole("dialog", { name: "Remove revoked runner trust" });
  const confirm = within(dialog).getByRole("button", { name: "Confirm removal" });
  expect(confirm).toBeDisabled();
  await user.type(within(dialog).getByRole("textbox", { name: "Runner ID" }), stopped.runner_id);
  await user.click(confirm);
  await waitFor(() => expect(remove).toHaveBeenCalledExactlyOnceWith(stopped.runner_id));
  await screen.findByRole("button", { name: "Verify & enroll" });
  await user.selectOptions(screen.getByRole("combobox", { name: "Experiment runner profile" }), addedId);
  await user.click(await screen.findByRole("button", { name: "Verify & enroll" }));
  expect(await screen.findByRole("button", { name: "Start authenticated host" })).toBeVisible();
  expect(bootstrap).toHaveBeenCalledExactlyOnceWith(addedId);
  expect(start).not.toHaveBeenCalled(); expect(stop).not.toHaveBeenCalled(); expect(upgrade).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
  expect(screen.getByRole("combobox", { name: "Experiment runner profile" })).toHaveValue(addedId);
});

it("keeps refresh available after a status error and displays its bounded refusal", async () => {
  const reason = "Runner enrollment could not be verified.";
  const status = vi.spyOn(api, "runnerStatus").mockRejectedValue(new ApiError("Managed runner status could not be verified.", "runner_lifecycle_unavailable", [reason], 409));
  const bootstrap = vi.spyOn(api, "bootstrapRunner");
  const start = vi.spyOn(api, "startRunner");
  const user = userEvent.setup();
  mount();
  expect(await screen.findByText("Managed status unavailable")).toBeVisible();
  expect(screen.getByText(reason)).toBeVisible();
  status.mockResolvedValue(notEnrolled);
  await user.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByText("This profile is not enrolled")).toBeVisible();
  expect(status).toHaveBeenCalledTimes(2);
  expect(bootstrap).not.toHaveBeenCalled(); expect(start).not.toHaveBeenCalled();
});

it("does not invent a recovery profile when enrolled IDs are not active in the catalog", async () => {
  vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...notEnrolled, profile_enrollment: { state: "not_enrolled", enrolled_profile_ids: ["retired-execute.v1"] } });
  mount();
  expect(await screen.findByText(/No active enrolled profile is available/)).toBeVisible();
  expect(screen.queryByRole("link", { name: /Inspect enrolled profile/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Verify & enroll" })).not.toBeInTheDocument();
});

it("links Runs to the selected enrollment recovery without preparing or starting anything", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue(notEnrolled);
  const bootstrap = vi.spyOn(api, "bootstrapRunner");
  const start = vi.spyOn(api, "startRunner");
  const user = userEvent.setup();
  mount(<ExecuteRunnerReadiness profileId={addedId}/>);
  expect(await screen.findByText("This profile is not enrolled")).toBeVisible();
  expect(screen.getByRole("link", { name: "Review enrollment recovery" })).toHaveAttribute("href", `/runners?profile=${addedId}`);
  expect(screen.queryByRole("button", { name: "Prepare runner" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start runner" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Check runner status" }));
  await waitFor(() => expect(status).toHaveBeenCalledTimes(2));
  expect(bootstrap).not.toHaveBeenCalled(); expect(start).not.toHaveBeenCalled();
});

it("keeps interrupted upgrade recovery ahead of trust replacement for an added profile", async () => {
  vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...notEnrolled, process: "absent", upgrade_recovery_required: true });
  const upgrade = vi.spyOn(api, "reviewRunnerUpgrade");
  const revoke = vi.spyOn(api, "revokeRunner");
  const remove = vi.spyOn(api, "removeRunner");
  mount();
  expect(await screen.findByText(/An interrupted runner update must be completed/)).toBeVisible();
  expect(screen.getByRole("link", { name: "Runner profiles" })).toHaveAttribute("href", "/runner-profiles");
  expect(screen.getByRole("link", { name: "Inspect enrolled profile: Workspace actions" })).toBeVisible();
  expect(screen.queryByText(/Once the host is stopped, explicitly revoke/)).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review runner upgrade" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Revoke trust" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Remove revoked trust" })).not.toBeInTheDocument();
  expect(upgrade).not.toHaveBeenCalled(); expect(revoke).not.toHaveBeenCalled(); expect(remove).not.toHaveBeenCalled();
});
