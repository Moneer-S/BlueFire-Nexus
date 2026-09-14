import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect, useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { RunWorkspace } from "../src/components/RunWorkspace";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { RunnerLifecycleStatus } from "../src/types";

vi.mock("../src/lib/api", async original => ({ ...await original<object>(), DEMO_MODE: false }));
const first = "sandbox-execute.v1";
const second = "other-execute.v1";
const stopped: RunnerLifecycleStatus = { schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "runner", profile_id: first, loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null };
const ready = { ...stopped, state: "ready", process: "authenticated", health: { accepting_execute: true } };
function Harness() {
  const { runConfig, setRunConfig } = useProduct(); const [seeded, setSeeded] = useState(false);
  useEffect(() => { if (!seeded) { setRunConfig({ ...runConfig, mode: "execute", profileId: first, autonomy: "off" }); setSeeded(true); } }, [runConfig, seeded, setRunConfig]);
  if (!seeded) return null;
  return <><button onClick={() => setRunConfig({ ...runConfig, profileId: second })}>Choose other profile</button><button onClick={() => setRunConfig({ ...runConfig, profileId: "missing" })}>Choose unavailable profile</button><RunWorkspace/></>;
}
function mount() {
  const profile = demoCatalog.runner_profiles.find(value => value.id === first)!;
  vi.spyOn(api, "catalog").mockResolvedValue({ ...demoCatalog, runner_profiles: [...demoCatalog.runner_profiles, { ...profile, id: second }] });
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", runs: [], unavailable_run_count: 0 });
  vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [demoScenario] });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [] });
  const submit = vi.spyOn(api, "submitRun");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  client.setQueryData(["runner-lifecycle"], { ...ready, profile_id: "default-profile" });
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/runs?prepare=1"]}><Harness/></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { user: userEvent.setup(), client, submit };
}
const guide = () => within(screen.getByRole("region", { name: "Guided local Execute" }));
it("queries, prepares, and starts the selected profile without using the default cache", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...stopped, state: "unbootstrapped", profile_id: null, enrollment: "absent" });
  const bootstrap = vi.spyOn(api, "bootstrapRunner").mockResolvedValue(stopped);
  const start = vi.spyOn(api, "startRunner").mockResolvedValue(ready);
  const { user, submit } = mount();
  await user.click(await screen.findByRole("button", { name: "Prepare runner" }));
  await user.click(await screen.findByRole("button", { name: "Start runner" }));
  await waitFor(() => expect(guide().getByText("Ready")).toBeVisible());
  expect(status).toHaveBeenCalledExactlyOnceWith(first);
  expect(bootstrap).toHaveBeenCalledExactlyOnceWith(first);
  expect(start).toHaveBeenCalledExactlyOnceWith(first);
  expect(submit).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Create approval-gated job" })).toBeDisabled();
});
it("keeps a late setup result in its original profile cache after selection changes", async () => {
  vi.spyOn(api, "runnerStatus").mockImplementation(async profile => ({ ...stopped, profile_id: profile! }));
  let finish!: (value: RunnerLifecycleStatus) => void;
  const start = vi.spyOn(api, "startRunner").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const { user, client, submit } = mount();
  await user.click(await screen.findByRole("button", { name: "Start runner" }));
  await user.click(screen.getByRole("button", { name: "Choose other profile" }));
  await waitFor(() => expect(api.runnerStatus).toHaveBeenCalledWith(second));
  await act(async () => finish(ready));
  expect(await screen.findByRole("button", { name: "Start runner" })).toBeEnabled();
  expect(guide().queryByText("Ready")).not.toBeInTheDocument();
  expect(screen.queryByText(/authenticated and ready for preflight/)).not.toBeInTheDocument();
  expect(client.getQueryData(["runner-lifecycle", first])).toEqual(ready);
  expect(client.getQueryData(["runner-lifecycle", second])).toEqual({ ...stopped, profile_id: second });
  expect(start).toHaveBeenCalledExactlyOnceWith(first); expect(submit).not.toHaveBeenCalled();
});
it("does not use a ready response for a different or missing profile", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...ready, profile_id: second });
  const start = vi.spyOn(api, "startRunner");
  const { user } = mount();
  await screen.findByRole("link", { name: /Open runner diagnostics/ });
  expect(guide().queryByText("Ready")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start runner" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Choose unavailable profile" }));
  expect(status).toHaveBeenCalledExactlyOnceWith(first);
  expect(screen.queryByRole("button", { name: "Prepare runner" })).not.toBeInTheDocument();
  expect(start).not.toHaveBeenCalled();
});

it("does not repaint a new profile with an earlier delayed readiness lookup", async () => {
  let finish!: (value: RunnerLifecycleStatus) => void;
  const previous = new Promise<RunnerLifecycleStatus>(resolve => { finish = resolve; });
  vi.spyOn(api, "runnerStatus").mockImplementation(profile => profile === first ? previous : Promise.resolve({ ...stopped, profile_id: second }));
  const { user } = mount();
  await waitFor(() => expect(api.runnerStatus).toHaveBeenCalledWith(first));
  await user.click(screen.getByRole("button", { name: "Choose other profile" }));
  await screen.findByRole("button", { name: "Start runner" });
  await act(async () => finish(ready));
  expect(guide().queryByText("Ready")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Start runner" })).toBeEnabled();
});
it("refuses a mismatched setup result and hides stale ready data after a failed status refresh", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue(stopped);
  vi.spyOn(api, "startRunner").mockResolvedValue({ ...ready, profile_id: second });
  const { user, client } = mount();
  await user.click(await screen.findByRole("button", { name: "Start runner" }));
  expect(await screen.findByText(/Runner setup returned a different profile/)).toBeVisible();
  expect(client.getQueryData(["runner-lifecycle", first])).toEqual(stopped);
  await act(async () => { client.setQueryData(["runner-lifecycle", first], ready); });
  await waitFor(() => expect(guide().getByText("Ready")).toBeVisible());
  status.mockRejectedValue(new Error("Status unavailable"));
  await act(async () => { await client.invalidateQueries({ queryKey: ["runner-lifecycle", first] }); });
  await waitFor(() => expect(guide().getByText("Unavailable")).toBeVisible());
  expect(guide().queryByText("Ready")).not.toBeInTheDocument();
});
