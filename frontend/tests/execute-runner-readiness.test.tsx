import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExecuteRunnerReadiness } from "../src/components/ExecuteRunnerReadiness";
import { api } from "../src/lib/api";
import type { RunnerLifecycleStatus } from "../src/types";

vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), DEMO_MODE: false }));
const stopped: RunnerLifecycleStatus = { schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "runner", profile_id: "selected-execute.v1", loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null };
const ready = { ...stopped, state: "ready", process: "authenticated", health: { accepting_execute: true } };
function mount(profileId: string | undefined = "selected-execute.v1") {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><MemoryRouter><ExecuteRunnerReadiness profileId={profileId} /></MemoryRouter></QueryClientProvider>);
}

it("prepares then starts only the selected profile through explicit actions", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...stopped, state: "unbootstrapped", enrollment: "absent", profile_id: null });
  const bootstrap = vi.spyOn(api, "bootstrapRunner").mockImplementation(async () => { status.mockResolvedValue(stopped); return stopped; });
  const start = vi.spyOn(api, "startRunner").mockImplementation(async () => { status.mockResolvedValue(ready); return ready; });
  const submit = vi.spyOn(api, "submitRun");
  const user = userEvent.setup(); mount();
  await screen.findByRole("button", { name: "Prepare runner" });
  expect(bootstrap).not.toHaveBeenCalled(); expect(start).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Prepare runner" }));
  await user.click(await screen.findByRole("button", { name: "Start runner" }));
  expect(await screen.findByText("Ready for preflight")).toBeVisible();
  expect(bootstrap).toHaveBeenCalledExactlyOnceWith("selected-execute.v1");
  expect(start).toHaveBeenCalledExactlyOnceWith("selected-execute.v1");
  expect(submit).not.toHaveBeenCalled();
});

it("shows a refused start and allows a status check without retrying the action", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue(stopped);
  const start = vi.spyOn(api, "startRunner").mockRejectedValue(new Error("Enrollment must be renewed."));
  const user = userEvent.setup(); mount();
  await user.click(await screen.findByRole("button", { name: "Start runner" }));
  expect(await screen.findByText("Enrollment must be renewed.")).toBeVisible();
  status.mockResolvedValue({ ...stopped, enrollment: "revoked" });
  await waitFor(() => expect(screen.getByRole("button", { name: "Check runner status" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Check runner status" }));
  expect(await screen.findByRole("link", { name: "Open runner diagnostics" })).toHaveAttribute("href", "/runners");
  expect(screen.queryByRole("button", { name: "Start runner" })).not.toBeInTheDocument();
  expect(start).toHaveBeenCalledTimes(1);
});

it("does not call a runner ready without authenticated accepting health", async () => {
  vi.spyOn(api, "runnerStatus").mockResolvedValue({ ...ready, health: { accepting_execute: false } });
  mount();
  await screen.findByRole("link", { name: "Open runner diagnostics" });
  expect(screen.queryByText("Ready for preflight")).not.toBeInTheDocument();
});

it("requires a selected profile and never silently starts the default", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockResolvedValue(stopped);
  const start = vi.spyOn(api, "startRunner");
  mount("");
  expect(screen.queryByRole("button", { name: "Start runner" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Check runner status" })).toBeDisabled();
  expect(screen.getByText("Choose an Execute profile below to prepare its runner.")).toBeVisible();
  expect(start).not.toHaveBeenCalled();
  expect(status).not.toHaveBeenCalled();
});

it("isolates selected profile status from default cache and late setup responses", async () => {
  const status = vi.spyOn(api, "runnerStatus").mockImplementation(async (profile) => profile === "selected-execute.v1" ? stopped : { ...stopped, profile_id: profile!, state: "unavailable", enrollment: "revoked" });
  let finish!: (value: RunnerLifecycleStatus) => void;
  const start = vi.spyOn(api, "startRunner").mockReturnValue(new Promise((resolve) => { finish = resolve; }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  client.setQueryData(["runner-lifecycle"], ready);
  function Selection() {
    const [profile, setProfile] = useState("selected-execute.v1");
    return <><button onClick={() => setProfile("new-execute.v1")}>Choose another profile</button><ExecuteRunnerReadiness profileId={profile} /></>;
  }
  render(<QueryClientProvider client={client}><MemoryRouter><Selection /></MemoryRouter></QueryClientProvider>);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Start runner" }));
  await user.click(screen.getByRole("button", { name: "Choose another profile" }));
  expect(await screen.findByText("Finishing runner setup for the previous profile…")).toBeVisible();
  expect(status).toHaveBeenCalledWith("new-execute.v1");
  finish(ready);
  await waitFor(() => expect(screen.queryByText("Finishing runner setup for the previous profile…")).not.toBeInTheDocument());
  expect(screen.getByRole("link", { name: "Open runner diagnostics" })).toBeVisible();
  expect(screen.queryByText("Ready for preflight")).not.toBeInTheDocument();
  expect(start).toHaveBeenCalledExactlyOnceWith("selected-execute.v1");
  expect(client.getQueryData<RunnerLifecycleStatus>(["runner-lifecycle", "new-execute.v1"])?.enrollment).toBe("revoked");
});
