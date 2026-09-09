import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ReceiverTestSetup } from "../src/components/ReceiverTestSetup";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import { receiverFixtureDigest } from "./receiver-defense-fixture";

function Witness() {
  const { runConfig, scenario } = useProduct();
  return <><output aria-label="Global run configuration">{JSON.stringify(runConfig)}</output><output aria-label="Builder draft">{JSON.stringify(scenario)}</output></>;
}
it("starts the receiver form's selected profile without changing the Builder's run configuration", async () => {
  const catalog = structuredClone(demoCatalog);
  catalog.runner_profiles.push({ ...catalog.runner_profiles.find((profile) => profile.mode === "execute")!, id: "alternate-execute.v1" });
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [{ scenario_id: demoScenario.id, title: demoScenario.title, version: 1, digest: receiverFixtureDigest, created_at: "2026-09-07T00:00:00Z", document: demoScenario }] });
  vi.spyOn(api, "receiverContext").mockImplementation(async (request) => ({ schema_version: "bluefire.receiver-defense-context.v1", ...request, context_digest: receiverFixtureDigest, scenario: demoScenario, scenario_title: demoScenario.title,
    eligible: false, reasons: [{ code: "setup", message: "Review this saved graph." }], handoff: null, policies: [], availability: { supported: true, ready: false, reason: "Selected runner is stopped.", native_path: null }, limitations: [] }));
  const status = vi.spyOn(api, "runnerStatus").mockImplementation(async (profileId) => ({ schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "runner", profile_id: profileId!, loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null }));
  const start = vi.spyOn(api, "startRunner").mockImplementation(async (profileId) => ({ schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "runner", profile_id: profileId ?? null, loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null }));
  const onStart = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><Witness /><ReceiverTestSetup disabled={false} onStart={onStart} /></MemoryRouter></ProductProvider></QueryClientProvider>);
  const originalConfig = screen.getByLabelText("Global run configuration").textContent;
  const originalDraft = screen.getByLabelText("Builder draft").textContent;
  const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText("Saved experiment", { exact: false }), `${demoScenario.id}:1:${receiverFixtureDigest}`);
  await user.click(screen.getByRole("radio", { name: /Execute/ }));
  await user.selectOptions(screen.getByLabelText("Environment profile"), "alternate-execute.v1");
  await waitFor(() => expect(status).toHaveBeenCalledWith("alternate-execute.v1"));
  await user.click(await screen.findByRole("button", { name: "Start runner" }));
  await waitFor(() => expect(start).toHaveBeenCalledWith("alternate-execute.v1"));
  expect(start).toHaveBeenCalledOnce(); expect(onStart).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Global run configuration").textContent).toBe(originalConfig);
  expect(screen.getByLabelText("Builder draft").textContent).toBe(originalDraft);
  expect(screen.getByRole("radio", { name: /Auto/ })).toBeDisabled();
});
