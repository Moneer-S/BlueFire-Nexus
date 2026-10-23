import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useNavigate } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ReceiverTestSetup } from "../src/components/ReceiverTestSetup";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { receiverScenarioSetupPath } from "../src/lib/receiver-navigation";
import { rememberReceiverConfiguration, rememberReceiverSelection } from "../src/lib/receiver-setup";
import { receiverAssistantFixture } from "./receiver-assistance-fixture";
import { ProductProvider } from "../src/state/ProductContext";
import { AssistanceProvider, useAssistancePanel } from "../src/state/AssistanceContext";
import type { RunConfiguration } from "../src/types";

function RouteSwitcher({ paths = [] }: { paths?: Array<{ label: string; path: string }> }) {
  const navigate = useNavigate();
  return <>{paths.map(({ label, path }) => <button key={label} onClick={() => navigate(path)}>{label}</button>)}</>;
}

function AssistantState() {
  const assistant = useAssistancePanel();
  return <output data-testid="assistant-selection-state">{JSON.stringify({ current: assistant?.selectionIsCurrent, selection: assistant?.selection })}</output>;
}

function mount(path: string, paths: Array<{ label: string; path: string }> = []) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><AssistanceProvider><ProductProvider><RouteSwitcher paths={paths} /><AssistantState /><ReceiverTestSetup disabled={false} onStart={vi.fn()} /></ProductProvider></AssistanceProvider></MemoryRouter></QueryClientProvider>);
}

it("reopens the exact captured version and run intent ahead of conflicting session settings", async () => {
  const fixture = receiverAssistantFixture();
  const source = fixture.native.context.selection;
  const savedVersion = { ...source, version: 2, digest: `sha256:${"d".repeat(64)}` };
  const runIntent = fixture.native.context.run_intent;
  const routeSelection = { kind: "receiver_scenario" as const, selection: savedVersion, run_intent: runIntent };
  const profileId = runIntent.runner_profile_id!;
  const staleConfiguration: RunConfiguration = {
    mode: "simulate", autonomy: "off", provider: "", model: "", endpoint: "", profileId: "sandbox-simulate.v1", runnerIds: [],
    scopeRefs: ["sandbox.workspace"], safetyTier: "controlled", approvalPolicy: "profile", approved: true,
    approvedBy: "old approval must not persist", maxSeconds: 120, maxSteps: 20, maxBytes: 8_388_608,
    collectors: ["stale.collector"], detectionBackends: ["structured-matcher"], cleanupPolicy: "always",
    counterfactual: "after_block", fixtureMode: true,
    actionImplementations: { "stale.action": "stale.method" },
  };
  rememberReceiverConfiguration(`${savedVersion.scenario_id}:${savedVersion.version}:${savedVersion.digest}`, staleConfiguration);
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [
    { ...savedVersion, title: fixture.native.context.scenario_title, created_at: "2026-10-02T12:00:00Z", document: fixture.native.context.scenario },
    { ...source, title: fixture.native.context.scenario_title, created_at: "2026-10-01T12:00:00Z", document: fixture.native.context.scenario },
  ] });
  const contextRequest = vi.spyOn(api, "receiverContext").mockImplementation(async (request) => ({ ...fixture.native.context, ...request }));

  mount(receiverScenarioSetupPath(routeSelection)!);

  await waitFor(() => expect(contextRequest).toHaveBeenCalled());
  expect(contextRequest.mock.calls[0]![0].selection).toEqual(savedVersion);
  expect(contextRequest.mock.calls[0]![0].run_intent).toEqual(runIntent);
  expect(contextRequest.mock.calls[0]![0].run_intent.runner_profile_id).toBe(profileId);
  expect(contextRequest.mock.calls[0]![0].run_intent.target_scope.scope_refs).toEqual(runIntent.target_scope.scope_refs);
  expect(contextRequest.mock.calls[0]![0].run_intent.collectors).toEqual(runIntent.collectors);
});

it("fails closed when the exact captured version is stale, without requesting receiver context", async () => {
  const fixture = receiverAssistantFixture();
  const source = fixture.native.context.selection;
  const stale = { ...source, version: 8, digest: `sha256:${"e".repeat(64)}` };
  const routeSelection = { kind: "receiver_scenario" as const, selection: stale, run_intent: fixture.native.context.run_intent };
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [
    { ...source, title: fixture.native.context.scenario_title, created_at: "2026-10-01T12:00:00Z", document: fixture.native.context.scenario },
  ] });
  const contextRequest = vi.spyOn(api, "receiverContext");
  const user = userEvent.setup();

  mount(receiverScenarioSetupPath(routeSelection)!);

  expect(await screen.findByText(/That exact saved version is no longer available/)).toBeInTheDocument();
  expect(contextRequest).not.toHaveBeenCalled();
  await user.selectOptions(screen.getByLabelText("Saved experiment", { exact: false }), `${source.scenario_id}:${source.version}:${source.digest}`);
  await waitFor(() => expect(contextRequest).toHaveBeenCalledWith(expect.objectContaining({ selection: source })));
});

it("restores a new captured intent when reopening the same saved version", async () => {
  const fixture = receiverAssistantFixture();
  const saved = fixture.native.context.selection;
  const first = { kind: "receiver_scenario" as const, selection: saved, run_intent: fixture.native.context.run_intent };
  const secondIntent = {
    ...fixture.native.context.run_intent,
    runner_profile_id: "other-owned-lab",
    target_scope: { scope_refs: ["other.scope"] },
    collectors: ["collector.other.v1"],
    action_implementations: { "action.other.v1": "method.other.v1" },
  };
  const second = { kind: "receiver_scenario" as const, selection: saved, run_intent: secondIntent };
  const version = { ...saved, title: fixture.native.context.scenario_title, created_at: "2026-10-02T12:00:00Z", document: fixture.native.context.scenario };
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [version] });
  const contextRequest = vi.spyOn(api, "receiverContext").mockImplementation(async (request) => ({ ...fixture.native.context, ...request }));
  const user = userEvent.setup();

  mount(receiverScenarioSetupPath(first)!, [{ label: "Switch captured setup", path: receiverScenarioSetupPath(second)! }]);
  await waitFor(() => expect(contextRequest).toHaveBeenCalledTimes(1));
  await user.click(screen.getByRole("button", { name: "Switch captured setup" }));
  await waitFor(() => expect(contextRequest).toHaveBeenCalledTimes(2));
  expect(contextRequest.mock.calls[1]![0].selection).toEqual(saved);
  expect(contextRequest.mock.calls[1]![0].run_intent).toEqual(secondIntent);
});

it("restores comparison workflow when reopening the same captured setup on the mounted page", async () => {
  const fixture = receiverAssistantFixture();
  const selection = { kind: "receiver_scenario" as const, selection: fixture.native.context.selection, run_intent: fixture.native.context.run_intent };
  const setupPath = receiverScenarioSetupPath(selection)!;
  const version = { ...selection.selection, title: fixture.native.context.scenario_title, created_at: "2026-10-02T12:00:00Z", document: fixture.native.context.scenario };
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [version] });
  const contextRequest = vi.spyOn(api, "receiverContext").mockImplementation(async (request) => ({
    ...fixture.native.context,
    ...request,
    schema_version: request.workflow ? "bluefire.receiver-defense-context.v2" : "bluefire.receiver-defense-context.v1",
    ...(request.workflow ? { control: null, eligible: false, workflow: request.workflow } : {}),
  }));
  const createReceiverTest = vi.spyOn(api, "createReceiverTest");
  const prepareReceiver = vi.spyOn(api, "prepareReceiver");
  const submitAssistance = vi.spyOn(api, "submitAssistance");
  const user = userEvent.setup();

  mount(setupPath, [{ label: "Reopen captured setup", path: setupPath }]);

  const comparison = await screen.findByRole("radio", { name: "Compare and restore prior policy" });
  const retained = screen.getByRole("radio", { name: "Retain redaction and verify legitimate use" });
  await waitFor(() => expect(contextRequest).toHaveBeenCalledTimes(1));
  expect(comparison).toBeChecked();
  expect(contextRequest.mock.calls[0]![0]).toEqual({ selection: selection.selection, run_intent: selection.run_intent });
  expect(await screen.findByRole("button", { name: "Coordinate with Assistant" })).toBeInTheDocument();

  await user.click(retained);
  await waitFor(() => expect(contextRequest).toHaveBeenCalledTimes(2));
  expect(contextRequest.mock.calls[1]![0]).toEqual({ selection: selection.selection, run_intent: selection.run_intent, workflow: "retained_redaction" });
  expect(screen.queryByRole("button", { name: "Coordinate with Assistant" })).not.toBeInTheDocument();
  await waitFor(() => expect(JSON.parse(screen.getByTestId("assistant-selection-state").textContent ?? "{}").current).toBe(false));

  await user.click(screen.getByRole("button", { name: "Reopen captured setup" }));

  await waitFor(() => expect(contextRequest).toHaveBeenCalledTimes(3));
  expect(screen.getByRole("radio", { name: "Compare and restore prior policy" })).toBeChecked();
  expect(contextRequest.mock.calls[2]![0]).toEqual({ selection: selection.selection, run_intent: selection.run_intent });
  expect(contextRequest.mock.calls[2]![0]).not.toHaveProperty("workflow");
  expect(await screen.findByRole("button", { name: "Coordinate with Assistant" })).toBeInTheDocument();
  await waitFor(() => {
    const published = JSON.parse(screen.getByTestId("assistant-selection-state").textContent ?? "{}");
    expect(published.current).toBe(true);
    expect(published.selection.selected).toEqual(selection);
    expect(published.selection.selected).not.toHaveProperty("workflow");
  });
  expect(createReceiverTest).not.toHaveBeenCalled();
  expect(prepareReceiver).not.toHaveBeenCalled();
  expect(submitAssistance).not.toHaveBeenCalled();
});

it("keeps a newly chosen version and storage warning when captured setup changes routes", async () => {
  const fixture = receiverAssistantFixture();
  const source = fixture.native.context.selection;
  const stored = { ...source, version: 1, digest: `sha256:${"a".repeat(64)}` };
  const captured = { ...source, version: 2, digest: `sha256:${"b".repeat(64)}` };
  const chosen = { ...source, version: 3, digest: `sha256:${"c".repeat(64)}` };
  rememberReceiverSelection(`${stored.scenario_id}:${stored.version}:${stored.digest}`);
  const selection = { kind: "receiver_scenario" as const, selection: captured, run_intent: fixture.native.context.run_intent };
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [stored, captured, chosen].map((item) => ({
    ...item, title: fixture.native.context.scenario_title, created_at: "2026-10-02T12:00:00Z", document: fixture.native.context.scenario,
  })) });
  const contextRequest = vi.spyOn(api, "receiverContext").mockImplementation(async (request) => ({ ...fixture.native.context, ...request }));
  const createReceiverTest = vi.spyOn(api, "createReceiverTest");
  const prepareReceiver = vi.spyOn(api, "prepareReceiver");
  const submitAssistance = vi.spyOn(api, "submitAssistance");
  const setItem = Storage.prototype.setItem;
  const storageWrite = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
    if (this === sessionStorage && key === "bluefire.receiver-defense.selected.v1") throw new Error("Browser storage is unavailable");
    setItem.call(this, key, value);
  });
  const user = userEvent.setup();

  mount(receiverScenarioSetupPath(selection)!);
  await screen.findByRole("radio", { name: "Compare and restore prior policy" });
  await waitFor(() => expect(contextRequest).toHaveBeenCalledTimes(1));
  await user.selectOptions(screen.getByLabelText("Saved experiment", { exact: false }), `${chosen.scenario_id}:${chosen.version}:${chosen.digest}`);

  await waitFor(() => expect(contextRequest).toHaveBeenCalledTimes(2));
  expect(screen.getByLabelText("Saved experiment", { exact: false })).toHaveValue(`${chosen.scenario_id}:${chosen.version}:${chosen.digest}`);
  expect(await screen.findByText("Browser storage is unavailable")).toBeInTheDocument();
  expect(storageWrite).toHaveBeenCalledWith("bluefire.receiver-defense.selected.v1", `${chosen.scenario_id}:${chosen.version}:${chosen.digest}`);
  expect(contextRequest.mock.calls[1]![0].selection).toEqual(chosen);
  expect(createReceiverTest).not.toHaveBeenCalled();
  expect(prepareReceiver).not.toHaveBeenCalled();
  expect(submitAssistance).not.toHaveBeenCalled();
});

it.each(["missing collectors", "empty action map", "duplicate receiver flag"])("issues no receiver context for a crafted setup URL with %s", async (problem) => {
  const fixture = receiverAssistantFixture();
  const selection = { kind: "receiver_scenario" as const, selection: fixture.native.context.selection, run_intent: fixture.native.context.run_intent };
  const altered = structuredClone(selection);
  if (problem === "missing collectors") altered.run_intent.collectors = undefined;
  if (problem === "empty action map") altered.run_intent.action_implementations = {};
  const params = new URLSearchParams({ receiver: "1", receiver_setup: JSON.stringify(altered) });
  if (problem === "duplicate receiver flag") params.append("receiver", "1");
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [
    { ...selection.selection, title: fixture.native.context.scenario_title, created_at: "2026-10-02T12:00:00Z", document: fixture.native.context.scenario },
  ] });
  const contextRequest = vi.spyOn(api, "receiverContext");

  mount(`/compare?${params}`);

  expect(await screen.findByText(/exact saved version link is invalid/i)).toBeInTheDocument();
  expect(contextRequest).not.toHaveBeenCalled();
});
