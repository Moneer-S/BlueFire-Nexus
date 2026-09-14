import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { SavedScenarioRunSetup } from "../src/pages/AssistedRun";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { validSavedRunSelection } from "../src/lib/run-assistance";
import { readAssistanceReceipt, storeAssistanceReceipt } from "../src/lib/assistance";
import { AssistanceProvider, useAssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

const digest = `sha256:${"c".repeat(64)}`;
const saved = { scenario_id: demoScenario.id, version: 2, digest, title: "Manual saved experiment", document: { ...demoScenario, title: "Manual saved experiment" }, created_at: "2030-01-01" };
function Witness() {
  const selection = useAssistanceSelection();
  const { scenario } = useProduct();
  return <><output aria-label="Selection">{JSON.stringify(selection)}</output><output aria-label="Draft">{JSON.stringify(scenario)}</output></>;
}
function mount(id: string | null = saved.scenario_id, selectedDigest = digest) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProductProvider><AssistanceProvider><MemoryRouter><Witness /><SavedScenarioRunSetup id={id} version={"2"} digest={selectedDigest} /></MemoryRouter></AssistanceProvider></ProductProvider></QueryClientProvider>);
}
function stub() {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [saved] });
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: saved });
  return vi.spyOn(api, "graphProposal");
}
it("opens a manually saved version without a graph proposal and retains explicit settings on return", async () => {
  const graph = stub(); const user = userEvent.setup(); const view = mount();
  await screen.findByRole("button", { name: "Run with Assistant" });
  const draft = screen.getByLabelText("Draft").textContent;
  const scope = screen.getByLabelText(/^Target scope/);
  await user.clear(scope); await user.type(scope, "owned.manual.scope");
  await waitFor(() => expect(screen.getByLabelText("Selection")).toHaveTextContent("owned.manual.scope"));
  const selected = JSON.parse(screen.getByLabelText("Selection").textContent!).selected;
  expect(selected.kind).toBe("saved_scenario");
  expect(selected.scenario).toEqual({ scenario_id: saved.scenario_id, version: 2, digest });
  expect(validSavedRunSelection(selected)).toBe(true);
  expect(storeAssistanceReceipt({ submission_id: "01234567-89ab-4def-8123-456789abcdef", context_digest: digest, selection: selected, message: "Prepare this exact experiment", autonomy: "assist", provider_id: "configured-fixture" })).toBe(true);
  expect(readAssistanceReceipt()).toMatchObject({ selection: selected });
  view.unmount(); mount();
  expect(await screen.findByLabelText(/^Target scope/)).toHaveValue("owned.manual.scope");
  expect(screen.getByLabelText("Draft").textContent).toBe(draft);
  expect(graph).not.toHaveBeenCalled();
});
it("offers saved versions with exact links, without preparing a run", async () => {
  const graph = stub(); const prepare = vi.spyOn(api, "assistanceRunContext"); mount(null);
  const link = await screen.findByRole("link", { name: "Manual saved experiment · version 2" });
  expect(link.getAttribute("href")).toContain("saved_scenario=");
  expect(link.getAttribute("href")).toContain("version=2");
  expect(link.getAttribute("href")).toContain(encodeURIComponent(digest));
  expect(prepare).not.toHaveBeenCalled(); expect(graph).not.toHaveBeenCalled();
});
it("refuses a different saved digest without publishing an Assistant selection", async () => {
  stub(); mount(saved.scenario_id, `sha256:${"d".repeat(64)}`);
  expect(await screen.findByText(/differs from the saved version/)).toBeVisible();
  expect(screen.getByLabelText("Selection")).toBeEmptyDOMElement();
  expect(screen.queryByRole("button", { name: "Run with Assistant" })).not.toBeInTheDocument();
});
it("rejects malformed saved identities and extra approval fields", () => {
  const valid = { kind: "saved_scenario", scenario: { scenario_id: saved.scenario_id, version: 2, digest }, run_intent: { mode: "simulate", autonomy: "off", ai_provider_id: null, runner_profile_id: null, target_scope: { scope_refs: ["workspace"] } } };
  expect(validSavedRunSelection(valid)).toBe(true);
  expect(validSavedRunSelection({ ...valid, approved: true })).toBe(false);
  expect(validSavedRunSelection({ ...valid, scenario: { ...valid.scenario, version: -1 } })).toBe(false);
});
