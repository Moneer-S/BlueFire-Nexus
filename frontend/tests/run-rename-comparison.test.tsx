import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api, type ReplayPreparation } from "../src/lib/api";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { ComparePage } from "../src/pages/Compare";
import type { RunRecord } from "../src/types";

const source: RunRecord = {
  ...structuredClone(demoRuns[0]!), mode: "execute", scenario: structuredClone(demoScenario),
  scenario_title: "File collection", target_scope: { scope_refs: ["sandbox.workspace", "sandbox.secondary"] },
};
const other: RunRecord = { ...structuredClone(source), run_id: "run-20300101T000000Z-bbbbbbbbbbbbbbbb", mode: "simulate" };
const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach(client => client.clear()); });

function prepared(request: Record<string, unknown>): ReplayPreparation {
  return {
    schema_version: "bluefire.replay-preparation.v1", preparation_id: "replay-preparation-reviewed",
    preparation_context: { schema_version: "bluefire.replay-preparation-context.v1", runner_readiness: { reviewed: true } },
    binding: { source: { run_id: source.run_id }, replay_request: structuredClone(request) },
    replay_request: structuredClone(request), replay_extent: "full", scenario: source.scenario!, lineage: { source_run_id: source.run_id },
    approval_created: false, effects_started: false,
    preflight: { ready: false, status: "approval_required", scope: { scope_refs: ["sandbox.workspace"] },
      plan: { steps: [], edges: [], mode: "execute" },
      approval_binding: { state_digest: "state-reviewed", plan_digest: "plan-reviewed", target_scope_digest: "scope-reviewed", profile_id: "reviewed-lab", maximum_tier: "controlled" },
      approval_envelope: { schema_version: "bluefire.approval-envelope.v1", envelope_digest: "envelope-reviewed", scenario_id: source.scenario!.id, steps: [] },
    },
  };
}
function mount() {
  vi.spyOn(api, "runs").mockResolvedValue({ runs: [source, other], unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "runDetail").mockImplementation(async id => id === source.run_id ? source : other);
  const prepare = vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => prepared(request));
  const submit = vi.spyOn(api, "submitReplay");
  const replay = vi.spyOn(api, "replay");
  const approve = vi.spyOn(api, "approveJob");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/compare?source=${source.run_id}`]}><ComparePage/></MemoryRouter></QueryClientProvider>);
  return { client, prepare, submit, replay, approve };
}
async function prepareNarrowed() {
  const state = mount();
  const user = userEvent.setup();
  const scope = await screen.findByRole("textbox", { name: "Exact target scope" });
  await waitFor(() => expect(scope).toHaveValue("sandbox.workspace, sandbox.secondary"));
  await user.clear(scope);
  await user.type(scope, "sandbox.workspace");
  await user.click(screen.getByRole("button", { name: "Review Execute replay" }));
  await screen.findByRole("region", { name: "Prepared Execute replay" });
  expect(screen.getByRole("button", { name: "Continue to approval" })).toBeEnabled();
  expect(state.prepare).toHaveBeenCalledOnce();
  expect(state.prepare.mock.calls[0]![1]).toHaveProperty("target_scope", { scope_refs: ["sandbox.workspace"] });
  return { ...state, user, scope };
}

it("retains narrowed scope and exact preparation after a presentation-only source refresh", async () => {
  const { client, prepare, scope, submit, replay, approve } = await prepareNarrowed();
  const renamed: RunRecord = { ...source, presentation: {
    schema_version: "bluefire.run-presentation.v1", run_id: source.run_id,
    display_name: "Operator named collection", default_name: "File collection", updated_at: "2030-01-01T12:00:00Z",
  } };
  vi.mocked(api.runDetail).mockResolvedValue(renamed);
  await act(async () => { await client.refetchQueries({ queryKey: ["run", source.run_id], exact: true }); });
  await waitFor(() => expect(screen.getByRole("combobox", { name: "Source run" }).querySelector("option:checked")).toHaveTextContent("Operator named collection"));
  expect(scope).toHaveValue("sandbox.workspace");
  expect(screen.getByRole("region", { name: "Prepared Execute replay" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Continue to approval" })).toBeEnabled();
  expect(prepare).toHaveBeenCalledOnce();
  expect(submit).not.toHaveBeenCalled(); expect(replay).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
});

it("invalidates the reviewed replay when canonical source content changes even with the same run ID", async () => {
  const { client, scope, prepare, submit, replay, approve } = await prepareNarrowed();
  vi.mocked(api.runDetail).mockResolvedValue({ ...source, manifest: { ...source.manifest, bundle_hash: "sha256:changed-canonical-record" } });
  await act(async () => { await client.refetchQueries({ queryKey: ["run", source.run_id], exact: true }); });
  await waitFor(() => expect(scope).toHaveValue("sandbox.workspace, sandbox.secondary"));
  expect(screen.queryByRole("region", { name: "Prepared Execute replay" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Continue to approval" })).toBeDisabled();
  expect(prepare).toHaveBeenCalledOnce();
  expect(submit).not.toHaveBeenCalled(); expect(replay).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
});

it("restores source scope after visiting a different Simulate source and returning to the original run", async () => {
  const { user, prepare, submit, replay, approve } = await prepareNarrowed();
  await user.selectOptions(screen.getByRole("combobox", { name: "Source run" }), other.run_id);
  await waitFor(() => expect(screen.queryByRole("textbox", { name: "Exact target scope" })).not.toBeInTheDocument());
  await user.selectOptions(screen.getByRole("combobox", { name: "Source run" }), source.run_id);
  expect(await screen.findByRole("textbox", { name: "Exact target scope" })).toHaveValue("sandbox.workspace, sandbox.secondary");
  expect(screen.queryByRole("region", { name: "Prepared Execute replay" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Continue to approval" })).toBeDisabled();
  expect(prepare).toHaveBeenCalledOnce();
  expect(submit).not.toHaveBeenCalled(); expect(replay).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
});
