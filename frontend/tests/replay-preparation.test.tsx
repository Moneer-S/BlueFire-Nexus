import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api, type ReplayPreparation } from "../src/lib/api";
import { demoBehaviors, demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { ComparePage } from "../src/pages/Compare";

const behavior = { ...demoBehaviors[0]!, title: "Collect reviewed records", parameters: [{ name: "record_count", type: "integer" as const, minimum: 1, maximum: 9 }] };
const scenario = { ...demoScenario, start: "collect", edges: [], steps: [{ id: "collect", behavior_id: behavior.id, parameters: { record_count: 3 }, inputs: {}, alternates: [] }] };
const source = { ...demoRuns[0]!, mode: "execute" as const, scenario, target_scope: { scope_refs: ["sandbox.workspace"] } };
function prepared(request: Record<string, unknown>): ReplayPreparation {
  return {
    schema_version: "bluefire.replay-preparation.v1", preparation_id: "replay-preparation-reviewed",
    preparation_context: { schema_version: "bluefire.replay-preparation-context.v1", runner_readiness: { reviewed: true } },
    binding: { source: { run_id: source.run_id }, replay_request: structuredClone(request) },
    replay_request: structuredClone(request), replay_extent: "full", scenario, lineage: { source_run_id: source.run_id },
    approval_created: false, effects_started: false,
    preflight: { ready: false, status: "approval_required", scope: source.target_scope, plan: { steps: [], edges: [], mode: "execute" },
      approval_binding: { state_digest: "state-reviewed", plan_digest: "plan-reviewed", target_scope_digest: "scope-reviewed", profile_id: "reviewed-lab", maximum_tier: "controlled" },
      approval_envelope: { schema_version: "bluefire.approval-envelope.v1", envelope_digest: "envelope-reviewed", scenario_id: scenario.id, steps: [] },
    },
  };
}
function mount() {
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", runs: [source], unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue({ ...demoCatalog, behaviors: [behavior] });
  vi.spyOn(api, "runDetail").mockResolvedValue(source);
  vi.spyOn(api, "preflight").mockRejectedValue(new Error("Full replay must use the exact preparation endpoint"));
  const replay = vi.spyOn(api, "replay").mockResolvedValue({ ...source, run_id: "run-20300101T000000Z-bbbbbbbbbbbbbbbb" });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/compare?source=${source.run_id}`]}><ComparePage /></MemoryRouter></QueryClientProvider>);
  return replay;
}
afterEach(() => vi.restoreAllMocks());

it("submits exactly the prepared request and readiness context after a fresh explicit approval", async () => {
  const user = userEvent.setup();
  const prepare = vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => prepared(request));
  const replay = mount();
  await user.click(await screen.findByRole("button", { name: "Review Execute replay" }));
  await screen.findByRole("region", { name: "Prepared Execute replay" });
  expect(api.preflight).not.toHaveBeenCalled();
  expect(replay).not.toHaveBeenCalled();
  await user.click(screen.getByRole("checkbox", { name: /I approve this reviewed Execute replay/ }));
  await user.type(screen.getByRole("textbox", { name: "Fresh replay operator identity" }), "reviewing-operator");
  await user.click(screen.getByRole("button", { name: "Create approved Execute replay" }));
  const request = prepare.mock.calls[0]![1];
  expect(replay).toHaveBeenCalledWith(source.run_id, { ...request, preparation_id: "replay-preparation-reviewed", preparation_context: prepared(request).preparation_context, approval: { confirmed: true, approved_by: "reviewing-operator" } });
});

it.each(["source", "request"])("refuses a prepared response with a mismatched %s", async (change) => {
  const user = userEvent.setup();
  vi.spyOn(api, "prepareReplay").mockImplementation(async (_id, request) => {
    const result = prepared(request);
    if (change === "source") result.binding.source.run_id = "different-run";
    else result.replay_request = { exact: false };
    return result;
  });
  const replay = mount();
  await user.click(await screen.findByRole("button", { name: "Review Execute replay" }));
  expect(await screen.findByText(/returned review does not match/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Create approved Execute replay" })).toBeDisabled();
  expect(replay).not.toHaveBeenCalled();
});

it("invalidates a pending review when a numeric draft is unfinished, without sending the previous valid value", async () => {
  const user = userEvent.setup();
  let resolve!: (value: ReplayPreparation) => void;
  const pending = new Promise<ReplayPreparation>((done) => { resolve = done; });
  const prepare = vi.spyOn(api, "prepareReplay").mockReturnValue(pending);
  const replay = mount();
  await user.selectOptions(await screen.findByRole("combobox", { name: "What will change?" }), "parameters");
  await user.click(screen.getByRole("button", { name: "Change Record count" }));
  const input = screen.getByRole("spinbutton", { name: "Record count" });
  fireEvent.change(input, { target: { value: "7" } });
  await user.click(screen.getByRole("button", { name: "Review Execute replay" }));
  expect(prepare.mock.calls[0]![1]).toHaveProperty("parameter_overrides", { collect: { record_count: 7 } });
  fireEvent.change(input, { target: { value: "" } });
  await act(async () => { resolve(prepared(prepare.mock.calls[0]![1])); await pending; });
  await waitFor(() => expect(screen.getByRole("button", { name: "Review Execute replay" })).toBeDisabled());
  expect(screen.queryByRole("region", { name: "Prepared Execute replay" })).not.toBeInTheDocument();
  expect(screen.getByRole("checkbox", { name: /I approve this reviewed Execute replay/ })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Create approved Execute replay" })).toBeDisabled();
  expect(replay).not.toHaveBeenCalled();
  expect(input).toHaveValue(null);
});

