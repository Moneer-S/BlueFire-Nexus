import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ReceiverTestSetup } from "../src/components/ReceiverTestSetup";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import type { ReceiverContextRequest } from "../src/lib/receiver-defense-types";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import { receiverFixtureDigest } from "./receiver-defense-fixture";

function Witness() {
  const { runConfig, scenario } = useProduct();
  return <><output aria-label="Global configuration">{JSON.stringify(runConfig)}</output><output aria-label="Working graph">{JSON.stringify(scenario)}</output></>;
}

function mount(reasons?: { code: string; message: string }[]) {
  vi.spyOn(api, "catalog").mockResolvedValue(structuredClone(demoCatalog));
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [{ scenario_id: demoScenario.id, title: demoScenario.title, version: 1, digest: receiverFixtureDigest, created_at: "2026-09-07T00:00:00Z", document: demoScenario }] });
  const context = vi.spyOn(api, "receiverContext").mockImplementation(async (request: ReceiverContextRequest) => {
    const missing = ["sandbox.workspace", "network.loopback"].filter((ref) => !request.run_intent.target_scope.scope_refs.includes(ref));
    const findings = reasons ?? (missing.length ? [{ code: "receiver_scope_required", message: `Receiver experiments require sandbox.workspace and network.loopback. In Environment and run settings, update Target scope to explicitly include: ${missing.join(", ")}. The selected runner profile must permit both references.` }] : []);
    const eligible = request.run_intent.mode === "execute" && findings.length === 0;
    return { schema_version: "bluefire.receiver-defense-context.v1", ...request, context_digest: receiverFixtureDigest, scenario: demoScenario, scenario_title: demoScenario.title,
      eligible, reasons: findings, handoff: { stage_step_id: "stage_records", handoff_step_id: "authorized_peer_handoff", port: 4317, artifact_type: "artifact.sandbox.bundle.v1", container: "jsonl" }, policies: [],
      availability: { supported: true, ready: eligible, reason: eligible ? null : "Use the supported Linux environment and prepare/start the selected native runner before preparing a receiver.", native_path: "/runs" }, limitations: [] };
  });
  const onStart = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><Witness /><ReceiverTestSetup disabled={false} onStart={onStart} /></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { context, onStart };
}

it.each(["sandbox.workspace", "network.loopback"])("keeps %s alone refused until the operator explicitly supplies both required scopes", async (initial) => {
  const user = userEvent.setup();
  const prepare = vi.spyOn(api, "prepareReceiver");
  const startRunner = vi.spyOn(api, "startRunner");
  const { context, onStart } = mount();
  const originalConfig = screen.getByLabelText("Global configuration").textContent;
  const originalGraph = screen.getByLabelText("Working graph").textContent;
  await user.selectOptions(await screen.findByLabelText(/Saved experiment/), `${demoScenario.id}:1:${receiverFixtureDigest}`);
  await user.click(screen.getByRole("radio", { name: /Execute/ }));
  const scope = screen.getByLabelText(/Target scope/);
  await user.clear(scope);
  await user.paste(initial);
  await waitFor(() => expect(screen.getByText(/In Environment and run settings, update Target scope/)).toHaveTextContent(`include: ${initial === "sandbox.workspace" ? "network.loopback" : "sandbox.workspace"}.`));
  expect(scope).toHaveValue(initial);
  expect(screen.getByRole("button", { name: "Save control test" })).toBeDisabled();
  expect(screen.queryByRole("link", { name: "Review the experiment in Build" })).not.toBeInTheDocument();
  expect(screen.queryByText("Prepare the lab first")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start runner" })).not.toBeInTheDocument();
  expect(onStart).not.toHaveBeenCalled();
  expect(prepare).not.toHaveBeenCalled();
  expect(startRunner).not.toHaveBeenCalled();

  await user.clear(scope);
  await user.paste("sandbox.workspace, network.loopback");
  await waitFor(() => expect(screen.getByRole("button", { name: "Save control test" })).toBeEnabled());
  expect(context).toHaveBeenLastCalledWith(expect.objectContaining({ run_intent: expect.objectContaining({ target_scope: { scope_refs: ["sandbox.workspace", "network.loopback"] } }) }));
  await user.click(screen.getByRole("button", { name: "Save control test" }));
  expect(onStart).toHaveBeenCalledOnce();
  expect(onStart).toHaveBeenCalledWith(expect.objectContaining({ selection: { kind: "saved_scenario", scenario_id: demoScenario.id, version: 1, digest: receiverFixtureDigest }, run_intent: expect.objectContaining({ mode: "execute", autonomy: "off", ai_provider_id: null, target_scope: { scope_refs: ["sandbox.workspace", "network.loopback"] } }) }));
  expect(prepare).not.toHaveBeenCalled();
  expect(startRunner).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Global configuration").textContent).toBe(originalConfig);
  expect(screen.getByLabelText("Working graph").textContent).toBe(originalGraph);
});

it("keeps profile-scope refusal in settings without offering an unrelated runner start", async () => {
  const user = userEvent.setup();
  const { onStart } = mount([{ code: "scope_required", message: "target scope is outside the selected profile: network.loopback" }]);
  await user.selectOptions(await screen.findByLabelText(/Saved experiment/), `${demoScenario.id}:1:${receiverFixtureDigest}`);
  expect(await screen.findByText(/target scope is outside the selected profile/)).toBeVisible();
  expect(screen.getByRole("group", { name: "Requested access" })).toBeVisible();
  await user.click(screen.getByText("Environment and scope references"));
  expect(screen.getByLabelText(/Target scope/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Save control test" })).toBeDisabled();
  expect(screen.queryByRole("link", { name: "Review the experiment in Build" })).not.toBeInTheDocument();
  expect(screen.queryByText("Prepare the lab first")).not.toBeInTheDocument();
  expect(onStart).not.toHaveBeenCalled();
});

it("retains the saved-experiment remedy for an actual graph eligibility problem", async () => {
  const user = userEvent.setup();
  const { onStart } = mount([{ code: "receiver_graph_ineligible", message: "Save a graph with a JSONL staging step feeding the registered peer handoff." }]);
  await user.selectOptions(await screen.findByLabelText(/Saved experiment/), `${demoScenario.id}:1:${receiverFixtureDigest}`);
  expect(await screen.findByRole("link", { name: "Review the experiment in Build" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Save control test" })).toBeDisabled();
  expect(onStart).not.toHaveBeenCalled();
});
