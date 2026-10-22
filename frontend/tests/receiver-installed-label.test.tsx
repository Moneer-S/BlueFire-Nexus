import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ReceiverTestSetup } from "../src/components/ReceiverTestSetup";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { receiverContextRequestAllowed, receiverContextRequestIsFinal } from "./installed/receiver-guards.mjs";
import { ProductProvider } from "../src/state/ProductContext";

it("exposes the saved experiment field name with its wrapped hint for installed browser selection", async () => {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({
    schema_version: "bluefire.scenario-version-list.v1",
    scenarios: [{
      scenario_id: demoScenario.id,
      title: demoScenario.title,
      version: 1,
      digest: `sha256:${"a".repeat(64)}`,
      created_at: "2026-10-02T12:00:00Z",
      document: demoScenario,
    }],
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><ReceiverTestSetup disabled={false} onStart={vi.fn()} /></MemoryRouter></ProductProvider></QueryClientProvider>);

  const field = await screen.findByLabelText("Saved experiment", { exact: false });
  expect(field).toBeInTheDocument();
  expect(() => screen.getByLabelText("Saved experiment", { exact: true })).toThrow();
});

it("keeps each real retained-redaction UI context request within the finite driver allowance", async () => {
  const catalog = structuredClone(demoCatalog);
  const deepLabProfile = {
    ...catalog.runner_profiles.find((item) => item.id === "sandbox-execute.v1")!,
    id: "sandbox-endpoint-deep-lab.v1",
    scope: ["sandbox.workspace", "network.loopback"],
  };
  catalog.runner_profiles.push(deepLabProfile);
  const digest = `sha256:${"a".repeat(64)}`;
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({
    schema_version: "bluefire.scenario-version-list.v1",
    scenarios: [{ scenario_id: demoScenario.id, title: demoScenario.title, version: 1, digest, created_at: "2026-10-02T12:00:00Z", document: demoScenario }],
  });
  const requests: unknown[] = [];
  vi.spyOn(api, "receiverContext").mockImplementation(async (request) => {
    requests.push(structuredClone(request));
    throw new Error("Context service unavailable in this unit test");
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><ReceiverTestSetup disabled={false} onStart={vi.fn()} /></MemoryRouter></ProductProvider></QueryClientProvider>);

  fireEvent.click(await screen.findByRole("radio", { name: /Retain redaction and verify legitimate use/ }));
  fireEvent.change(await screen.findByLabelText("Saved experiment", { exact: false }), {
    target: { value: `${demoScenario.id}:1:${digest}` },
  });
  await waitFor(() => expect(requests.length).toBeGreaterThanOrEqual(1));
  const executeMode = screen.getByRole("radio", { name: /Execute/ });
  fireEvent.click(executeMode);
  await waitFor(() => expect(requests.length).toBeGreaterThanOrEqual(2));
  const profile = screen.getByLabelText("Environment profile", { exact: true });
  fireEvent.change(profile, { target: { value: "sandbox-endpoint-deep-lab.v1" } });
  await waitFor(() => expect(requests.length).toBeGreaterThanOrEqual(3));
  fireEvent.click(screen.getByRole("checkbox", { name: "Connections to the local lab receiver" }));
  await waitFor(() => expect(requests.length).toBeGreaterThanOrEqual(4));

  const expectedSelection = { kind: "saved_scenario", scenario_id: demoScenario.id, version: 1, digest };
  const expected = {
    selection: expectedSelection,
    workflow: "retained_redaction",
    sourceControl: null,
    profileIdsByMode: { simulate: ["sandbox-simulate.v1"], execute: ["sandbox-execute.v1", "sandbox-endpoint-deep-lab.v1"] },
    scopeRefs: ["sandbox.workspace", "network.loopback"],
    collectors: ["collector.filesystem.sandbox.v1"],
    finalRunIntent: {
      mode: "execute",
      autonomy: "off",
      ai_provider_id: null,
      runner_profile_id: "sandbox-endpoint-deep-lab.v1",
      target_scope: { scope_refs: ["sandbox.workspace", "network.loopback"] },
      collectors: ["collector.filesystem.sandbox.v1"],
    },
  };
  expect(requests.length).toBeGreaterThanOrEqual(4);
  for (const request of requests) expect(receiverContextRequestAllowed(request, expected)).toBe(true);
  expect(requests.some((request) => receiverContextRequestIsFinal(request, expected))).toBe(true);
  expect(requests.at(-1)).toEqual({ selection: expectedSelection, workflow: "retained_redaction", run_intent: expected.finalRunIntent });
  client.clear();
});
