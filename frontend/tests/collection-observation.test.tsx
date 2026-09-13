import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { collectionObservationSteps, collectionSemanticsCollector } from "../src/lib/collection-observation";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario } from "../src/types";

const scenario: Scenario = { ...structuredClone(demoScenario), id: "scenario.endpoint.lab-collection-methods.v1", steps: [{ id: "stage_collection", behavior_id: "sandbox.collection.records.v1", parameters: { stage_variant: "primary" }, inputs: {}, alternates: ["sandbox.collection.archive.v1"] }], start: "stage_collection", edges: [] };
function json(value: unknown) { return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } }); }
function ChooseScenario({ method = "sandbox.collection.records.v1" }: { method?: string }) {
  const { setScenario } = useProduct();
  return <><button onClick={() => setScenario({ ...scenario, steps: [{ ...scenario.steps[0]!, behavior_id: method }] })}>Choose collection experiment</button><button onClick={() => setScenario({ ...scenario, steps: [{ ...scenario.steps[0]!, behavior_id: "package.reviewed-collection.v1" }] })}>Choose package collection</button></>;
}
afterEach(() => { vi.unstubAllGlobals(); localStorage.clear(); });

it.each([
  ["sandbox.collection.records.v1", "jsonl"],
  ["sandbox.collection.atomic-gzip.v1", "jsonl.gz"],
])("selects and visibly binds %s collection contents through the ordinary Execute preflight request", async (method, extension) => {
  const requests: Record<string, unknown>[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://localhost").pathname;
    if (path.endsWith("/catalog")) return json(demoCatalog);
    if (path.endsWith("/scenarios")) return json({ scenarios: [] });
    if (path.endsWith("/runs")) return json({ runs: [] });
    if (path.endsWith("/jobs")) return json({ jobs: [] });
    if (path.endsWith("/runner")) return json({ state: "not_enrolled", readiness: "unavailable" });
    if (path.endsWith("/runs/preflight")) { requests.push(JSON.parse(String(init?.body))); return json({ status: "refused", ready: false, problems: ["Test preflight stops before approval"] }); }
    throw new Error(`Unexpected request: ${path}`);
  }));
  const user = userEvent.setup();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/runs?prepare=1"]}><ChooseScenario method={method}/><RunsPage/></MemoryRouter></ProductProvider></QueryClientProvider>);
  await screen.findByRole("radio", { name: /^Simulate/ });
  await user.click(screen.getByRole("button", { name: "Choose collection experiment" }));
  await user.click(screen.getByRole("radio", { name: /^Execute/ }));
  const collector = screen.getByRole("checkbox", { name: /Collection contents/ });
  expect(collector).toBeChecked();
  expect(screen.getByText(`staged/collection/bundle.${extension}`)).toBeVisible();
  const preflight = screen.getByRole("button", { name: /^Run preflight$/ });
  await waitFor(() => expect(preflight).toBeEnabled());
  await user.click(preflight);
  await waitFor(() => expect(requests).toHaveLength(1));
  expect(requests[0]?.collectors).toEqual(["collector.filesystem.sandbox.v1", collectionSemanticsCollector]);
  expect(requests[0]?.approved).toBeUndefined();
  await user.click(collector);
  expect(collector).not.toBeChecked();
  await user.click(preflight);
  await waitFor(() => expect(requests).toHaveLength(2));
  expect(requests[1]?.collectors).toEqual(["collector.filesystem.sandbox.v1"]);
  await user.click(screen.getByRole("button", { name: "Choose package collection" }));
  expect(screen.getByRole("region", { name: "Required observations" })).toBeVisible();
  expect(collector).toBeVisible();
  expect(collector).toBeEnabled();
  await user.click(collector);
  await user.click(preflight);
  await waitFor(() => expect(requests).toHaveLength(3));
  expect(requests[2]?.collectors).toEqual(["collector.filesystem.sandbox.v1", collectionSemanticsCollector]);
});

it("shows the heldout archive path and leaves earlier behaviors outside semantic collection", () => {
  expect(collectionObservationSteps({ ...scenario, steps: [{ ...scenario.steps[0]!, behavior_id: "sandbox.collection.archive.v1", parameters: { stage_variant: "heldout" } }] })).toEqual([{ stepId: "stage_collection", path: "staged/variation/bundle.tar" }]);
  expect(collectionObservationSteps({ ...scenario, steps: [{ ...scenario.steps[0]!, behavior_id: "sandbox.collection.atomic-gzip.v1", parameters: { stage_variant: "heldout" } }] })).toEqual([{ stepId: "stage_collection", path: "staged/variation/bundle.jsonl.gz" }]);
  expect(collectionObservationSteps({ ...scenario, steps: [{ ...scenario.steps[0]!, behavior_id: "sandbox.collection.stage.v1" }] })).toEqual([]);
});
