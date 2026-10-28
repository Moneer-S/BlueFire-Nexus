import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { GRAPH_NODE_HEIGHT, GRAPH_NODE_WIDTH } from "../src/lib/graph-view";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider } from "../src/state/ProductContext";
import type { Outcome, Scenario } from "../src/types";
import { builderOptions, focusSuccessPath } from "./helpers/builder-options";

// Same six-step/17-route topology as the public receiver experiment, with registered demo methods; no runtime effects.
const names = ["create_fixture", "transform_fixture", "inspect_fixture_metadata", "stage_records", "authorized_peer_handoff", "cleanup_workspace"];
const behaviors = ["sandbox.fixture.create.v1", "sandbox.program.fixed.v1", "endpoint.discovery.system.v1", "sandbox.collection.stage.v1", "sandbox.network.loopback.v1", "sandbox.cleanup.v1"];
const scenario: Scenario = { ...structuredClone(demoScenario), id: "scenario.receiver-route-review.v1", title: "Public receiver route review", start: names[0]!, layout: undefined,
  steps: names.map((id, index) => ({ id, behavior_id: behaviors[index]!, parameters: {}, inputs: {}, alternates: [] })),
  edges: [...names.slice(0, -1).map((id, index) => ({ from_step: id, outcome: "success" as Outcome, to_step: names[index + 1]! })),
    ...names.slice(1, -1).flatMap((id) => (["partial", "blocked", "failed"] as Outcome[]).map((outcome) => ({ from_step: id, outcome, to_step: names[5]! })))],
};

// Supply only missing layout measurements. The actual React Flow, node/edge renderers,
// handle discovery, selection and deleteElements implementation remain in use.
function measurements() {
  vi.spyOn(globalThis, "ResizeObserver").mockImplementation(function (callback) {
    const observed = new Set<Element>();
    const observer: ResizeObserver = { observe(target) { observed.add(target); queueMicrotask(() => {
      if (!observed.has(target)) return;
      const contentRect = target.getBoundingClientRect();
      const size = { inlineSize: contentRect.width, blockSize: contentRect.height };
      callback([{ target, contentRect, borderBoxSize: [size], contentBoxSize: [size], devicePixelContentBoxSize: [size] }], observer);
    }); }, unobserve(target) { observed.delete(target); }, disconnect() { observed.clear(); } };
    return observer;
  });
  Object.defineProperty(SVGElement.prototype, "getBBox", { configurable: true, value: () => ({ x: 0, y: 0, width: 24, height: 12 }) });
  vi.spyOn(HTMLElement.prototype, "offsetWidth", "get").mockImplementation(function (this: HTMLElement) { return this.classList.contains("react-flow__handle") ? 10 : this.classList.contains("react-flow__node") ? GRAPH_NODE_WIDTH : 1000; });
  vi.spyOn(HTMLElement.prototype, "offsetHeight", "get").mockImplementation(function (this: HTMLElement) { return this.classList.contains("react-flow__handle") ? 10 : this.classList.contains("react-flow__node") ? GRAPH_NODE_HEIGHT : 600; });
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
    const element = this as HTMLElement;
    const handle = element.classList.contains("react-flow__handle"), node = element.classList.contains("react-flow__node");
    const viewport = element.closest(".react-flow__viewport");
    const scale = viewport && (handle || node) ? new window.DOMMatrixReadOnly(getComputedStyle(viewport).transform).m22 : 1;
    const x = handle ? (element.style.left.endsWith("%") ? Number.parseFloat(element.style.left) * GRAPH_NODE_WIDTH / 100 : element.getAttribute("data-handlepos") === "right" ? GRAPH_NODE_WIDTH : 0) * scale : 0;
    const y = handle ? (element.getAttribute("data-handlepos") === "bottom" ? GRAPH_NODE_HEIGHT : element.getAttribute("data-handlepos") === "right" || element.getAttribute("data-handlepos") === "left" ? Number.parseFloat(element.style.top) * GRAPH_NODE_HEIGHT / 100 || GRAPH_NODE_HEIGHT / 2 : 0) * scale : 0;
    const width = (handle ? 10 : node ? GRAPH_NODE_WIDTH : 1000) * scale, height = (handle ? 10 : node ? GRAPH_NODE_HEIGHT : 600) * scale;
    return { x, y, width, height, left: x, top: y, right: x + width, bottom: y + height, toJSON: () => ({}) };
  });
}
afterEach(() => { Reflect.deleteProperty(SVGElement.prototype, "getBBox"); });

function mount(readOnly = false, experiment = scenario) {
  measurements();
  const digest = `sha256:${"a".repeat(64)}`;
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(readOnly ? demoScenario : experiment));
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: experiment.id, version: 1, digest, title: experiment.title, created_at: "2030-01-01", document: experiment } });
  const validate = vi.spyOn(api, "validate").mockResolvedValue({ valid: true, issues: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const path = readOnly ? `/builder?saved_scenario=${experiment.id}&version=1&digest=${digest}` : "/builder";
  return { validate, ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[path]}><ProductProvider><BuilderPage/></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>) };
}
const cached = (): Scenario => JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!);
const routeButtons = () => within(screen.getByRole("list", { name: "Visible routes" })).getAllByRole("button");
async function showFullRouteGraph(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Show route list" }));
}

it("keeps all 17 route meanings keyboard inspectable and unfolds each selected route", async () => {
  const user = userEvent.setup();
  mount(true);
  await showFullRouteGraph(user);
  expect(screen.getByText("6 steps · 17 routes")).toBeInTheDocument();
  const buttons = routeButtons();
  expect(buttons).toHaveLength(17);
  const cleanupPaths: string[] = [];
  await user.click(buttons[0]!);
  for (const [index, edge] of scenario.edges.entries()) {
    if (index) await user.keyboard("{ArrowDown}");
    expect(buttons[index]).toHaveFocus();
    expect(buttons[index]).toHaveAttribute("aria-pressed", "true");
    const rendered = await screen.findByTestId(`rf__edge-route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`);
    await waitFor(() => expect(rendered).toHaveClass("selected"));
    expect(rendered).toHaveAccessibleName(new RegExp(`^Route ${index + 1}:`));
    expect(rendered.querySelector("title")).toHaveTextContent(`Route ${index + 1}:`);
    const path = rendered.querySelector(".react-flow__edge-path")!;
    expect(path).toHaveAttribute("d");
    if (index >= 5) cleanupPaths.push(path.getAttribute("d")!);
  }
  expect(new Set(cleanupPaths).size).toBe(12);
  expect(cached()).toEqual(demoScenario);
});


it("deletes only the selected route after confirmation and Undo restores every route", async () => {
  const user = userEvent.setup();
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  mount();
  await showFullRouteGraph(user);
  await user.click(routeButtons()[6]!);
  const selectedButton = routeButtons()[6]!;
  await user.keyboard("{Delete}");
  const dialog = await screen.findByRole("dialog", { name: "Delete from experiment?" });
  expect(within(dialog).getByText("Route 7: Run reviewed fixture program → Reconcile and clean workspace · When blocked")).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
  expect(cached()).toEqual(scenario);
  await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
  await waitFor(() => expect(selectedButton).toHaveFocus());
  expect(cached()).toEqual(scenario);
  await user.keyboard("{Delete}");
  await user.click(within(await screen.findByRole("dialog", { name: "Delete from experiment?" })).getByRole("button", { name: "Delete" }));
  await waitFor(() => expect(cached().edges).toEqual(scenario.edges.filter((_, index) => index !== 6)));
  expect(cached().steps).toEqual(scenario.steps);
  await waitFor(() => expect(routeButtons().some(button => button === document.activeElement)).toBe(true));
  expect(confirm).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Undo" }));
  await waitFor(() => expect(cached()).toEqual(scenario));
  expect(routeButtons()).toHaveLength(17);
});

it("keeps disclosure explicit and returns focus when the route list is closed", async () => {
  const user = userEvent.setup();
  mount();
  await showFullRouteGraph(user);
  await user.click(routeButtons()[7]!);
  await focusSuccessPath(user);
  expect(routeButtons()).toHaveLength(5);
  expect(screen.getByText(/12 routes hidden/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Delete route" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Close route list" }));
  expect(screen.getByRole("button", { name: "Show route list" })).toHaveFocus();
  await user.keyboard("{Enter}");
  expect(routeButtons()).toHaveLength(5);
  expect(cached()).toEqual(scenario);
});

it("keeps keyboard node deletion on its replacement when the route list is open", async () => {
  const user = userEvent.setup();
  mount();
  await showFullRouteGraph(user);
  await user.click(screen.getByRole("button", { name: "Show node inspector" }));
  expect(screen.getByLabelText("View options", { selector: "summary" }).closest("details")).not.toHaveAttribute("open");
  const node = screen.getByTestId("rf__node-stage_records");
  node.focus();
  await user.keyboard("{Enter}");
  await waitFor(() => expect(node).toHaveClass("selected"));
  expect(routeButtons()).toHaveLength(17);
  await user.keyboard("{Delete}");
  await user.click(within(await screen.findByRole("dialog", { name: "Delete from experiment?" })).getByRole("button", { name: "Delete" }));
  await waitFor(() => expect(screen.queryByTestId("rf__node-stage_records")).not.toBeInTheDocument());
  const replacement = screen.getByTestId("rf__node-create_fixture");
  await waitFor(() => expect(replacement).toHaveFocus());
  expect(screen.getByLabelText("View options", { selector: "summary" }).closest("details")).not.toHaveAttribute("open");
  expect(replacement).toHaveClass("selected");
  expect(screen.getByLabelText(/^Step ID/)).toHaveValue("create_fixture");
  await builderOptions(user);
  expect(screen.getByRole("button", { name: "Delete selected node" })).toBeEnabled();
  expect(routeButtons().every(button => button.getAttribute("aria-pressed") === "false")).toBe(true);
  expect(cached().steps).toEqual(scenario.steps.filter(step => step.id !== "stage_records"));
}, 15000);

it("keeps deleted input-connection focus on the canvas instead of selecting an unrelated route", async () => {
  const user = userEvent.setup();
  mount(false, demoScenario);
  await user.click(await screen.findByRole("button", { name: "Show route list" }));
  await builderOptions(user);
  await user.click(screen.getByRole("checkbox", { name: "Show input connections" }));
  await builderOptions(user, false);
  const edge = screen.getByTestId("rf__edge-artifact-place_fixture-workspace-run_fixture-workspace");
  edge.focus();
  await user.keyboard("{Enter}");
  await waitFor(() => expect(edge).toHaveClass("selected"));
  await user.keyboard("{Delete}");
  await user.click(within(await screen.findByRole("dialog", { name: "Delete from experiment?" })).getByRole("button", { name: "Delete" }));
  await waitFor(() => expect(cached().steps.find(step => step.id === "run_fixture")!.inputs).toEqual({}));
  await waitFor(() => expect(screen.getByLabelText("Scenario graph canvas")).toHaveFocus());
  expect(routeButtons().every(button => button.getAttribute("aria-pressed") === "false")).toBe(true);
  expect(cached().edges).toEqual(demoScenario.edges);
  await user.click(screen.getByRole("button", { name: "Undo" }));
  await waitFor(() => expect(cached()).toEqual(demoScenario));
}, 15000);

it("never labels an unvalidated saved view ready, and shows validation only after its actual response", async () => {
  const user = userEvent.setup();
  const view = mount(true);
  expect(await screen.findByText("Read-only view · not validated here")).toBeInTheDocument();
  expect(screen.queryByText("Ready to review your run")).not.toBeInTheDocument();
  expect(view.validate).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Validate" }));
  expect(await screen.findByText("Experiment validated")).toBeInTheDocument();
  expect(view.validate).toHaveBeenCalledWith(scenario);
  expect(cached()).toEqual(demoScenario);
});


it("opens complete route inspection from the canvas keyboard without stealing its focus", async () => {
  const user = userEvent.setup();
  mount(true);
  await showFullRouteGraph(user);
  await user.click(screen.getByRole("button", { name: "Close route list" }));
  const edge = screen.getByTestId("rf__edge-route-inspect_fixture_metadata-failed-cleanup_workspace-10");
  edge.focus();
  await user.keyboard("{Enter}");
  await waitFor(() => expect(edge).toHaveClass("selected"));
  expect(edge).toHaveFocus();
  expect(routeButtons()[10]).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Delete route" })).toBeDisabled();
  expect(cached()).toEqual(demoScenario);
});


it("keeps saved route inspection read-only and returns between the route list and source details", async () => {
  const user = userEvent.setup();
  const view = mount(true);
  await showFullRouteGraph(user);
  await user.click(routeButtons()[6]!);
  expect(screen.getByRole("button", { name: "Delete route" })).toBeDisabled();
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  await user.keyboard("{Delete}");
  expect(confirm).not.toHaveBeenCalled();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(cached()).toEqual(demoScenario);
  await user.click(screen.getByRole("button", { name: "Inspect source step" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Hide node inspector" })).toHaveFocus());
  expect(view.container.querySelector("fieldset.graph-review-editor")).toBeDisabled();
  expect(screen.queryByRole("list", { name: "Visible routes" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Show route list" }));
  expect(screen.queryByRole("button", { name: "Close step details" })).not.toBeInTheDocument();
  expect(routeButtons()).toHaveLength(17);
});


it.each(["click", "keyboard"])("reopens a retained selected route after closing its list using %s", async (method) => {
  const user = userEvent.setup();
  mount(true);
  await showFullRouteGraph(user);
  await user.click(routeButtons()[6]!);
  await user.click(screen.getByRole("button", { name: "Close route list" }));
  const edge = screen.getByTestId("rf__edge-route-transform_fixture-blocked-cleanup_workspace-6");
  expect(edge).toHaveClass("selected");
  if (method === "click") await user.click(edge);
  else { edge.focus(); await user.keyboard("{Enter}"); expect(edge).toHaveFocus(); }
  expect(routeButtons()[6]).toHaveAttribute("aria-pressed", "true");
  expect(cached()).toEqual(demoScenario);
});

it("names shared-destination conditions once and reveals their complete routes through keyboard inspection", async () => {
  const user = userEvent.setup();
  mount();
  await showFullRouteGraph(user);
  // authorized_peer_handoff continues to cleanup on every outcome (routes 5, 15, 16 and 17).
  const success = await screen.findByTestId("rf__edge-route-authorized_peer_handoff-success-cleanup_workspace-4");
  await waitFor(() => expect(success.querySelector("title")).toHaveTextContent("Route 5: On success. Any outcome"));
  const label = success.querySelector(".react-flow__edge-text");
  if (label) expect(label).toHaveTextContent("Any outcome");
  expect(success).toHaveAccessibleName(/Any outcome/);
  for (const [index, outcome] of (["partial", "blocked", "failed"] as const).entries()) {
    expect(screen.queryByTestId(`rf__edge-route-authorized_peer_handoff-${outcome}-cleanup_workspace-${14 + index}`)).not.toBeInTheDocument();
  }
  // Every route remains listed. Keyboard selection paints its own condition,
  // even though repeated idle geometry is absent from the canvas.
  expect(routeButtons()).toHaveLength(17);
  await user.click(routeButtons()[14]!);
  await user.keyboard("{ArrowDown}");
  expect(routeButtons()[15]).toHaveFocus();
  const selected = await screen.findByTestId("rf__edge-route-authorized_peer_handoff-blocked-cleanup_workspace-15");
  await waitFor(() => expect(selected).toHaveClass("selected"));
  expect(selected).toHaveAccessibleName(/When blocked/);
  // The selected condition speaks for itself; the success route still accounts
  // for its two hidden siblings without repeating the selected condition.
  await waitFor(() => expect(success.querySelector("title")).toHaveTextContent(/^Route 5: On success\. Also partial, failed$/));
  expect(success).toHaveAccessibleName(/Also partial, failed/);
  expect(success.querySelector(".react-flow__edge-text")).toHaveTextContent("Also partial, failed");
  expect(cached()).toEqual(scenario);
});

it("keeps a method qualifier's parentheses so the card title and qualifier restate the full method name", async () => {
  const behavior = demoCatalog.behaviors.find(item => item.id === "sandbox.collection.stage.v1")!;
  const original = behavior.title;
  behavior.title = "Stage selected records (native JSONL)";
  try {
    mount();
    const node = await screen.findByTestId("rf__node-stage_records");
    await waitFor(() => expect(node.querySelector(".node-method")).toHaveTextContent(/^\(native JSONL\)$/));
    const title = node.querySelector(".node-title > strong")!;
    expect(title).toHaveTextContent(/^Stage selected records$/);
    expect(title).toHaveAttribute("title", "Stage selected records (native JSONL)");
  } finally {
    behavior.title = original;
  }
});
