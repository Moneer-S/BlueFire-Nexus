import * as Tooltip from "@radix-ui/react-tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider } from "../src/state/ProductContext";
import type { Outcome, Scenario } from "../src/types";

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
  vi.spyOn(HTMLElement.prototype, "offsetWidth", "get").mockImplementation(function (this: HTMLElement) { return this.classList.contains("react-flow__handle") ? 10 : this.classList.contains("react-flow__node") ? 252 : 1000; });
  vi.spyOn(HTMLElement.prototype, "offsetHeight", "get").mockImplementation(function (this: HTMLElement) { return this.classList.contains("react-flow__handle") ? 10 : this.classList.contains("react-flow__node") ? 160 : 600; });
  vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
    const element = this as HTMLElement;
    const handle = element.classList.contains("react-flow__handle"), node = element.classList.contains("react-flow__node");
    const viewport = element.closest(".react-flow__viewport");
    const scale = viewport && (handle || node) ? new window.DOMMatrixReadOnly(getComputedStyle(viewport).transform).m22 : 1;
    const x = handle ? (element.style.left.endsWith("%") ? Number.parseFloat(element.style.left) * 2.52 : 126) * scale : 0;
    const y = handle && element.getAttribute("data-handlepos") === "bottom" ? 160 * scale : 0;
    const width = (handle ? 10 : node ? 252 : 1000) * scale, height = (handle ? 10 : node ? 160 : 600) * scale;
    return { x, y, width, height, left: x, top: y, right: x + width, bottom: y + height, toJSON: () => ({}) };
  });
}
afterEach(() => { Reflect.deleteProperty(SVGElement.prototype, "getBBox"); });

function mount(readOnly = false) {
  measurements();
  const digest = `sha256:${"a".repeat(64)}`;
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(readOnly ? demoScenario : scenario));
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue({ schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: scenario.id, version: 1, digest, title: scenario.title, created_at: "2030-01-01", document: scenario } });
  const validate = vi.spyOn(api, "validate").mockResolvedValue({ valid: true, issues: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const path = readOnly ? `/builder?saved_scenario=${scenario.id}&version=1&digest=${digest}` : "/builder";
  return { validate, ...render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter initialEntries={[path]}><ProductProvider><BuilderPage/></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>) };
}
const cached = (): Scenario => JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!);
const routeButtons = () => within(screen.getByRole("list", { name: "Visible routes" })).getAllByRole("button");

it("renders all 17 separate routes with compact source labels and complete keyboard inspection", async () => {
  const user = userEvent.setup();
  const view = mount(true);
  await user.click(await screen.findByRole("button", { name: "Show all branches" }));
  expect(routeButtons()).toHaveLength(17);
  await waitFor(() => expect(view.container.querySelectorAll(".react-flow__edge-path")).toHaveLength(17));
  const labels = Array.from(view.container.querySelectorAll(".react-flow__edge-text")).map((label) => label.textContent);
  expect(new Set(labels)).toEqual(new Set(Array.from({ length: 17 }, (_, index) => `R${index + 1}`)));
  const cleanupPaths = scenario.edges.slice(5).map((edge, index) => screen.getByTestId(`rf__edge-route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index + 5}`).querySelector(".react-flow__edge-path")!.getAttribute("d"));
  expect(new Set(cleanupPaths).size).toBe(12);
  await user.click(routeButtons()[5]!);
  await user.keyboard("{ArrowDown}");
  expect(routeButtons()[6]).toHaveFocus();
  expect(routeButtons()[6]).toHaveAttribute("aria-pressed", "true");
  const selected = screen.getByTestId("rf__edge-route-transform_fixture-blocked-cleanup_workspace-6");
  await waitFor(() => expect(selected).toHaveClass("selected"));
  expect(selected).toHaveAccessibleName(/When blocked/);
  expect(cached()).toEqual(demoScenario);
});

it("deletes only the selected route after confirmation and Undo restores every route", async () => {
  const user = userEvent.setup();
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  mount();
  await user.click(await screen.findByRole("button", { name: "Show all branches" }));
  await user.click(routeButtons()[6]!);
  await user.keyboard("{Delete}");
  await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
  expect(cached()).toEqual(scenario);
  confirm.mockReturnValue(true);
  await user.keyboard("{Delete}");
  await waitFor(() => expect(cached().edges).toEqual(scenario.edges.filter((_, index) => index !== 6)));
  expect(cached().steps).toEqual(scenario.steps);
  await user.click(screen.getByRole("button", { name: "Undo" }));
  await waitFor(() => expect(cached()).toEqual(scenario));
  expect(routeButtons()).toHaveLength(17);
});

it("keeps disclosure explicit and returns focus when the route list is closed", async () => {
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole("button", { name: "Show all branches" }));
  await user.click(routeButtons()[7]!);
  await user.click(screen.getByRole("button", { name: "Focus on success path" }));
  expect(routeButtons()).toHaveLength(5);
  expect(screen.getByText(/12 branches hidden/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Delete route" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Close route list" }));
  expect(screen.getByRole("button", { name: "Show route list" })).toHaveFocus();
  await user.keyboard("{Enter}");
  expect(routeButtons()).toHaveLength(5);
  expect(cached()).toEqual(scenario);
});

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
  await user.click(await screen.findByRole("button", { name: "Show all branches" }));
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
  await user.click(await screen.findByRole("button", { name: "Show all branches" }));
  await user.click(routeButtons()[6]!);
  expect(screen.getByRole("button", { name: "Delete route" })).toBeDisabled();
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  await user.keyboard("{Delete}");
  expect(confirm).not.toHaveBeenCalled();
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
  await user.click(await screen.findByRole("button", { name: "Show all branches" }));
  await user.click(routeButtons()[6]!);
  await user.click(screen.getByRole("button", { name: "Close route list" }));
  const edge = screen.getByTestId("rf__edge-route-transform_fixture-blocked-cleanup_workspace-6");
  expect(edge).toHaveClass("selected");
  if (method === "click") await user.click(edge);
  else { edge.focus(); await user.keyboard("{Enter}"); expect(edge).toHaveFocus(); }
  expect(routeButtons()[6]).toHaveAttribute("aria-pressed", "true");
  expect(cached()).toEqual(demoScenario);
});
