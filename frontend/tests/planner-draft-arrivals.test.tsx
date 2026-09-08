import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { AIPlannerPage } from "../src/pages/AIPlanner";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { AIGraphDraftResult } from "../src/types";

vi.mock("../src/components/ProviderSetup", () => ({ ProviderSetup: () => null }));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach((client) => client.clear()));
function deferred() {
  let resolve!: (result: AIGraphDraftResult) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<AIGraphDraftResult>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function result(title = "Returned registered draft"): AIGraphDraftResult {
  return { schema_version: "bluefire.ai-graph-draft-result.v1", draft_id: "draft-retained-request", saved: false,
    scenario: { ...structuredClone(demoScenario), title }, rationale: "Reviewed server proposal", assumptions: [],
    audit: { unsaved: true, selected_behavior_ids: [] } };
}
function WorkingGraph() {
  const { scenario } = useProduct();
  return <output aria-label="Working experiment">{scenario.title}</output>;
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } } });
  clients.push(client);
  const catalog = structuredClone(demoCatalog);
  catalog.ai.providers = ["provider-first", "provider-second"].map((provider_id) => ({ provider_id, kind: "deterministic", model: "test-model", credential_reference: null, health: { state: "ready", message: "Fixture readiness" } }));
  client.setQueryData(["catalog"], catalog);
  const view = render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><WorkingGraph/><Routes><Route path="/" element={<AIPlannerPage/>}/><Route path="/builder" element={<p>Builder workspace</p>}/></Routes></MemoryRouter></ProductProvider></QueryClientProvider>);
  fireEvent.change(screen.getByRole("combobox", { name: "Provider adapter" }), { target: { value: "provider-first" } });
  fireEvent.change(screen.getByRole("textbox", { name: "Experiment objective" }), { target: { value: "First objective" } });
  return view;
}
const generate = () => screen.getByRole("button", { name: "Generate registered draft" });
const open = () => screen.queryByRole("button", { name: "Open unsaved draft in Builder" });

it.each(["objective", "provider", "objective-return", "provider-return"])("discards a late success after %s edits without changing the graph or resubmitting", async (change) => {
  const pending = deferred(); const draft = vi.spyOn(api, "aiDraft").mockReturnValue(pending.promise);
  mount(); const original = screen.getByLabelText("Working experiment").textContent;
  fireEvent.click(generate());
  await waitFor(() => expect(draft).toHaveBeenCalledExactlyOnceWith("First objective", "provider-first", 8, 16));
  if (change.startsWith("objective")) {
    const input = screen.getByRole("textbox", { name: "Experiment objective" });
    fireEvent.change(input, { target: { value: "Different objective" } });
    if (change.endsWith("return")) fireEvent.change(input, { target: { value: "First objective" } });
  } else {
    const input = screen.getByRole("combobox", { name: "Provider adapter" });
    fireEvent.change(input, { target: { value: "provider-second" } });
    if (change.endsWith("return")) fireEvent.change(input, { target: { value: "provider-first" } });
  }
  expect(screen.getByRole("button", { name: "Drafting through control plane" })).toBeDisabled();
  await act(async () => pending.resolve(result()));
  await waitFor(() => expect(generate()).toBeEnabled());
  expect(open()).not.toBeInTheDocument();
  expect(screen.queryByText(/returned as an unsaved registered-contract draft/)).not.toBeInTheDocument();
  expect(screen.getByLabelText("Working experiment")).toHaveTextContent(original!);
  expect(draft).toHaveBeenCalledTimes(1);
  draft.mockResolvedValue(result("Current input draft")); fireEvent.click(generate());
  await screen.findByRole("button", { name: "Open unsaved draft in Builder" });
  expect(draft).toHaveBeenCalledTimes(2);
  expect(screen.getByRole("heading", { name: "Current input draft" })).toBeVisible();
});

it("ignores a stale failure and does not revive a settled preview when its provider changes", async () => {
  const pending = deferred(); const draft = vi.spyOn(api, "aiDraft").mockReturnValue(pending.promise);
  mount(); fireEvent.click(generate()); await waitFor(() => expect(draft).toHaveBeenCalledTimes(1));
  fireEvent.change(screen.getByRole("textbox", { name: "Experiment objective" }), { target: { value: "New objective" } });
  await act(async () => pending.reject(new Error("Previous provider refused")));
  await waitFor(() => expect(generate()).toBeEnabled());
  expect(screen.queryByText("Previous provider refused")).not.toBeInTheDocument();
  draft.mockResolvedValue(result()); fireEvent.click(generate());
  await screen.findByRole("button", { name: "Open unsaved draft in Builder" });
  fireEvent.change(screen.getByRole("combobox", { name: "Provider adapter" }), { target: { value: "provider-second" } });
  expect(open()).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole("combobox", { name: "Provider adapter" }), { target: { value: "provider-first" } });
  expect(open()).not.toBeInTheDocument(); expect(draft).toHaveBeenCalledTimes(2);
});

it("applies only an explicitly opened current preview and drops an unmounted arrival", async () => {
  const pending = deferred(); const draft = vi.spyOn(api, "aiDraft").mockReturnValue(pending.promise);
  const view = mount(); fireEvent.click(generate()); await waitFor(() => expect(draft).toHaveBeenCalledTimes(1));
  view.unmount(); await act(async () => pending.resolve(result("Unmounted draft")));
  draft.mockResolvedValue(result("Current registered draft")); mount();
  expect(open()).not.toBeInTheDocument(); fireEvent.click(generate());
  const button = await screen.findByRole("button", { name: "Open unsaved draft in Builder" });
  expect(screen.getByLabelText("Working experiment")).not.toHaveTextContent("Current registered draft");
  fireEvent.click(button);
  expect(screen.getByText("Builder workspace")).toBeVisible();
  expect(screen.getByLabelText("Working experiment")).toHaveTextContent("Current registered draft");
  expect(draft).toHaveBeenCalledTimes(2);
});
