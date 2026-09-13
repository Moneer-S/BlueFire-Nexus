import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoScenario } from "../src/lib/demo";
import { AIPlannerPage } from "../src/pages/AIPlanner";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import { AssistanceProvider, useAssistancePanel } from "../src/state/AssistanceContext";
import { readAssistanceReceipt, storeAssistanceReceipt, type AssistanceRequest } from "../src/lib/assistance";

function Workspace() {
  const { scenario, dirty } = useProduct();
  const assistant = useAssistancePanel();
  return <><h1>Builder workspace</h1><output aria-label="Working experiment">{JSON.stringify(scenario)}</output><output aria-label="Unsaved changes">{String(dirty)}</output><output aria-label="Assistant open">{String(assistant?.open)}</output></>;
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProductProvider><AssistanceProvider><MemoryRouter initialEntries={["/ai-planner"]}><Routes><Route path="/ai-planner" element={<AIPlannerPage/>}/><Route path="/builder" element={<Workspace/>}/></Routes></MemoryRouter></AssistanceProvider></ProductProvider></QueryClientProvider>);
}
it("redirects ordinary Planner drafting into Assistant without replacing unsaved work or starting a model call", async () => {
  const draft = { ...structuredClone(demoScenario), title: "Unsaved operator changes" };
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(draft));
  const legacy = vi.spyOn(api, "aiDraft");
  const shared = vi.spyOn(api, "submitAssistance");
  mount();
  await screen.findByRole("heading", { name: "Builder workspace" });
  expect(JSON.parse(screen.getByLabelText("Working experiment").textContent!)).toEqual(draft);
  expect(screen.getByLabelText("Unsaved changes")).toHaveTextContent("true");
  expect(screen.getByLabelText("Assistant open")).toHaveTextContent("true");
  expect(legacy).not.toHaveBeenCalled(); expect(shared).not.toHaveBeenCalled();
});
it("preserves an uncertain submitted request and its draft when an old Planner link is reopened", async () => {
  const receipt: AssistanceRequest = { submission_id: "12345678-9abc-4def-8123-456789abcdef", context_digest: `sha256:${"a".repeat(64)}`, selection: { kind: "graph", base_scenario: null }, message: "Create a separate experiment", autonomy: "assist", provider_id: "review-provider" };
  storeAssistanceReceipt(receipt);
  sessionStorage.setItem("bluefire.assistance.draft.v1", "Retained follow-up request");
  const submit = vi.spyOn(api, "submitAssistance");
  const legacy = vi.spyOn(api, "aiDraft");
  mount(); await screen.findByRole("heading", { name: "Builder workspace" });
  expect(readAssistanceReceipt()).toEqual(receipt);
  expect(sessionStorage.getItem("bluefire.assistance.draft.v1")).toBe("Retained follow-up request");
  expect(submit).not.toHaveBeenCalled(); expect(legacy).not.toHaveBeenCalled();
});
