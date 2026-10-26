import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { defaultGraphView, writeWorkingGraphView } from "../src/lib/graph-view-retention";
import { BuilderPage } from "../src/pages/Builder";
import { ProductProvider } from "../src/state/ProductContext";
import { AssistanceProvider } from "../src/state/AssistanceContext";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";

it.each([true, false])("restores the %s inspector preference after temporary Assistant details without changing saved work", async (inspector) => {
  const user = userEvent.setup();
  const step = demoScenario.steps[0]!;
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
  localStorage.setItem("bluefire.local.scenario-saved.v1", JSON.stringify(demoScenario));
  writeWorkingGraphView(demoScenario, { ...defaultGraphView(demoScenario),
    selected: { id: step.id, behavior: step.behavior_id }, inspector });
  const viewKey = `bluefire.working-graph-view.v2:${demoScenario.id}`;
  const savedView = localStorage.getItem(viewKey);
  const savedGraph = localStorage.getItem("bluefire.local.scenario.v1");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  vi.spyOn(api, "assistanceGraphEditContext").mockImplementation(async selection => ({
    schema_version: "bluefire.assistance-context.v1", context_digest: `sha256:${"a".repeat(64)}`,
    selected: selection, capabilities: [], limitations: ["No execution"],
  }));
  const submit = vi.spyOn(api, "submitAssistance");
  const { container } = render(<QueryClientProvider client={client}><Tooltip.Provider><MemoryRouter><ProductProvider><AssistanceProvider><BuilderPage/><ExperimentAssistant providers={[]}/></AssistanceProvider></ProductProvider></MemoryRouter></Tooltip.Provider></QueryClientProvider>);
  const panel = container.querySelector(".inspector-panel")!;
  if (inspector) expect(panel).toBeVisible(); else expect(panel).not.toBeVisible();
  const openAssistant = screen.getByText("Plan with Assistant", { selector: "button" });
  await user.click(openAssistant);
  const dock = screen.getByRole("complementary", { name: "BlueFire Assistant" });
  await waitFor(() => expect(dock).toHaveFocus());
  expect(panel).not.toBeVisible();
  expect(localStorage.getItem(viewKey)).toBe(savedView);
  const showDetails = screen.getByText("Step details", { selector: "button" });
  showDetails.focus();
  await user.keyboard("{Enter}");
  expect(panel).toBeVisible();
  await waitFor(() => expect(screen.getByLabelText("Hide node inspector", { selector: "button" })).toHaveFocus());
  expect(localStorage.getItem(viewKey)).toBe(savedView);
  await user.click(screen.getByLabelText("Hide node inspector", { selector: "button" }));
  expect(panel).not.toBeVisible();
  const assistant = within(dock);
  await user.click(assistant.getByRole("button", { name: "Close assistant" }));
  if (inspector) expect(panel).toBeVisible(); else expect(panel).not.toBeVisible();
  expect(localStorage.getItem(viewKey)).toBe(savedView);
  expect(localStorage.getItem("bluefire.local.scenario.v1")).toBe(savedGraph);
  expect(submit).not.toHaveBeenCalled();
});
