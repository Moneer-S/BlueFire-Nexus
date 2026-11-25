import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { AppShell } from "../src/components/AppShell";
import { OverviewPage } from "../src/pages/Overview";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario } from "../src/types";

// A service whose catalog does not register one behavior of the app's seeded
// example, so the app chooses a plan from the catalog's own list instead.
const MISSING = "sandbox.program.fixed.v1";
const CHOSEN: Scenario = {
  ...structuredClone(demoScenario),
  id: "catalog.collect.v1",
  title: "Collect samples with a local fallback",
  steps: demoScenario.steps.map((step) => (step.behavior_id === MISSING ? { ...step, behavior_id: "sandbox.fixture.create.v1" } : step)),
};

/** What a visitor does in Build, in one click: changes the plan. */
function EditThePlan() {
  const { scenario, setScenario } = useProduct();
  return <button type="button" onClick={() => setScenario({ ...scenario, title: "My own plan" })}>Edit the plan</button>;
}

/** The app as it starts: its shell around the Overview. Each call is a fresh load of the page in the same browser. */
function load() {
  // The shell scrolls to the top on every page, which jsdom does not do.
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  vi.spyOn(api, "catalog").mockResolvedValue({ ...structuredClone(demoCatalog), behaviors: demoCatalog.behaviors.filter((behavior) => behavior.id !== MISSING) });
  vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [structuredClone(CHOSEN)] });
  vi.spyOn(api, "runs").mockResolvedValue({ runs: [], unavailable_run_count: 0 });
  vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [], unreadable_count: 0, omitted_count: 0 });
  vi.spyOn(api, "recordingDeltas").mockResolvedValue({ deltas: [], unreadable_count: 0, omitted_count: 0 });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/"]}>
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<><OverviewPage /><EditThePlan /></>} />
      </Route>
    </Routes>
  </MemoryRouter></ProductProvider></QueryClientProvider>);
}

/** The Overview's card of the plan in Build, once it names the plan the app chose. */
async function planCard(title: string) {
  // The shell, the Overview and their answers take a while on a busy machine.
  const heading = await screen.findByRole("heading", { level: 3, name: title }, { timeout: 8_000 });
  const card = heading.closest("section");
  if (!card) throw new Error("The plan's card is not a section.");
  return card;
}

describe("the plan in Build on the Overview", { timeout: 40_000 }, () => {
  it("calls a plan the app chose an example, also after a reload, until the visitor changes it", async () => {
    const first = load();
    const chosen = await planCard(CHOSEN.title);
    expect(within(chosen).getByRole("heading", { level: 2 })).toHaveTextContent("Example plan");
    expect(chosen).toHaveTextContent("Built-in example");
    expect(chosen).toHaveTextContent("A starting point for your own objective");
    expect(chosen).not.toHaveTextContent("Working draft");
    expect(chosen).not.toHaveTextContent("Your current plan in Build");
    first.unmount();

    // A reload: the app chooses the same plan again, and it is still an example.
    const second = load();
    const again = await planCard(CHOSEN.title);
    expect(within(again).getByRole("heading", { level: 2 })).toHaveTextContent("Example plan");
    expect(again).toHaveTextContent("Built-in example");

    // The visitor changes it: it is theirs now, and stays theirs after a reload.
    await userEvent.setup().click(screen.getByRole("button", { name: "Edit the plan" }));
    const edited = await planCard("My own plan");
    expect(within(edited).getByRole("heading", { level: 2 })).toHaveTextContent("Working draft");
    expect(edited).toHaveTextContent("Your current plan in Build");
    second.unmount();

    load();
    const kept = await planCard("My own plan");
    expect(within(kept).getByRole("heading", { level: 2 })).toHaveTextContent("Working draft");
    expect(kept).not.toHaveTextContent("Built-in example");
  });
});
