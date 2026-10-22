import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ReceiverTestSetup } from "../src/components/ReceiverTestSetup";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
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
