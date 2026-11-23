import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { SavedDefensiveWork } from "../src/components/SavedDefensiveWork";
import { loadSavedWork } from "../src/lib/saved-defensive-work";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: true }));
vi.mock("../src/lib/saved-defensive-work", async importOriginal => ({ ...await importOriginal<typeof import("../src/lib/saved-defensive-work")>(), loadSavedWork: vi.fn() }));

it.each(["handoff", "file", "domain", "cloud"])("does not load or fabricate saved %s work in demo mode", family => {
  const client = new QueryClient();
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/?work=${family}`]}><SavedDefensiveWork /></MemoryRouter></QueryClientProvider>);
  expect(screen.getByText("Saved defensive work is available in the installed workspace.")).toBeVisible();
  expect(loadSavedWork).not.toHaveBeenCalled();
  expect(screen.queryByText("Recorded state")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Refresh/ })).toBeDisabled();
  client.clear();
});
