import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ErrorState } from "../src/components/Primitives";
import { api, ApiError } from "../src/lib/api";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { GettingStartedPage } from "../src/pages/GettingStarted";

afterEach(() => vi.restoreAllMocks());

function start() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><GettingStartedPage /></MemoryRouter></QueryClientProvider>);
}

it.each(["runs", "scenarios"] as const)("keeps a failed %s request unavailable and recovers without presenting an empty workspace", async (source) => {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  const scenarios = vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [demoScenario] });
  const runs = vi.spyOn(api, "runs").mockResolvedValue({ runs: demoRuns, unavailable_run_count: 0 });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "bluefire.detection-lab-health.v1", ready: false, persistence_ready: true, candidate_resources: 0, invalid_candidate_resources: 0, languages: {}, limits: { source_bytes: 65536, fixture_bytes: 65536, fixtures_per_action: 128, evidence_per_action: 128, notes_per_action: 32 } });
  const failure = new ApiError("The list could not be read.", "storage_unavailable", undefined, 503);
  if (source === "runs") runs.mockRejectedValueOnce(failure);
  else scenarios.mockRejectedValueOnce(failure);
  start();
  expect(await screen.findByText(source === "runs" ? "Run history could not be loaded" : "Experiments could not be loaded")).toBeVisible();
  expect(screen.queryByText("From a question to a result")).not.toBeInTheDocument();
  expect(screen.queryByText("Empty")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(await screen.findByRole("heading", { name: "Start an experiment" })).toBeVisible();
  expect(screen.getByText("Continue your work")).toBeVisible();
  expect(document.querySelector("a button, button a")).toBeNull();
});

it.each([
  [400, "invalid_input", "Check the request"],
  [403, "scope_refused", "Access not permitted"],
  [404, "run_not_found", "Item not found"],
  [409, "context_changed", "This request needs a fresh review"],
  [401, "browser_session_unavailable", "Reconnect to the workspace"],
] as const)("shows the actual error category for HTTP %i without claiming the service is disconnected", (status, code, title) => {
  render(<ErrorState error={new ApiError("The request was refused.", code, undefined, status)} />);
  expect(screen.getByText(title)).toBeVisible();
  expect(screen.queryByText("Local service unavailable")).not.toBeInTheDocument();
  expect(screen.getByText("The request was refused.")).toBeVisible();
  expect(screen.getByText("Technical details")).toBeVisible();
});

it("does not present unreadable run records as a first-time empty workspace", async () => {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [demoScenario] });
  vi.spyOn(api, "runs").mockResolvedValue({ runs: [], unavailable_run_count: 2 });
  vi.spyOn(api, "detectionHealth").mockImplementation(() => new Promise(() => {}));
  start();
  expect(await screen.findByText("Some run history is unavailable")).toBeVisible();
  expect(screen.getByText("Continue your work")).toBeVisible();
  expect(screen.queryByText("From a question to a result")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Run history" })).toHaveAttribute("href", "/runs");
  await userEvent.click(screen.getByText("Workspace availability"));
  expect(screen.getByText("Checking installed tools.")).toBeVisible();
});

it("keeps error details inspectable and runs only the supplied retry", async () => {
  const retry = vi.fn();
  render(<ErrorState error={new ApiError("Connection refused.", "service_unavailable")} retry={retry} />);
  expect(screen.getByText("Local service unavailable")).toBeVisible();
  expect(screen.getByText("service_unavailable")).not.toBeVisible();
  await userEvent.click(screen.getByText("Technical details"));
  expect(screen.getByText("service_unavailable")).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(retry).toHaveBeenCalledOnce();
});
