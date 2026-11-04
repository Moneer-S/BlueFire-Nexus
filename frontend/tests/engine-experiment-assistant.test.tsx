import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api, request } from "../src/lib/api";
import type { EngineExperimentAssistanceSelection } from "../src/lib/engine-assistance";
import { AssistanceProvider, usePublishEngineExperimentSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";

vi.mock("../src/lib/api", async importOriginal => ({ ...await importOriginal<typeof import("../src/lib/api")>(), DEMO_MODE: false, request: vi.fn() }));

const experimentId = `experiment-${"a".repeat(32)}`;
const attemptId = `engine-attempt-${"b".repeat(32)}`;
const selection: EngineExperimentAssistanceSelection = {
  kind: "engine_experiment",
  experiment_id: experimentId,
  workspace_digest: `sha256:${"c".repeat(64)}`,
  attempt_id: attemptId,
  check_id: null,
};

function Selection() {
  usePublishEngineExperimentSelection(selection, "Bounded tenant-record defense");
  return null;
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  sessionStorage.setItem("bluefire.assistance.open.v1", "true");
  vi.mocked(request).mockReset();
});

it("captures the exact workspace for reopening without calling a generic model context", async () => {
  const genericContext = vi.spyOn(api, "assistanceContext");
  const submit = vi.spyOn(api, "submitAssistance");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  const tree = (show: boolean) => <QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider>{show ? <Selection /> : null}<ExperimentAssistant providers={[]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>;
  const view = render(tree(true));

  expect(await screen.findByText("Bounded tenant-record defense")).toBeVisible();
  expect(screen.getByText("Context captured")).toBeVisible();
  expect(screen.getByText(/Assistant requests remain unavailable until the local service/)).toBeVisible();
  expect(screen.queryByRole("textbox", { name: "What would you like to do?" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start work" })).not.toBeInTheDocument();
  expect(request).not.toHaveBeenCalled();
  expect(genericContext).not.toHaveBeenCalled();
  expect(submit).not.toHaveBeenCalled();
  await waitFor(() => expect(sessionStorage.getItem("bluefire.assistance.selection.v1")).toContain(selection.workspace_digest));

  view.rerender(tree(false));
  const reopen = await screen.findByRole("link", { name: "Reopen source" });
  expect(reopen).toHaveAttribute("href", `/composition?engine_experiment=${experimentId}&attempt=${attemptId}`);
  expect(request).not.toHaveBeenCalled();
  expect(genericContext).not.toHaveBeenCalled();
  expect(submit).not.toHaveBeenCalled();
});
