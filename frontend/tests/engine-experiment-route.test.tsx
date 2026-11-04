import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { parseEngineExperimentRoute, CompositionRoute } from "../src/pages/EngineExperimentRoute";
import type { EngineExperiment } from "../src/lib/engine-experiment";
import { engineExperimentApi } from "../src/lib/engine-experiment-api";
import { AssistanceProvider, useAssistanceSelection } from "../src/state/AssistanceContext";

vi.mock("../src/pages/Composition", () => ({ CompositionPage: () => <h1>Ordinary composition workspace</h1> }));
vi.mock("../src/components/EngineExperimentWorkspace", () => ({
  EngineExperimentWorkspace: ({ experiment, selectedAttemptId, selectedCheckId, onSelectAttempt, onSelectCheck }: any) => <section aria-label="Engine experiment witness">
    <h1>{experiment.objective.title}</h1>
    <output aria-label="Selected route item">{selectedAttemptId ?? selectedCheckId ?? "none"}</output>
    <button type="button" onClick={() => onSelectAttempt(experiment.projection.attempts[0].attempt_id)}>Select baseline</button>
    <button type="button" onClick={() => onSelectCheck(experiment.projection.checks[0].check_id)}>Select retest</button>
  </section>,
}));

const workspace = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/engine-experiment-api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/engine-experiment-api")>();
  return { ...actual, engineExperimentApi: { ...actual.engineExperimentApi, workspace } };
});

const experimentId = `experiment-${"a".repeat(32)}`;
const attemptId = `engine-attempt-${"b".repeat(32)}`;
const checkId = `controller-check-${"c".repeat(32)}`;
const workspaceDigest = `sha256:${"d".repeat(64)}`;
const raw = {
  experiment_id: experimentId,
  workspace_digest: workspaceDigest,
  objective: { title: "Controlled tenant-record defense fixture" },
  projection: {
    attempts: [{ attempt_id: attemptId, state: "completed" }],
    checks: [{ check_id: checkId, state: "completed" }],
  },
} as unknown as EngineExperiment;

function Witness() {
  const location = useLocation();
  const navigate = useNavigate();
  const selection = useAssistanceSelection();
  return <><output aria-label="Current location">{`${location.pathname}${location.search}`}</output><output aria-label="Assistant selection">{selection ? JSON.stringify(selection) : "none"}</output><button type="button" onClick={() => navigate(-1)}>Browser back</button></>;
}

function mount(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><AssistanceProvider><Routes><Route path="/composition" element={<CompositionRoute />} /></Routes><Witness /></AssistanceProvider></MemoryRouter></QueryClientProvider>);
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.mocked(engineExperimentApi.workspace).mockReset().mockImplementation(async (_experiment, selection) => {
    if (selection?.kind === "controller_check") throw new Error("Selected workspace context changed.");
    return raw;
  });
});

it.each([
  [`?engine_experiment=${experimentId}&engine_experiment=${experimentId}`, "duplicate experiment"],
  [`?engine_experiment=${experimentId}&attempt=${attemptId}&check=${checkId}`, "ambiguous selection"],
  [`?engine_experiment=${experimentId}&attempt=${attemptId}&attempt=${attemptId}`, "duplicate attempt"],
  [`?engine_experiment=${experimentId}&check=${checkId}&check=${checkId}`, "duplicate check"],
  [`?engine_experiment=${experimentId}&attempt=`, "empty selection"],
  [`?engine_experiment=${experimentId}&unknown=1`, "unknown field"],
  [`?engine_experiment=${experimentId}&attempt=engine%2Dattempt-${"b".repeat(32)}`, "noncanonical encoding"],
  ["?engine_experiment=invalid", "malformed experiment"],
])("rejects a %s route", (search) => {
  expect(() => parseEngineExperimentRoute(search)).toThrow(/invalid/i);
});

it("preserves ordinary Composition when no engine experiment is present", () => {
  expect(parseEngineExperimentRoute(`?attempt=${attemptId}`)).toBeNull();
  mount("/composition?view=map");
  expect(screen.getByRole("heading", { name: "Ordinary composition workspace" })).toBeVisible();
  expect(engineExperimentApi.workspace).not.toHaveBeenCalled();
});

it("loads the strict workspace, captures Assistant context, and preserves selection history", async () => {
  const user = userEvent.setup();
  mount(`/composition?engine_experiment=${experimentId}`);
  expect(await screen.findByRole("heading", { name: raw.objective.title })).toBeVisible();
  expect(engineExperimentApi.workspace).toHaveBeenCalledWith(experimentId, null);
  expect(screen.getByLabelText("Assistant selection")).toHaveTextContent(workspaceDigest);
  await waitFor(() => expect(localStorage.getItem("bluefire.local.active-defensive-work.v1")).toContain('"family":"engine"'));

  await user.click(screen.getByRole("button", { name: "Select baseline" }));
  await waitFor(() => expect(screen.getByLabelText("Current location")).toHaveTextContent(`attempt=${attemptId}`));
  await waitFor(() => expect(engineExperimentApi.workspace).toHaveBeenCalledWith(experimentId, { kind: "engine_attempt", id: attemptId }));
  expect(await screen.findByLabelText("Selected route item")).toHaveTextContent(attemptId);
  expect(screen.getByLabelText("Assistant selection")).toHaveTextContent(`"attempt_id":"${attemptId}"`);

  await user.click(screen.getByRole("button", { name: "Browser back" }));
  await waitFor(() => expect(screen.getByLabelText("Current location")).not.toHaveTextContent("attempt="));
  expect(screen.getByLabelText("Selected route item")).toHaveTextContent("none");
});

it("shows a recoverable error when the server cannot bind a requested selection", async () => {
  mount(`/composition?engine_experiment=${experimentId}&check=${checkId}`);
  expect(await screen.findByText("Engine experiment unavailable")).toBeVisible();
  expect(screen.getByRole("link", { name: "Composition workspace" })).toHaveAttribute("href", "/composition");
});
