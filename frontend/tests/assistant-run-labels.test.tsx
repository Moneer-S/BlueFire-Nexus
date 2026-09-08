import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { AssistantRunReference } from "../src/components/AssistantRunReference";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api } from "../src/lib/api";
import { assistanceJobId, storeAssistanceReceipt, type AssistanceEnvelope, type AssistanceRequest } from "../src/lib/assistance";
import { demoRuns } from "../src/lib/demo";
import { AssistanceProvider, usePublishAssistanceSelection, type AssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";
import type { RunRecord } from "../src/types";

const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));
function client() {
  const value = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  clients.push(value);
  return value;
}
function run(id = "run-a", name: string | null = "Collection before control"): RunRecord {
  return { ...structuredClone(demoRuns[0]!), schema_version: "bluefire.run-result.v1", run_id: id,
    scenario_title: "Frozen collection procedure", mode: "execute", created_at: "2030-01-01T12:00:00Z", runner_profile_id: "recorded-lab.v1",
    presentation: { schema_version: "bluefire.run-presentation.v1", run_id: id, display_name: name, default_name: "Frozen collection procedure", updated_at: "2030-01-01T12:00:00Z" } };
}
function mountReference(runId = "run-a", queryClient = client()) {
  const onNavigate = vi.fn();
  const tree = (id: string) => <QueryClientProvider client={queryClient}><MemoryRouter><AssistantRunReference runId={id} label="Reviewed run" onNavigate={onNavigate}/></MemoryRouter></QueryClientProvider>;
  const view = render(tree(runId));
  return { ...view, client: queryClient, onNavigate, changeRun: (id: string) => view.rerender(tree(id)) };
}

it("uses the shared custom name, recorded context and separately accessible exact ID", async () => {
  vi.spyOn(api, "runDetail").mockResolvedValue(run());
  const { onNavigate } = mountReference();
  const link = await screen.findByRole("link", { name: "Reviewed run: Collection before control" });
  expect(link).toHaveAttribute("href", "/runs/run-a");
  expect(screen.getByText(/Execute.*Profile: recorded-lab.v1/)).toBeVisible();
  expect(document.querySelector("time")).toHaveAttribute("datetime", "2030-01-01T12:00:00Z");
  expect(screen.getByText("run-a", { selector: "code" })).not.toBeVisible();
  const user = userEvent.setup();
  await user.click(screen.getByText("Run identity", { selector: "summary" }));
  expect(screen.getByText("run-a", { selector: "code" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Copy run ID" })).toBeEnabled();
  await user.click(link);
  expect(onNavigate).toHaveBeenCalledOnce();
});

it("reflects rename cache updates and a fresh reset without mutating canonical evidence", async () => {
  const original = run();
  const detail = vi.spyOn(api, "runDetail").mockResolvedValue(original);
  const { client } = mountReference();
  await screen.findByRole("link", { name: "Reviewed run: Collection before control" });
  const renamed = { ...original, presentation: { ...original.presentation!, display_name: "Operator renamed run" } };
  act(() => client.setQueryData(["run", original.run_id], renamed));
  await screen.findByRole("link", { name: "Reviewed run: Operator renamed run" });
  detail.mockResolvedValue(run("run-a", null));
  await act(async () => { await client.invalidateQueries({ queryKey: ["run", original.run_id], exact: true }); });
  await screen.findByRole("link", { name: "Reviewed run: Frozen collection procedure" });
  expect(original.presentation!.display_name).toBe("Collection before control");
  expect(client.getQueryData<RunRecord>(["run", original.run_id])!.steps).toEqual(original.steps);
});

it("uses the frozen procedure title for legacy metadata and never uses the objective paragraph", async () => {
  const legacy = { ...run(), schema_version: undefined, presentation: undefined, objective: "A long objective is not a run name." };
  vi.spyOn(api, "runDetail").mockResolvedValue(legacy);
  mountReference();
  expect(await screen.findByRole("link", { name: "Reviewed run: Frozen collection procedure" })).toHaveAttribute("href", "/runs/run-a");
  expect(screen.queryByText(legacy.objective)).not.toBeInTheDocument();
});

it.each(["unavailable", "wrong-id", "wrong-schema"])("keeps the exact run link available with neutral text when details are %s", async failure => {
  const detail = vi.spyOn(api, "runDetail");
  if (failure === "unavailable") detail.mockRejectedValue(new Error("Offline"));
  else detail.mockResolvedValue(failure === "wrong-id" ? run("run-other", "Unrelated run") : { ...run(), schema_version: "bluefire.other.v1" });
  mountReference();
  await screen.findByText("Run details unavailable");
  expect(screen.getByRole("link", { name: "Reviewed run: Run" })).toHaveAttribute("href", "/runs/run-a");
  expect(screen.queryByText("Unrelated run")).not.toBeInTheDocument();
  expect(screen.queryByText("Collection before control")).not.toBeInTheDocument();
});

it("does not label a new selection with an older delayed response or mismatched cached data", async () => {
  let finish!: (value: RunRecord) => void;
  vi.spyOn(api, "runDetail").mockImplementation(id => id === "run-a" ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(run(id, "Current selected run")));
  const queryClient = client();
  queryClient.setQueryData(["run", "run-a"], run("wrong", "Wrong cached name"));
  // A fresh query is still needed for invalid cached data.
  void queryClient.invalidateQueries({ queryKey: ["run", "run-a"] });
  const view = mountReference("run-a", queryClient);
  expect(screen.queryByText("Wrong cached name")).not.toBeInTheDocument();
  await waitFor(() => expect(finish).toBeTypeOf("function"));
  view.changeRun("run-b");
  await screen.findByRole("link", { name: "Reviewed run: Current selected run" });
  await act(async () => finish(run("run-a", "Late previous run")));
  expect(screen.getByRole("link", { name: "Reviewed run: Current selected run" })).toHaveAttribute("href", "/runs/run-b");
  expect(screen.queryByText("Late previous run")).not.toBeInTheDocument();
});

const digest = `sha256:${"a".repeat(64)}`;
const selection: AssistanceSelection = { runId: "run-current", candidateId: "rule", resourceDigest: digest, title: "Selected rule", manualEdits: false };
function Selection({ value }: { value: AssistanceSelection }) { usePublishAssistanceSelection(value); return null; }
function mountAssistant(value = selection) {
  const queryClient = client();
  return render(<QueryClientProvider client={queryClient}><MemoryRouter><ProductProvider><AssistanceProvider><Selection value={value}/><ExperimentAssistant providers={[]}/></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
}

it("names the live selected evidence without making model requests while Off", async () => {
  const detail = vi.spyOn(api, "runDetail").mockResolvedValue(run(selection.runId, "Selected observation run"));
  vi.spyOn(api, "assistanceContext").mockRejectedValue(new Error("Context temporarily unavailable"));
  const submit = vi.spyOn(api, "submitAssistance");
  mountAssistant();
  expect(detail).not.toHaveBeenCalled();
  await userEvent.setup().click(screen.getByRole("button", { name: "Assistant" }));
  expect(await screen.findByRole("link", { name: "Source observations: Selected observation run" })).toHaveAttribute("href", "/runs/run-current");
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
});

it.each(["available", "unavailable"])("retains the saved operation's exact source and comparison pair when result names are %s", async metadata => {
  const request: AssistanceRequest = { submission_id: "01234567-89ab-4def-8123-456789abcdef", context_digest: digest, run_id: "run-a", candidate_id: "rule", candidate_resource_digest: digest, message: "Compare the saved observations.", case_role: "attack", autonomy: "assist", provider_id: "saved-provider" };
  storeAssistanceReceipt(request);
  const before = JSON.stringify(request);
  const envelope: AssistanceEnvelope = { job: { schema_version: "bluefire.job.v1", job_id: assistanceJobId(request.submission_id), kind: "assistance.turn", state: "completed", request: { submitted_request: request }, progress: {} }, turn: {
    schema_version: "bluefire.assistance-turn.v1", status: "completed", can_start_new_turn: true, message: "The comparison is retained.", context_digest: digest, selected: { run_id: "run-a", candidate_id: "rule", candidate_resource_digest: digest }, plan: [], active_child: null, next_action: null, continuation: null, limitations: [],
    results: [{ kind: "method_comparison", step_id: "compare", candidate_id: "rule", evaluation_ids: ["evaluation-a", "evaluation-b"], run_ids: ["run-a", "run-b"], comparison_id: "comparison", native_path: "/compare?source=run-a&replay=run-b" }],
  } };
  vi.spyOn(api, "assistanceTurn").mockResolvedValue(envelope);
  const get = vi.spyOn(api, "runDetail").mockImplementation(async id => {
    if (metadata === "unavailable" && id === "run-b") throw new Error("Offline");
    return run(id, id === "run-a" ? "Before control" : "After control");
  });
  const submit = vi.spyOn(api, "submitAssistance");
  mountAssistant();
  await userEvent.setup().click(screen.getByRole("button", { name: /^Assistant/ }));
  const saved = await screen.findByRole("region", { name: "Saved results" });
  expect(await within(saved).findByRole("link", { name: "Compared run: Before control" })).toHaveAttribute("href", "/runs/run-a");
  if (metadata === "unavailable") await within(saved).findByText("Run details unavailable");
  expect(await within(saved).findByRole("link", { name: metadata === "available" ? "Compared run: After control" : "Compared run: Run" })).toHaveAttribute("href", "/runs/run-b");
  expect(within(saved).getByRole("link", { name: "Open method comparison" })).toHaveAttribute("href", "/compare?source=run-a&replay=run-b");
  expect(get).not.toHaveBeenCalledWith(selection.runId);
  expect(JSON.stringify(request)).toBe(before);
  expect(submit).not.toHaveBeenCalled();
});
