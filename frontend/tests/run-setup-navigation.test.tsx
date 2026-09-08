import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect, useState } from "react";
import { HashRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { GettingStartedPage } from "../src/pages/GettingStarted";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { PreflightReport, RunConfiguration, RunJob } from "../src/types";

const binding = { state_digest: "saved-state", plan_digest: "saved-plan", target_scope_digest: "saved-scope", profile_id: "sandbox-execute.v1", maximum_tier: "controlled" };
const storedReview: PreflightReport = {
  status: "approval_required", ready: false, plan: { mode: "execute", steps: [], edges: [] },
  scope: { scope_refs: ["saved.job.scope"] }, cleanup: { policy: "always" }, approval_binding: binding,
  approval_envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: demoScenario.id, envelope_digest: "saved-envelope", steps: [] },
};
const savedJob: RunJob = {
  schema_version: "bluefire.job.v1", job_id: "job-1234567890abcdef1234567890abcdef", kind: "scenario.run", state: "awaiting_approval",
  request: { mode: "execute", approval_request_id: "approval-saved", scenario: demoScenario },
  approval_request: { approval_id: "approval-saved", status: "pending", expires_at: "2035-01-01T00:00:00Z", ...binding },
  progress: { phase: "awaiting_approval" }, error: null, result_ref: null,
};

function DraftHarness({ initialMode }: { initialMode: RunConfiguration["mode"] }) {
  const { runConfig, setRunConfig, scenario } = useProduct();
  const [seeded, setSeeded] = useState(false);
  useEffect(() => {
    if (seeded) return;
    setRunConfig({ ...runConfig, mode: initialMode, profileId: `sandbox-${initialMode}.v1`, scopeRefs: ["operator.selected.scope"], provider: "operator-provider", model: "operator-model", autonomy: "assist", maxSteps: 17 });
    setSeeded(true);
  }, [initialMode, runConfig, seeded, setRunConfig]);
  if (!seeded) return null;
  return <>
    <output aria-label="Current draft configuration">{JSON.stringify(runConfig)}</output>
    <output aria-label="Current draft graph">{JSON.stringify(scenario)}</output>
    <button onClick={() => setRunConfig({ ...runConfig, approved: true, approvedBy: "draft-reviewer" })}>Acknowledge current draft in test</button>
    <Routes><Route path="/getting-started" element={<GettingStartedPage />} /><Route path="/runs" element={<RunsPage />} /><Route path="/runs/:runId" element={<RunsPage />} /></Routes>
  </>;
}

function mount(path: string, initialMode: RunConfiguration["mode"], job?: RunJob, inventory?: Promise<RunJob[]>, storedLookup?: { jobId: string; response: Promise<Response> }) {
  window.location.hash = `#${path}`;
  window.localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(demoScenario));
  const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { "Content-Type": "application/json" } });
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const endpoint = url.pathname.replace(/^\/api\/v1/, "");
    if (endpoint === "/catalog") return json(demoCatalog);
    if (endpoint === "/scenarios") return json({ scenarios: [demoScenario] });
    if (endpoint === "/runs" && (!init?.method || init.method === "GET")) return json({ runs: [] });
    if (endpoint === "/runner") return json({ schema_version: "bluefire.runner-lifecycle-status.v1", state: "unbootstrapped", runner_id: "fixture-runner", profile_id: null, loopback_only: true, enrollment: "absent", process: "absent", runner: null, health: null });
    if (endpoint === "/detections/health") return json({ ready: false });
    if (endpoint === "/jobs") return json({ schema_version: "bluefire.active-job-list.v1", jobs: inventory ? await inventory : job ? [job] : [] });
    if (storedLookup && endpoint === `/jobs/${storedLookup.jobId}`) return storedLookup.response;
    if (job && endpoint === `/jobs/${job.job_id}`) return json(job);
    if (job && endpoint === "/runs/preflight") return json(storedReview);
    if (endpoint === `/runs/${demoRuns[0]!.run_id}`) return json(demoRuns[0]);
    throw new Error(`Unexpected navigation request: ${init?.method ?? "GET"} ${endpoint}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><ProductProvider><HashRouter><DraftHarness initialMode={initialMode} /></HashRouter></ProductProvider></QueryClientProvider>);
  const config = () => JSON.parse(screen.getByLabelText("Current draft configuration").textContent!) as RunConfiguration;
  const nonReads = () => fetchMock.mock.calls.filter(([, init]) => init?.method && init.method !== "GET");
  return { ...view, client, config, nonReads, fetchMock, user: userEvent.setup() };
}

afterEach(() => vi.unstubAllGlobals());

it.each(["simulate", "execute"] as const)("the Getting Started %s link selects setup without changing the operator's graph, scope, or provider", async (mode) => {
  const opposite = mode === "execute" ? "simulate" : "execute";
  const { user, config, nonReads, client } = mount("/getting-started", opposite);
  const link = await screen.findByRole("link", { name: mode === "execute" ? "Prepare guided Execute" : "Configure Simulate" });
  expect(link.getAttribute("href")).toBe(`#/runs?setup=${mode}${mode === "execute" ? "#guided-execute" : ""}`);
  await user.click(screen.getByRole("button", { name: "Acknowledge current draft in test" }));
  expect(config().approvedBy).toBe("draft-reviewer");
  const before = config();
  await user.click(link);
  await waitFor(() => expect(screen.getByRole("radio", { name: new RegExp(`^${mode}`, "i") })).toBeChecked());
  expect(config()).toEqual({ ...before, mode, profileId: `sandbox-${mode}.v1`, approved: false, approvedBy: "" });
  expect(JSON.parse(screen.getByLabelText("Current draft graph").textContent!)).toEqual(demoScenario);
  if (mode === "execute") expect(screen.getByRole("region", { name: "Guided local Execute" })).toBeVisible();
  else expect(screen.queryByRole("region", { name: "Guided local Execute" })).not.toBeInTheDocument();
  expect(nonReads()).toEqual([]);

  // The URL remains reusable, but polling and manual changes do not replay it.
  await user.click(screen.getByRole("radio", { name: new RegExp(`^${opposite}`, "i") }));
  await user.click(screen.getByRole("button", { name: "Acknowledge current draft in test" }));
  await act(async () => { await client.invalidateQueries({ queryKey: ["catalog"] }); });
  expect(config().mode).toBe(opposite);
  expect(config().approvedBy).toBe("draft-reviewer");
  expect(nonReads()).toEqual([]);
});

it.each([
  ["/runs?setup=simulate", "simulate", "execute"],
  ["/runs?setup=execute#guided-execute", "execute", "simulate"],
  ["/runs#guided-execute", "execute", "simulate"],
] as const)("opens a fresh tab directly at %s without execution calls", async (path, mode, initialMode) => {
  const { config, nonReads } = mount(path, initialMode);
  await waitFor(() => expect(screen.getByRole("radio", { name: new RegExp(`^${mode}`, "i") })).toBeChecked());
  expect(config()).toMatchObject({ mode, scopeRefs: ["operator.selected.scope"], provider: "operator-provider", model: "operator-model", autonomy: "assist" });
  expect(nonReads()).toEqual([]);
});

it.each([false, true])("keeps the saved durable approval review ahead of setup (restored=%s)", async (restored) => {
  if (restored) window.localStorage.setItem("bluefire.local.active-job-id.v1", savedJob.job_id);
  const path = restored ? "/runs?setup=execute" : `/runs?job=${savedJob.job_id}&setup=execute#guided-execute`;
  const { config, user, client, nonReads } = mount(path, "simulate", savedJob);
  const gate = await screen.findByRole("region", { name: "Durable Execute job approval" });
  const identity = within(gate).getByRole("textbox", { name: "Operator identity for this job" });
  await waitFor(() => expect(identity).toBeEnabled());
  expect(config().mode).toBe("simulate");
  expect(within(gate).getByText("saved.job.scope")).toBeVisible();
  expect(within(gate).getByRole("checkbox")).not.toBeChecked();
  await user.type(identity, "operator");
  await act(async () => { await client.invalidateQueries({ queryKey: ["catalog"] }); });
  expect(identity).toHaveValue("operator");
  expect(config().mode).toBe("simulate");
  // The existing review restoration recompiles only this immutable saved request.
  expect(nonReads()).toHaveLength(1);
  expect(JSON.parse(String(nonReads()[0]![1]!.body))).toEqual(savedJob.request);
  expect(String(nonReads()[0]![0])).toMatch(/\/runs\/preflight$/);
});

it("keeps a historical run review intact when its URL also contains a setup hint", async () => {
  const { config, nonReads } = mount(`/runs/${demoRuns[0]!.run_id}?setup=execute#guided-execute`, "simulate");
  await screen.findByRole("link", { name: "Back to run workspace" });
  expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  expect(config().mode).toBe("simulate");
  expect(nonReads()).toEqual([]);
});

it("waits for controller inventory before applying setup in a fresh tab without a stored job pointer", async () => {
  let resolveInventory!: (jobs: RunJob[]) => void;
  const inventory = new Promise<RunJob[]>((resolve) => { resolveInventory = resolve; });
  const { config, nonReads } = mount("/runs?setup=execute#guided-execute", "simulate", savedJob, inventory);
  expect(await screen.findByRole("radio", { name: /^Simulate/ })).toBeChecked();
  expect(config().mode).toBe("simulate");
  expect(nonReads()).toEqual([]);
  await act(async () => { resolveInventory([savedJob]); });
  const gate = await screen.findByRole("region", { name: "Durable Execute job approval" });
  await waitFor(() => expect(within(gate).getByRole("textbox", { name: "Operator identity for this job" })).toBeEnabled());
  expect(config().mode).toBe("simulate");
  expect(within(gate).getByRole("checkbox")).not.toBeChecked();
  expect(nonReads()).toHaveLength(1);
  expect(JSON.parse(String(nonReads()[0]![1]!.body))).toEqual(savedJob.request);
});

it.each(["mode", "scope"] as const)("honors a manual %s edit made while setup awaits inventory", async (field) => {
  let resolveInventory!: (jobs: RunJob[]) => void;
  const inventory = new Promise<RunJob[]>((resolve) => { resolveInventory = resolve; });
  const { user, config, nonReads } = mount("/runs?setup=execute", "simulate", undefined, inventory);
  const simulate = await screen.findByRole("radio", { name: /^Simulate/ });
  expect(simulate).toBeChecked();
  if (field === "mode") {
    await user.click(screen.getByRole("radio", { name: /^Execute/ }));
    await user.click(simulate);
  } else {
    const scope = screen.getByRole("textbox", { name: /^Target scope/ });
    await user.clear(scope);
    await user.type(scope, "operator.new.scope");
  }
  const edited = config();
  await act(async () => { resolveInventory([]); });
  await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
  expect(config()).toEqual(edited);
  expect(simulate).toBeChecked();
  expect(nonReads()).toEqual([]);
});

it("keeps idle setup and history useful without an empty live console", async () => {
  mount("/runs", "simulate");
  await screen.findByRole("heading", { name: "Run history" });
  await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
  expect(screen.queryByRole("heading", { name: "No active run" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Pause" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();
  expect(screen.getByRole("radio", { name: /^Simulate/ })).toBeChecked();
});

const staleStoredJobId = "job-abcdefabcdefabcdefabcdefabcdefab";
function deferredStoredLookup() {
  let settle!: (response: Response) => void;
  const response = new Promise<Response>((resolve) => { settle = resolve; });
  return { lookup: { jobId: staleStoredJobId, response }, settle };
}
function missingStoredJob(status = 404, code = "job_not_found") {
  return new Response(JSON.stringify({ error: { code, message: "Stored job lookup did not resolve." } }), { status, headers: { "Content-Type": "application/json" } });
}

it.each(["simulate", "execute"] as const)("applies a %s setup arrival after the stored job is definitively missing", async (mode) => {
  const opposite = mode === "execute" ? "simulate" : "execute";
  window.localStorage.setItem("bluefire.local.active-job-id.v1", staleStoredJobId);
  const { lookup, settle } = deferredStoredLookup();
  const { config, nonReads } = mount(`/runs?setup=${mode}`, opposite, undefined, undefined, lookup);
  await screen.findByRole("radio", { name: new RegExp(`^${opposite}`, "i") });
  expect(config().mode).toBe(opposite);
  expect(window.localStorage.getItem("bluefire.local.active-job-id.v1")).toBe(staleStoredJobId);
  expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();
  await act(async () => { settle(missingStoredJob()); });
  await waitFor(() => expect(screen.getByRole("radio", { name: new RegExp(`^${mode}`, "i") })).toBeChecked());
  expect(window.localStorage.getItem("bluefire.local.active-job-id.v1")).toBeNull();
  expect(config()).toMatchObject({ mode, scopeRefs: ["operator.selected.scope"], provider: "operator-provider", model: "operator-model", autonomy: "assist" });
  expect(nonReads()).toEqual([]);
});

it.each(["mode", "scope"] as const)("preserves a manual %s choice while the stale stored job lookup is pending", async (field) => {
  window.localStorage.setItem("bluefire.local.active-job-id.v1", staleStoredJobId);
  const { lookup, settle } = deferredStoredLookup();
  const { config, user, nonReads } = mount("/runs?setup=execute", "simulate", undefined, undefined, lookup);
  await screen.findByRole("radio", { name: /^Simulate/ });
  if (field === "mode") {
    await user.click(screen.getByRole("radio", { name: /^Execute/ }));
    await user.click(screen.getByRole("radio", { name: /^Simulate/ }));
  } else {
    const scope = screen.getByRole("textbox", { name: /^Target scope/ });
    await user.clear(scope);
    await user.type(scope, "chosen.scope");
  }
  const edited = config();
  await act(async () => { settle(missingStoredJob()); });
  await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
  expect(window.localStorage.getItem("bluefire.local.active-job-id.v1")).toBeNull();
  expect(config()).toEqual(edited);
  expect(nonReads()).toEqual([]);
});

it.each([[500, "service_unavailable"], [404, "unresolved_endpoint"]] as const)("does not apply setup after ambiguous stored lookup %s/%s", async (status, code) => {
  window.localStorage.setItem("bluefire.local.active-job-id.v1", staleStoredJobId);
  const { lookup, settle } = deferredStoredLookup();
  const { config, nonReads } = mount("/runs?setup=execute", "simulate", undefined, undefined, lookup);
  await screen.findByRole("radio", { name: /^Simulate/ });
  await act(async () => { settle(missingStoredJob(status, code)); });
  await screen.findByText("Stored job lookup did not resolve.");
  expect(window.localStorage.getItem("bluefire.local.active-job-id.v1")).toBe(staleStoredJobId);
  expect(config().mode).toBe("simulate");
  expect(screen.getByRole("button", { name: "Run preflight" })).toBeDisabled();
  expect(nonReads()).toEqual([]);
});

it("keeps explicit job URL precedence when that job is definitively missing", async () => {
  const { lookup, settle } = deferredStoredLookup();
  const { config, nonReads } = mount(`/runs?job=${staleStoredJobId}&setup=execute`, "simulate", undefined, undefined, lookup);
  await screen.findByRole("heading", { name: "Run details" });
  await act(async () => { settle(missingStoredJob()); });
  await waitFor(() => expect(window.localStorage.getItem("bluefire.local.active-job-id.v1")).toBeNull());
  expect(config().mode).toBe("simulate");
  expect(nonReads()).toEqual([]);
});

it("does not replay setup after a freshly validated stored job later disappears", async () => {
  window.localStorage.setItem("bluefire.local.active-job-id.v1", staleStoredJobId);
  const { lookup, settle } = deferredStoredLookup();
  const { config, client, nonReads } = mount("/runs?setup=execute", "simulate", undefined, undefined, lookup);
  await screen.findByRole("radio", { name: /^Simulate/ });
  await act(async () => {
    settle(new Response(JSON.stringify({ ...savedJob, job_id: staleStoredJobId, state: "running", progress: { phase: "running" } }), { headers: { "Content-Type": "application/json" } }));
  });
  await screen.findByText(/Mutable controls remain disabled while ownership is reconciled/);
  expect(config().mode).toBe("simulate");
  lookup.response = Promise.resolve(missingStoredJob());
  await act(async () => { await client.refetchQueries({ queryKey: ["job", staleStoredJobId], exact: true }); });
  await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeEnabled());
  expect(window.localStorage.getItem("bluefire.local.active-job-id.v1")).toBeNull();
  expect(config().mode).toBe("simulate");
  expect(nonReads()).toEqual([]);
});

it("keeps an interrupted Assistant run with its operation instead of offering a replacement", async () => {
  const operation = `job-${"e".repeat(32)}`;
  const job: RunJob = { ...savedJob, state: "interrupted", approval_request: null, request: { ...savedJob.request, assistance_run: { operation_job_id: operation, preparation_digest: "bound-preparation" } }, progress: { phase: "interrupted" } };
  const view = mount(`/runs?job=${job.job_id}`, "simulate", job);
  expect(await screen.findByRole("link", { name: "Return to Assistant run and evidence" })).toHaveAttribute("href", `#/runs?assistance_job=${operation}`);
  expect(screen.queryByRole("button", { name: "Retry as replacement" })).not.toBeInTheDocument();
  expect(screen.getByText("Review this run and its cleanup before starting new work. Evidence recovery does not repeat execution.")).toBeVisible();
  expect(view.fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/retry"))).toEqual([]);
});


it("opens history first and reopens the same new-review link without changing Execute settings", async () => {
  const { user, config, nonReads } = mount("/runs", "execute");
  await screen.findByRole("heading", { name: "Run history" });
  const setup = screen.getByText("Review a new run \u00b7 " + demoScenario.title).closest("details")!;
  expect(setup).not.toHaveAttribute("open");
  const before = config();
  await user.click(screen.getAllByRole("link", {name:"Review new run"})[0]!);
  await waitFor(() => expect(setup).toHaveAttribute("open"));
  await user.click(setup.querySelector("summary")!);
  await waitFor(() => expect(setup).not.toHaveAttribute("open"));
  await user.click(screen.getAllByRole("link", {name:"Review new run"})[0]!);
  await waitFor(() => expect(setup).toHaveAttribute("open"));
  expect(config()).toEqual(before);
  expect(nonReads()).toEqual([]);
});
