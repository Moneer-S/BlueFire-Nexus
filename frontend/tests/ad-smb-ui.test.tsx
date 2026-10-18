import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AdSmbPage } from "../src/pages/AdSmb";
import { ObjectiveStart } from "../src/components/ObjectiveStart";
import { adSmbApi, readAdPending, storeAdPending } from "../src/lib/ad-smb";
import { adChild, adOwner, adPendingFixture, adSubmission, auditWindowStartForFixture, rawAdAcknowledgement, rawAdEnvironments, rawAdNormalizedObservation, rawAdReview, rawAdWorkflow } from "./ad-smb-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));
function mount(path = `/ad-smb?workflow=${adOwner}`) { const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); return { ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><AdSmbPage /></MemoryRouter></QueryClientProvider>), client }; }
beforeEach(() => {
  localStorage.clear();
  vi.spyOn(crypto, "randomUUID").mockReturnValue(adSubmission);
  vi.spyOn(adSmbApi, "environments").mockResolvedValue(rawAdEnvironments());
  vi.spyOn(adSmbApi, "list").mockResolvedValue({ workflows: [rawAdWorkflow()] });
  vi.spyOn(adSmbApi, "workflow").mockResolvedValue(rawAdWorkflow());
  vi.spyOn(adSmbApi, "review").mockResolvedValue(rawAdReview());
  vi.spyOn(adSmbApi, "submit").mockResolvedValue(rawAdAcknowledgement());
  vi.spyOn(adSmbApi, "create").mockRejectedValue(new Error("Not admitted"));
  vi.spyOn(adSmbApi, "stop").mockResolvedValue(rawAdWorkflow({ stopped: true }));
  vi.spyOn(adSmbApi, "recover").mockResolvedValue(rawAdWorkflow());
  vi.spyOn(adSmbApi, "job").mockResolvedValue(rawAdAcknowledgement());
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
it("opens AD readiness from the objective chooser without creating or authorizing work", async () => {
  vi.mocked(adSmbApi.environments).mockResolvedValue({ environments: [], native_execution_available: false });
  vi.mocked(adSmbApi.list).mockResolvedValue({ workflows: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/getting-started"]}><Routes>
    <Route path="/getting-started" element={<ObjectiveStart />} />
    <Route path="/ad-smb" element={<AdSmbPage />} />
  </Routes></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByRole("combobox", { name: "Objective" }), { target: { value: "ad-access" } });
  expect(screen.getByText("Not checked")).toBeVisible();
  expect(adSmbApi.environments).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("link", { name: "Review environment" }));
  expect(await screen.findByText("Live AD execution unavailable")).toBeVisible();
  expect(screen.getByRole("heading", { name: "AD share access" })).toBeVisible();
  expect(adSmbApi.create).not.toHaveBeenCalled();
  expect(adSmbApi.review).not.toHaveBeenCalled();
  expect(adSmbApi.submit).not.toHaveBeenCalled();
  expect(adSmbApi.stop).not.toHaveBeenCalled();
  expect(adSmbApi.recover).not.toHaveBeenCalled();
});
it("shows unavailable enrollment without credential inputs or fabricated ready state", async () => {
  vi.mocked(adSmbApi.environments).mockResolvedValue({ environments: [], native_execution_available: false });
  mount("/ad-smb");
  expect(await screen.findByText("Live AD execution unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Save exercise" })).not.toBeInTheDocument();
  expect(screen.queryByRole("textbox")).not.toBeInTheDocument(); expect(adSmbApi.create).not.toHaveBeenCalled();
});
it("loads saved work read-only and hides opaque credentials and binary descriptors", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(rawAdWorkflow({ phases: ["inspect", "baseline"], allowed: ["harden"] }));
  mount();
  await screen.findByRole("heading", { name: "Read outcomes" });
  expect(within(screen.getByRole("region", { name: "Baseline and fresh read comparison" })).getByRole("table")).toBeInTheDocument();
  expect(document.body.textContent).not.toMatch(/credential-|PRIVATE_DESCRIPTOR_BYTES|binary_b64/);
  expect(screen.getByText(/Effective access not established/)).toBeInTheDocument();
  expect(adSmbApi.review).not.toHaveBeenCalled(); expect(adSmbApi.submit).not.toHaveBeenCalled(); expect(adSmbApi.recover).not.toHaveBeenCalled();
});
it("refreshes from missing enrollment through partial channels without authorizing work", async () => {
  const partial = rawAdEnvironments();
  const entry = partial.environments[0]!;
  const unavailable = { ...partial, environments: [{ ...entry, available: false, readiness: { ...entry.readiness, available: false, client_read_admission: false, secret_channel_available: false, problem: "client_channel_unavailable" } }] };
  vi.mocked(adSmbApi.environments).mockResolvedValueOnce({ environments: [], native_execution_available: false }).mockResolvedValueOnce(unavailable).mockResolvedValue(rawAdEnvironments());
  mount("/ad-smb");
  expect(await screen.findByText("Not tested")).toBeVisible();
  expect(screen.getByText("Not checked")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  expect(await screen.findByText("The client channel did not confirm its enrolled configuration.")).toBeVisible();
  expect(screen.getAllByText("Configuration confirmed")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Save exercise" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Save exercise" })).toBeEnabled());
  expect(screen.getAllByText("Configuration confirmed")).toHaveLength(3);
  expect(screen.getByText(/Configuration checks only/)).toBeVisible();
  expect(screen.queryByText("Member observation")).not.toBeInTheDocument();
  expect(adSmbApi.create).not.toHaveBeenCalled();
  expect(adSmbApi.review).not.toHaveBeenCalled();
  expect(adSmbApi.submit).not.toHaveBeenCalled();
});
it.each(["future", "expired"])("does not offer a saved exercise for a %s scope", async state => {
  const value = rawAdEnvironments();
  const scope = value.environments[0]!.environment.scope;
  if (state === "future") scope.created_at = new Date(Date.now() + 60_000).toISOString();
  else scope.expires_at = new Date(Date.now() - 60_000).toISOString();
  vi.mocked(adSmbApi.environments).mockResolvedValue(value);
  mount("/ad-smb");
  expect(await screen.findByText(state === "future" ? "Not started" : "Expired")).toBeVisible();
  expect(screen.getByRole("button", { name: "Save exercise" })).toBeDisabled();
  expect(screen.getByText("The authorized scope window is not current.")).toBeVisible();
  expect(screen.queryByText("Configuration confirmed")).not.toBeInTheDocument();
  expect(adSmbApi.create).not.toHaveBeenCalled();
});
it("requires explicit review, unchecked consent and reviewer before one exact submission", async () => {
  mount(); fireEvent.click(await screen.findByRole("button", { name: "Review inspect share" }));
  const submit = await screen.findByRole("button", { name: "Submit reviewed stage" });
  expect(submit).toBeDisabled(); expect(screen.getByRole("checkbox")).not.toBeChecked();
  fireEvent.click(screen.getByRole("checkbox")); expect(submit).toBeDisabled();
  fireEvent.change(screen.getByRole("textbox", { name: "Reviewed by" }), { target: { value: "operator" } });
  fireEvent.click(submit);
  await waitFor(() => expect(adSmbApi.submit).toHaveBeenCalledOnce());
  expect(adSmbApi.submit).toHaveBeenCalledWith(adOwner, adPendingFixture().body);
  await waitFor(() => expect(readAdPending()).toBeUndefined());
});
it("does not dispatch when exact request persistence fails", async () => {
  mount(); fireEvent.click(await screen.findByRole("button", { name: "Review inspect share" }));
  await screen.findByRole("checkbox"); fireEvent.click(screen.getByRole("checkbox")); fireEvent.change(screen.getByRole("textbox", { name: "Reviewed by" }), { target: { value: "operator" } });
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage unavailable"); });
  fireEvent.click(screen.getByRole("button", { name: "Submit reviewed stage" }));
  expect(await screen.findByText("Storage unavailable")).toBeInTheDocument(); expect(adSmbApi.submit).not.toHaveBeenCalled();
});
it("restores an unconfirmed original on reload and checks it without automatic replay", async () => {
  storeAdPending(adPendingFixture()); mount("/ad-smb");
  expect(await screen.findByText("Original request not yet confirmed")).toBeInTheDocument();
  expect(adSmbApi.submit).not.toHaveBeenCalled(); expect(adSmbApi.job).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Check saved request" }));
  await waitFor(() => expect(readAdPending()).toBeUndefined()); expect(adSmbApi.job).toHaveBeenCalledWith(adPendingFixture().id); expect(adSmbApi.submit).not.toHaveBeenCalled();
});
it("retains a wrong confirmation and blocks new stage review", async () => {
  const wrong = rawAdAcknowledgement(); wrong.request.submitted_request.reviewed_by = "different";
  vi.mocked(adSmbApi.submit).mockResolvedValue(wrong);
  mount(); fireEvent.click(await screen.findByRole("button", { name: "Review inspect share" })); await screen.findByRole("checkbox"); fireEvent.click(screen.getByRole("checkbox")); fireEvent.change(screen.getByRole("textbox", { name: "Reviewed by" }), { target: { value: "operator" } }); fireEvent.click(screen.getByRole("button", { name: "Submit reviewed stage" }));
  await screen.findByText("The saved AD operation did not confirm the exact reviewed request.");
  expect(readAdPending()).toEqual(adPendingFixture()); expect(screen.getByRole("button", { name: "Review inspect share" })).toBeDisabled();
});
it("shows a settled ineffective retest with restore still offered and no success claim", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(rawAdWorkflow({ phases: ["inspect", "baseline", "harden", "retest"], allowed: ["rollback", "audit"], expectation: "not_met" }));
  mount(); expect(await screen.findByText("Read expectations not met")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Review restore share access" })).toBeEnabled();
  const compare = screen.getByRole("region", { name: "Baseline and fresh read comparison" });
  expect(within(compare).getAllByText("Content matched")).toHaveLength(6);
  expect(screen.queryByText("Original operation unsettled")).not.toBeInTheDocument();
});
it("reviews restoration in its actual direction without changing the saved hardening evidence", async () => {
  const value = rawAdWorkflow({ phases: ["inspect", "baseline", "harden", "retest"], allowed: ["rollback"] });
  vi.mocked(adSmbApi.workflow).mockResolvedValue(value);
  vi.mocked(adSmbApi.review).mockResolvedValue(rawAdReview("rollback", value.workflow.progress.revision));
  mount(); fireEvent.click(await screen.findByRole("button", { name: "Review restore share access" }));
  const review = await screen.findByRole("region", { name: "Explicit AD stage review" });
  expect(within(review).getByRole("row", { name: "Principal Current Restored" })).toBeInTheDocument();
  expect(within(review).getByRole("row", { name: "Probe No explicit allow Read" })).toBeInTheDocument();
  expect(within(review).getByText("The probe's explicit Read entry is restored. Owner, group, and retained entries remain unchanged.")).toBeInTheDocument();
  expect(within(review).queryByText("Explicit allow removed")).not.toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Retained AD evidence" })).getByRole("row", { name: "Probe Read Explicit allow removed" })).toBeInTheDocument();
  expect(within(review).getByRole("checkbox")).not.toBeChecked();
  expect(within(review).getByRole("button", { name: "Submit reviewed stage" })).toBeDisabled();
  expect(adSmbApi.submit).not.toHaveBeenCalled();
});
it("keeps Stop usable for an active recovery even after new work is stopped", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(rawAdWorkflow({ phases: ["inspect", "baseline", "harden"], pending: adChild, stopped: true }));
  mount(); const stop = await screen.findByRole("button", { name: "Stop current operation" }); expect(stop).toBeEnabled(); fireEvent.click(stop);
  await waitFor(() => expect(adSmbApi.stop).toHaveBeenCalledWith(adOwner));
});
it("checks only original results and keeps unavailable recovery truthful", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(rawAdWorkflow({ pending: adChild }));
  vi.mocked(adSmbApi.recover).mockRejectedValue(new Error("Original terminal remains unavailable; no replay."));
  mount(); fireEvent.click(await screen.findByRole("button", { name: "Check original results" }));
  expect(await screen.findByText("Original terminal remains unavailable; no replay.")).toBeInTheDocument();
  expect(adSmbApi.recover).toHaveBeenCalledWith(adOwner); expect(adSmbApi.submit).not.toHaveBeenCalled();
});
it("does not offer expired business checks while restore remains current", async () => {
  const raw = rawAdWorkflow({ phases: ["inspect", "baseline", "harden"], allowed: ["retest", "rollback"] }); raw.workflow.request.environment.scope.created_at = new Date(Date.now() - 1900_000).toISOString();
  vi.mocked(adSmbApi.workflow).mockResolvedValue(raw); mount();
  expect(await screen.findByRole("button", { name: "Review restore share access" })).toBeEnabled(); expect(screen.queryByRole("button", { name: "Review fresh read checks" })).not.toBeInTheDocument();
});
it("keeps saved results visible but disables stage actions without admission", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(rawAdWorkflow({ phases: ["inspect", "baseline"], allowed: ["harden"], unavailable: true }));
  mount(); expect(await screen.findByText("Native admission unavailable")).toBeInTheDocument(); expect(screen.getByRole("button", { name: "Review remove probe access" })).toBeDisabled(); expect(screen.getAllByRole("link", { name: "Open retained run" })).toHaveLength(2);
});
it("does not report missing audit observations as an observed zero", async () => {
  const raw = rawAdWorkflow({ phases: ["audit"] });
  const operation = raw.workflow.progress.operations[0]!;
  operation.outcome.state = "not_started";
  operation.executions = [{ ...operation.executions[0]!, dispatch: "not_started", observation: null } as unknown as typeof operation.executions[number]];
  vi.mocked(adSmbApi.workflow).mockResolvedValue(raw); mount();
  expect(await screen.findByText("No audit observation retained. No independent observation is reported.")).toBeInTheDocument();
  expect(screen.queryByText(/Audit retained: 0 events/)).not.toBeInTheDocument();
});
it("keeps successful fixture read expectations distinct from runner provenance", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(rawAdWorkflow({ phases: ["baseline", "retest"] })); mount();
  expect(await screen.findByText("Retained observations match the requested read outcomes. Remote identity and effective access remain unproven.")).toBeInTheDocument();
  expect(screen.queryByText(/Runner-reported observations match/)).not.toBeInTheDocument(); expect(screen.getAllByText("Synthetic fixture").length).toBeGreaterThan(0);
});
it("distinguishes observed zero audit events from an absent observation", async () => {
  const raw = rawAdWorkflow({ phases: ["audit"] }); const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation;
  if (!("events" in observation)) throw new Error("Expected audit fixture"); observation.events = 0; observation.truncated = false;
  vi.mocked(adSmbApi.workflow).mockResolvedValue(raw); mount();
  expect(await screen.findByText("Audit retained: 0 source events. Normalized event rows are not present in this saved summary. Source authentication and independence are not established.")).toBeInTheDocument();
});
it("does not label a truncated legacy audit summary as a capture-limit result", async () => {
  const raw = rawAdWorkflow({ phases: ["audit"] });
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation;
  if (!("events" in observation)) throw new Error("Expected audit fixture");
  observation.truncated = true;
  vi.mocked(adSmbApi.workflow).mockResolvedValue(raw); mount();
  expect(await screen.findByText(/incomplete or truncated capture/)).toBeInTheDocument();
  expect(screen.queryByText(/capture limit reached/)).not.toBeInTheDocument();
});
function normalizedAuditWorkflow(count: number) {
  const raw = rawAdWorkflow({ phases: ["audit"] });
  const observation = raw.workflow.progress.operations[0]!.executions[0]!.observation;
  if (!("events" in observation)) throw new Error("Expected audit fixture");
  const payload = observation as unknown as Record<string, any>;
  payload.events = count;
  payload.truncated = false;
  payload.normalized_observation = rawAdNormalizedObservation(count, auditWindowStartForFixture(raw.workflow.request.environment.scope.created_at));
  return raw;
}
it("renders bounded normalized rows and opens exact source references without raw event content", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(normalizedAuditWorkflow(3)); mount();
  expect(await screen.findByRole("heading", { name: "Normalized Security events" })).toBeVisible();
  expect(screen.getByText("Share check denied")).toBeVisible();
  expect(screen.getByText("Multiple possible logon records")).toBeVisible();
  expect(screen.getByText(/A 5145 result is a share-level access check/)).toBeVisible();
  const sourceRefs = screen.getAllByText("Source refs", { selector: "summary" })[0]!;
  fireEvent.click(sourceRefs);
  expect(within(sourceRefs.closest("details")!).getByText("Source event digest")).toBeVisible();
  expect(document.body.textContent).not.toMatch(/<Event|EventData|TargetUserName|probe-user|raw_xml/);
  expect(adSmbApi.submit).not.toHaveBeenCalled();
});
it("paginates a bounded large capture without changing its saved workflow", async () => {
  vi.mocked(adSmbApi.workflow).mockResolvedValue(normalizedAuditWorkflow(26)); mount();
  expect(await screen.findByText("Events 1-25 of 26")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Next audit events" }));
  expect(await screen.findByText("Events 26-26 of 26")).toBeVisible();
  expect(screen.getByRole("button", { name: "Next audit events" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Previous audit events" })).toBeEnabled();
  expect(adSmbApi.submit).not.toHaveBeenCalled();
});
it("shows settled legitimate read breakage alongside the probe outcome", async () => {
  const raw = rawAdWorkflow({ phases: ["baseline", "harden", "retest"], allowed: ["rollback"], expectation: "not_met" });
  const observation = raw.workflow.progress.operations[2]!.executions[1]!.observation;
  if (!("reader" in observation)) throw new Error("Expected read fixture"); observation.state = "open_access_denied"; observation.bytes_read = 0; observation.sha256 = null;
  vi.mocked(adSmbApi.workflow).mockResolvedValue(raw); mount();
  await screen.findByText("Read expectations not met");
  const row = screen.getByRole("row", { name: "Legitimate / records.jsonl Content matched Open denied" }); expect(row).toBeInTheDocument(); expect(screen.getByRole("button", { name: "Review restore share access" })).toBeEnabled();
});
it("does not let a stale in-flight read repaint controls after Stop", async () => {
  const initial = rawAdWorkflow(); const stopped = rawAdWorkflow({ stopped: true, allowed: [] });
  let release!: (value: unknown) => void;
  vi.mocked(adSmbApi.workflow).mockResolvedValueOnce(initial).mockImplementationOnce(() => new Promise(resolve => { release = resolve; })).mockResolvedValue(stopped);
  vi.mocked(adSmbApi.stop).mockResolvedValue(stopped);
  const { client } = mount(); await screen.findByRole("button", { name: "Review inspect share" });
  act(() => { void client.refetchQueries({ queryKey: ["ad-smb-workflow", adOwner] }); });
  await waitFor(() => expect(release).toBeTypeOf("function"));
  fireEvent.click(screen.getByRole("button", { name: "Stop new work" }));
  await screen.findByText("New work stopped");
  await act(async () => { release(initial); });
  expect(screen.queryByRole("button", { name: "Review inspect share" })).not.toBeInTheDocument(); expect(screen.getByRole("button", { name: "Stop new work" })).toBeDisabled();
});
