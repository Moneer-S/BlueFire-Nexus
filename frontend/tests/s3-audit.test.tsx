import { webcrypto } from "node:crypto";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useSearchParams } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import corpus from "../../tests_platform/fixtures/s3_audit_reviews_v1.json";
import { auditFiles, auditInputDigest, checkedCollectedAuditReview, checkedAuditHistory, checkedAuditReview, readAuditPending, s3AuditApi, saveAuditPending, type AuditHistory, type AuditInput, type AuditReview } from "../src/lib/s3-audit";
import { S3Audit } from "../src/pages/S3Audit";
import { collectedReview, collectedSummary } from "./s3-audit-collected-fixture";

const history = corpus.history as AuditHistory;
const sample = corpus.cases[0]!;
const review = sample.review as AuditReview;
const input = sample.input as AuditInput;
const owner = history.workflow_job_id;
const collectedOwner = collectedReview.workflow_job_id;
const marker = { owner, submission_id: input.submission_id, run_id: input.run_id, delivery_state: input.delivery_state, input_digest: review.input_digest };
const fixtureFile = () => { const bytes = Uint8Array.from(atob(input.logs[0]!.data), c => c.charCodeAt(0)); return Object.assign(new File([bytes], "audit.json.gz"), { arrayBuffer: async () => bytes.buffer }); };
function view(selectedOwner = owner, initialEntry = "/s3-access") { const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 }, mutations: { retry: false } } }); return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[initialEntry]}><S3Audit owner={selectedOwner} /></MemoryRouter></QueryClientProvider>); }
function RouteSwitcher({ target }: { target: string }) { const [, setSearchParams] = useSearchParams(); return <button onClick={() => setSearchParams(new URLSearchParams(target.split("?")[1]))}>Switch audit source</button>; }
function collectedHistory(): AuditHistory {
  if (history.schema_version !== "bluefire.s3-audit-reviews.v1") throw new Error("The import-history fixture must remain v1.");
  const base = structuredClone(history);
  const result: AuditHistory = { workflow_job_id: base.workflow_job_id, reads: base.reads, reviews: base.reviews, maximum_reviews: base.maximum_reviews, maximum_input_bytes: base.maximum_input_bytes, maximum_expanded_bytes: base.maximum_expanded_bytes, schema_version: "bluefire.s3-audit-reviews.v2", collections: [structuredClone(collectedSummary)], maximum_collections: 2 };
  return result;
}
beforeEach(() => { localStorage.clear(); vi.stubGlobal("crypto", webcrypto); vi.spyOn(s3AuditApi, "list").mockResolvedValue(structuredClone(history)); vi.spyOn(s3AuditApi, "read").mockResolvedValue(structuredClone(review)); vi.spyOn(s3AuditApi, "save").mockResolvedValue(structuredClone(review)); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("accepts actual backend projections and the canonical original-input fingerprint", async () => {
  expect(checkedAuditHistory(history, owner)).toEqual(history);
  for (const row of corpus.cases) { const saved = row.review as AuditReview; expect(checkedAuditReview(saved, owner, saved.review_id)).toEqual(saved); expect(await auditInputDigest(row.input as AuditInput)).toBe(saved.input_digest); }
});
it.each(["owner", "run", "provenance", "proof", "request", "bytes", "reader", "imports", "delivery"])("refuses a changed response binding: %s", change => {
  const bad = structuredClone(review);
  if (change === "owner") bad.workflow_job_id = "job-" + "f".repeat(32);
  if (change === "run") bad.source.run_id = "../../other";
  if (change === "provenance") Object.assign(bad, { collection_provenance: "independent" });
  if (change === "proof") Object.assign(bad.correlation.audit, { independent_collection_proven: true });
  if (change === "request") bad.correlation.request_digest = "sha256:" + "f".repeat(64);
  if (change === "bytes") Object.assign(bad.correlation.reads[0]!, { full_object_bytes_proven: true });
  if (change === "reader") bad.correlation.reads[0]!.reader = "legitimate";
  if (change === "imports") bad.imports[0]!.expanded_bytes++;
  if (change === "delivery") Object.assign(bad.correlation.audit, { reported_delivery_state: "verified" });
  expect(() => checkedAuditReview(bad, owner, review.review_id)).toThrow();
});
it("rejects duplicated history and a review from another source", () => {
  const bad = structuredClone(history); bad.reviews.push(bad.reviews[0]!); expect(() => checkedAuditHistory(bad, owner)).toThrow();
  const changed = structuredClone(history); changed.reviews[0]!.source.outcome_digest = "sha256:" + "f".repeat(64); expect(() => checkedAuditHistory(changed, owner)).toThrow();
});
it("accepts v2 history without changing its separate operator-import history", () => {
  const v2 = collectedHistory();
  expect(checkedAuditHistory(v2, owner)).toEqual(v2);
  expect(v2.reviews).toEqual(history.reviews);
  expect(v2.reads).toEqual(history.reads);
});
it.each(["operation", "phase", "pair-run", "receipt-reservation", "correlation", "correlation-window", "observation-schema", "extra-key"])("rejects a spliced collected detail: %s", change => {
  const bad = structuredClone(collectedReview);
  expect(checkedCollectedAuditReview(bad, collectedOwner, bad.review_id)).toEqual(bad);
  if (change === "operation") bad.operation_job_id = "job-" + "f".repeat(32);
  if (change === "phase") bad.phase = "retest";
  if (change === "pair-run") bad.original_pair.reads[1].run_id = bad.original_pair.reads[0].run_id;
  if (change === "receipt-reservation") bad.receipt.reservation_digest = "sha256:" + "0".repeat(64);
  if (change === "correlation") bad.receipt.result.data.correlations.probe.request_digest = "sha256:" + "f".repeat(64);
  if (change === "correlation-window") bad.receipt.result.data.correlations.probe.authorized_request_window.from = "2026-10-11T20:44:20Z";
  if (change === "observation-schema") Object.assign(bad.receipt.result.data, { schema_version: "bluefire.s3-audit-observation.v1" });
  if (change === "extra-key") Object.assign(bad.receipt.result.data, { unexpected: true });
  expect(bad).not.toEqual(collectedReview);
  expect(() => checkedCollectedAuditReview(bad, collectedOwner, collectedReview.review_id)).toThrow();
});
it("accepts a validated failed original read and an unreported object call", () => {
  const partial = structuredClone(collectedReview);
  const probe = partial.original_pair.reads[0];
  probe.result.outcome = "failed";
  probe.result.problem = "scoped_operation_failed";
  probe.result.data = null;
  probe.result.send_permits_consumed = 3;
  probe.result.calls.splice(3);
  Object.assign(partial.receipt.result.data.correlations.probe.reads[0]!, {
    status: "worker_unreported",
    worker_outcome: "unreported",
    worker_request_id: null,
  });
  expect(checkedCollectedAuditReview(partial, collectedOwner, partial.review_id)).toEqual(partial);
});
it("accepts a failed setup prefix without any object call", () => {
  const failed = structuredClone(collectedReview);
  const probe = failed.original_pair.reads[0];
  probe.result.outcome = "failed"; probe.result.problem = "scoped_operation_failed";
  probe.result.data = null; probe.result.send_permits_consumed = 2; probe.result.calls.splice(2);
  probe.result.calls[1] = { ...probe.result.calls[1]!, error_code: "AccessDenied", http_status: 403 };
  Object.assign(failed.receipt.result.data.correlations.probe.reads[0]!, {
    status: "worker_unreported", worker_outcome: "unreported", worker_request_id: null,
  });
  expect(checkedCollectedAuditReview(failed, collectedOwner, failed.review_id)).toEqual(failed);
});
it.each(["status", "request-id", "event-id", "outcome"] as const)("rejects a %s claim for an unreported original call", field => {
  const partial = structuredClone(collectedReview);
  const probe = partial.original_pair.reads[0];
  probe.result.outcome = "failed"; probe.result.problem = "scoped_operation_failed";
  probe.result.data = null; probe.result.send_permits_consumed = 3; probe.result.calls.splice(3);
  const row = partial.receipt.result.data.correlations.probe.reads[0]!;
  Object.assign(row, { status: "worker_unreported", worker_outcome: "unreported", worker_request_id: null });
  expect(checkedCollectedAuditReview(partial, collectedOwner, partial.review_id)).toEqual(partial);
  if (field === "status") row.status = "missing";
  if (field === "request-id") row.worker_request_id = "probe-request-3";
  if (field === "event-id") row.audit_event_ids = ["12345678-1234-1234-1234-123456789abc"];
  if (field === "outcome") row.audit_outcomes = ["service_success"];
  expect(() => checkedCollectedAuditReview(partial, collectedOwner, partial.review_id)).toThrow();
});
it("accepts a failed original read with a validated service error call", () => {
  const failed = structuredClone(collectedReview);
  const legitimate = failed.original_pair.reads[1];
  legitimate.result.outcome = "failed";
  legitimate.result.problem = "scoped_operation_failed";
  legitimate.result.data = null;
  legitimate.result.calls[4] = { ...legitimate.result.calls[4]!, error_code: "InternalError", http_status: 500 };
  Object.assign(failed.receipt.result.data.correlations.legitimate.reads[1]!, { worker_outcome: "other_service_error" });
  expect(checkedCollectedAuditReview(failed, collectedOwner, failed.review_id)).toEqual(failed);
});
it.each(["SignatureDoesNotMatch", "RequestExpired", "AuthorizationHeaderMalformed"] as const)("matches backend credential-error classification for %s", errorCode => {
  const failed = structuredClone(collectedReview);
  const legitimate = failed.original_pair.reads[1];
  legitimate.result.outcome = "failed"; legitimate.result.problem = "scoped_operation_failed";
  legitimate.result.data = null;
  legitimate.result.calls[4] = { ...legitimate.result.calls[4]!, error_code: errorCode, http_status: 403 };
  Object.assign(failed.receipt.result.data.correlations.legitimate.reads[1]!, { worker_outcome: "credential_error" });
  expect(checkedCollectedAuditReview(failed, collectedOwner, failed.review_id)).toEqual(failed);
});
it("rejects collection calls that were not successful HTTP 200 responses", () => {
  const bad = structuredClone(collectedReview);
  bad.receipt.result.calls[3]!.http_status = 500;
  expect(() => checkedCollectedAuditReview(bad, collectedOwner, bad.review_id)).toThrow();
});
it.each(["worker_unreported", "matched", "conflict", "missing", "truncated"] as const)("rejects an existing call with unsupported evidence status %s", status => {
  const bad = structuredClone(collectedReview);
  expect(checkedCollectedAuditReview(bad, collectedOwner, bad.review_id)).toEqual(bad);
  bad.receipt.result.data.correlations.probe.reads[0]!.status = status;
  expect(() => checkedCollectedAuditReview(bad, collectedOwner, bad.review_id)).toThrow();
});
it.each(["from", "through"] as const)("binds the correlation %s to its original request rather than only UTC syntax", field => {
  const bad = structuredClone(collectedReview);
  expect(checkedCollectedAuditReview(bad, collectedOwner, bad.review_id)).toEqual(bad);
  bad.receipt.result.data.correlations.probe.authorized_request_window[field] = "2026-10-11T20:44:51+00:00";
  expect(() => checkedCollectedAuditReview(bad, collectedOwner, bad.review_id)).toThrow();
});
it("preserves microseconds when joining the original request window", () => {
  const value = structuredClone(collectedReview);
  value.original_pair.reads[0].request.deadline = "2026-10-11T20:44:50.123456Z";
  Object.assign(value.receipt.result.data.correlations.probe.authorized_request_window, {
    from: "2026-10-11T20:44:20.123456+00:00", through: "2026-10-11T20:44:50.123456+00:00",
  });
  expect(checkedCollectedAuditReview(value, collectedOwner, value.review_id)).toEqual(value);
  value.receipt.result.data.correlations.probe.authorized_request_window.from = "2026-10-11T20:44:20.123457+00:00";
  expect(() => checkedCollectedAuditReview(value, collectedOwner, value.review_id)).toThrow();
});
it("bounds uploaded files before reading their bytes", async () => {
  const file = fixtureFile(); expect(await auditFiles([file])).toEqual(input.logs);
  await expect(auditFiles([])).rejects.toThrow(); await expect(auditFiles(Array(5).fill(file))).rejects.toThrow();
  const oversized = Object.assign(new File([new Uint8Array(524289)], "oversized.json"), { arrayBuffer: vi.fn() });
  await expect(auditFiles([oversized])).rejects.toThrow(); expect(oversized.arrayBuffer).not.toHaveBeenCalled();
});
it("opens immutable evidence without submitting or claiming independent collection", async () => {
  view(); await userEvent.click(await screen.findByRole("button", { name: "Baseline reads · Probe" }));
  expect(await screen.findByRole("region", { name: "Cloud audit" })).toBeInTheDocument();
  await waitFor(() => expect(screen.getByLabelText("Saved audit review detail")).toBeInTheDocument());
  expect(screen.getByText("Collection not independently verified")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `/runs/${review.source.run_id}`);
  expect(s3AuditApi.save).not.toHaveBeenCalled();
});
it("restores an exact saved review from its source route without submitting", async () => {
  const href = `/s3-access?exercise=${owner}&audit_review=${review.review_id}&audit_digest=${review.review_digest}`;
  view(owner, href);
  await waitFor(() => expect(screen.getByLabelText("Saved audit review detail")).toBeInTheDocument());
  expect(s3AuditApi.read).toHaveBeenCalledWith(owner, review.review_id);
  expect(s3AuditApi.save).not.toHaveBeenCalled();
});
it("publishes only the latest same-owner source after delayed reads resolve out of order", async () => {
  const second = history.reviews.find(row => row.review_id !== review.review_id)!;
  const secondDetail = corpus.cases.map(row => row.review as AuditReview).find(row => row.review_id === second.review_id)!;
  const href = (id: string, digest: string) => `/s3-access?exercise=${owner}&audit_review=${id}&audit_digest=${digest}`;
  const pending = new Map<string, (value: AuditReview) => void>();
  vi.mocked(s3AuditApi.read).mockImplementation((_selectedOwner, id) => new Promise(resolve => { pending.set(id, resolve); }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[href(review.review_id, review.review_digest)]}>
    <RouteSwitcher target={href(second.review_id, second.review_digest)} /><S3Audit owner={owner} />
  </MemoryRouter></QueryClientProvider>);
  await waitFor(() => expect(s3AuditApi.read).toHaveBeenCalled());
  expect(s3AuditApi.read).toHaveBeenCalledWith(owner, review.review_id);
  expect(pending.has(review.review_id)).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Switch audit source" }));
  await waitFor(() => expect(pending.has(second.review_id)).toBe(true));
  await act(async () => { pending.get(review.review_id)!(structuredClone(review)); });
  expect(screen.queryByLabelText("Saved audit review detail")).not.toBeInTheDocument();
  await act(async () => { pending.get(second.review_id)!(structuredClone(secondDetail)); });
  await waitFor(() => expect(screen.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `/runs/${secondDetail.source.run_id}`));
  expect(s3AuditApi.save).not.toHaveBeenCalled();
});
it("does not let a manual history read overwrite a newer exact source route", async () => {
  const sourceA = history.reviews.find(row => row.source.reader === "probe")!;
  const sourceB = history.reviews.find(row => row.review_id !== sourceA.review_id)!;
  const detailA = corpus.cases.map(row => row.review as AuditReview).find(row => row.review_id === sourceA.review_id)!;
  const detailB = corpus.cases.map(row => row.review as AuditReview).find(row => row.review_id === sourceB.review_id)!;
  const href = `/s3-access?exercise=${owner}&audit_review=${sourceB.review_id}&audit_digest=${sourceB.review_digest}`;
  const pending = new Map<string, (value: AuditReview) => void>();
  vi.mocked(s3AuditApi.read).mockImplementation((_selectedOwner, id) => new Promise(resolve => { pending.set(id, resolve); }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/s3-access"]}>
    <RouteSwitcher target={href} /><S3Audit owner={owner} />
  </MemoryRouter></QueryClientProvider>);
  await userEvent.click(await screen.findByRole("button", { name: "Baseline reads · Probe" }));
  await waitFor(() => expect(pending.has(sourceA.review_id)).toBe(true));
  await userEvent.click(screen.getByRole("button", { name: "Switch audit source" }));
  await waitFor(() => expect(pending.has(sourceB.review_id)).toBe(true));
  await act(async () => { pending.get(sourceB.review_id)!(structuredClone(detailB)); });
  await waitFor(() => expect(screen.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `/runs/${detailB.source.run_id}`));
  await act(async () => { pending.get(sourceA.review_id)!(structuredClone(detailA)); });
  expect(screen.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `/runs/${detailB.source.run_id}`);
  expect(s3AuditApi.save).not.toHaveBeenCalled();
});
it("does not let a confirmed import replace a newer exact source route", async () => {
  const sourceB = history.reviews.find(row => row.review_id !== review.review_id)!;
  const detailB = corpus.cases.map(row => row.review as AuditReview).find(row => row.review_id === sourceB.review_id)!;
  const href = `/s3-access?exercise=${owner}&audit_review=${sourceB.review_id}&audit_digest=${sourceB.review_digest}`;
  const pendingRead = new Map<string, (value: AuditReview) => void>();
  let resolveSave!: (value: AuditReview) => void;
  saveAuditPending(marker);
  vi.mocked(s3AuditApi.read).mockImplementation((_selectedOwner, id) => new Promise(resolve => { pendingRead.set(id, resolve); }));
  vi.mocked(s3AuditApi.save).mockReturnValue(new Promise(resolve => { resolveSave = resolve; }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/s3-access"]}>
    <RouteSwitcher target={href} /><S3Audit owner={owner} />
  </MemoryRouter></QueryClientProvider>);
  await userEvent.upload(await screen.findByLabelText("Audit files"), fixtureFile());
  await userEvent.click(screen.getByRole("button", { name: "Retry original import" }));
  await waitFor(() => expect(s3AuditApi.save).toHaveBeenCalled());
  await userEvent.click(screen.getByRole("button", { name: "Switch audit source" }));
  await waitFor(() => expect(pendingRead.has(sourceB.review_id)).toBe(true));
  await act(async () => { pendingRead.get(sourceB.review_id)!(structuredClone(detailB)); });
  await waitFor(() => expect(screen.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `/runs/${detailB.source.run_id}`));
  await act(async () => { resolveSave(structuredClone(review)); });
  expect(screen.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `/runs/${detailB.source.run_id}`);
  expect(readAuditPending(owner)).toBeNull();
});
it("fails closed when a source route or fetched review digest is stale", async () => {
  const href = `/s3-access?exercise=${owner}&audit_review=${review.review_id}&audit_digest=${review.review_digest}`;
  const changedHistory = structuredClone(history);
  changedHistory.reviews.find(row => row.review_id === review.review_id)!.review_digest = `sha256:${"f".repeat(64)}`;
  vi.mocked(s3AuditApi.list).mockResolvedValue(changedHistory);
  view(owner, href);
  expect(await screen.findByText("The saved audit review no longer matches this source link.")).toBeInTheDocument();
  expect(s3AuditApi.read).not.toHaveBeenCalled();

  cleanup();
  vi.mocked(s3AuditApi.list).mockResolvedValue(structuredClone(history));
  vi.mocked(s3AuditApi.read).mockResolvedValue({ ...structuredClone(review), review_digest: `sha256:${"f".repeat(64)}` });
  view(owner, href);
  expect(await screen.findByText("The saved review does not match its history entry.")).toBeInTheDocument();
  expect(screen.queryByLabelText("Saved audit review detail")).not.toBeInTheDocument();
});
it("refuses an incomplete source route without opening any review", async () => {
  view(owner, `/s3-access?exercise=${owner}&audit_review=${review.review_id}`);
  expect(await screen.findByText("The saved audit source link is incomplete or changed.")).toBeInTheDocument();
  expect(s3AuditApi.read).not.toHaveBeenCalled();
});
it("opens collected history with both original links and bounded retrieval claims", async () => {
  const v2 = collectedHistory();
  v2.workflow_job_id = collectedOwner;
  vi.mocked(s3AuditApi.list).mockResolvedValue(v2);
  vi.mocked(s3AuditApi.read).mockResolvedValue(structuredClone(collectedReview));
  view(collectedOwner);
  await userEvent.click(await screen.findByRole("button", { name: "Baseline reads · Collected audit" }));
  await waitFor(() => expect(screen.getByLabelText("Saved audit review detail")).toBeInTheDocument());
  expect(screen.getAllByText("Authenticated source retrieval").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Integrity unverified").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Delivery incomplete").length).toBeGreaterThan(0);
  expect(screen.getByRole("link", { name: "Probe original run evidence" })).toHaveAttribute("href", `/runs/${collectedReview.original_pair.reads[0].run_id}`);
  expect(screen.getByRole("link", { name: "Legitimate original run evidence" })).toHaveAttribute("href", `/runs/${collectedReview.original_pair.reads[1].run_id}`);
  expect(s3AuditApi.save).not.toHaveBeenCalled();
});
it("restores an uncertain save after reload without retaining file bytes", async () => {
  saveAuditPending(marker); expect(localStorage.getItem(`bluefire.s3.audit.pending.v1.${owner}`)).not.toContain(input.logs[0]!.data);
  view(); await userEvent.click(await screen.findByRole("button", { name: "Check saved review" }));
  await waitFor(() => expect(readAuditPending(owner)).toBeNull());
  expect(s3AuditApi.read).toHaveBeenCalledWith(owner, review.review_id); expect(s3AuditApi.save).not.toHaveBeenCalled();
});
it("retries only the exact pending input and clears it after confirmation", async () => {
  saveAuditPending(marker); view();
  await userEvent.upload(await screen.findByLabelText("Audit files"), fixtureFile());
  await userEvent.click(screen.getByRole("button", { name: "Retry original import" }));
  await waitFor(() => expect(s3AuditApi.save).toHaveBeenCalledExactlyOnceWith(owner, input));
  await waitFor(() => expect(readAuditPending(owner)).toBeNull());
});
it("keeps the original marker on a changed file or lost response", async () => {
  saveAuditPending(marker); view();
  const changed = Object.assign(new File(["{}"], "changed.json"), { arrayBuffer: async () => new TextEncoder().encode("{}").buffer });
  await userEvent.upload(await screen.findByLabelText("Audit files"), changed); await userEvent.click(screen.getByRole("button", { name: "Retry original import" }));
  expect(await screen.findByText(/differ from the pending import/)).toBeInTheDocument(); expect(s3AuditApi.save).not.toHaveBeenCalled();
  vi.mocked(s3AuditApi.save).mockRejectedValueOnce(new Error("Response lost"));
  await userEvent.upload(screen.getByLabelText("Audit files"), fixtureFile()); await userEvent.click(screen.getByRole("button", { name: "Retry original import" }));
  expect(await screen.findByText("Response lost")).toBeInTheDocument(); expect(readAuditPending(owner)).toEqual(marker);
});
it("will not clear a pending marker for a different saved import", async () => {
  saveAuditPending(marker); vi.mocked(s3AuditApi.read).mockResolvedValue({ ...review, input_digest: "sha256:" + "f".repeat(64) }); view();
  await userEvent.click(await screen.findByRole("button", { name: "Check saved review" }));
  expect(await screen.findByText(/does not match the original import/)).toBeInTheDocument(); expect(readAuditPending(owner)).toEqual(marker);
});
it("discards only the local reminder, never saved server history", async () => {
  saveAuditPending(marker); view(); await userEvent.click(await screen.findByRole("button", { name: "Start another review" }));
  expect(readAuditPending(owner)).toBeNull(); expect(s3AuditApi.save).not.toHaveBeenCalled(); expect(await screen.findByRole("button", { name: "Baseline reads · Probe" })).toBeInTheDocument();
});
it("does not clear another mounted workspace's marker when an old response arrives", async () => {
  saveAuditPending(marker); let resolve!: (r: AuditReview) => void; vi.mocked(s3AuditApi.read).mockReturnValue(new Promise(r => { resolve = r; }));
  const first = view(); await userEvent.click(await screen.findByRole("button", { name: "Check saved review" })); first.unmount();
  await act(async () => { resolve(review); }); expect(readAuditPending(owner)).toEqual(marker);
});
