import { webcrypto } from "node:crypto";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import corpus from "../../tests_platform/fixtures/s3_audit_reviews_v1.json";
import { auditFiles, auditInputDigest, checkedAuditHistory, checkedAuditReview, readAuditPending, s3AuditApi, saveAuditPending, type AuditHistory, type AuditInput, type AuditReview } from "../src/lib/s3-audit";
import { S3Audit } from "../src/pages/S3Audit";

const history = corpus.history as AuditHistory;
const sample = corpus.cases[0]!;
const review = sample.review as AuditReview;
const input = sample.input as AuditInput;
const owner = history.workflow_job_id;
const marker = { owner, submission_id: input.submission_id, run_id: input.run_id, delivery_state: input.delivery_state, input_digest: review.input_digest };
const fixtureFile = () => { const bytes = Uint8Array.from(atob(input.logs[0]!.data), c => c.charCodeAt(0)); return Object.assign(new File([bytes], "audit.json.gz"), { arrayBuffer: async () => bytes.buffer }); };
function view(selectedOwner = owner) { const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 }, mutations: { retry: false } } }); return render(<QueryClientProvider client={client}><MemoryRouter><S3Audit owner={selectedOwner} /></MemoryRouter></QueryClientProvider>); }
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
it("bounds uploaded files before reading their bytes", async () => {
  const file = fixtureFile(); expect(await auditFiles([file])).toEqual(input.logs);
  await expect(auditFiles([])).rejects.toThrow(); await expect(auditFiles(Array(5).fill(file))).rejects.toThrow();
  const oversized = Object.assign(new File([new Uint8Array(524289)], "oversized.json"), { arrayBuffer: vi.fn() });
  await expect(auditFiles([oversized])).rejects.toThrow(); expect(oversized.arrayBuffer).not.toHaveBeenCalled();
});
it("opens immutable evidence without submitting or claiming independent collection", async () => {
  view(); await userEvent.click(await screen.findByRole("button", { name: "Baseline reads · Probe" }));
  expect(await screen.findByRole("region", { name: "Imported cloud audit" })).toBeInTheDocument();
  await waitFor(() => expect(screen.getByLabelText("Saved audit review detail")).toBeInTheDocument());
  expect(screen.getByText("Collection not independently verified")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `/runs/${review.source.run_id}`);
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
