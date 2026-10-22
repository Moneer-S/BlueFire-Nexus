import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import corpus from "../../tests_platform/fixtures/s3_audit_reviews_v1.json" with { type: "json" };
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { S3Audit } from "../src/pages/S3Audit";
import { api } from "../src/lib/api";
import * as auditContext from "../src/lib/audit-assistance";
import { checkedAuditHistory, checkedAuditReview, s3AuditApi, type AuditHistory, type AuditReview } from "../src/lib/s3-audit";
import { assistanceJobId, matchesAssistanceReceipt, readAssistanceHistory, readAssistanceReceipt, type AssistanceEnvelope, type AssistanceRequest } from "../src/lib/assistance";
import { AssistanceProvider } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";

const owner = corpus.history.workflow_job_id;
const review = checkedAuditReview(corpus.cases[0]!.review as AuditReview, owner, corpus.cases[0]!.review.review_id);
if (review.schema_version !== "bluefire.s3-audit-review.v1") throw new Error("Expected imported fixture");
const selected: auditContext.AuditAssistanceSelection = { kind: "s3_audit_review", workflow_job_id: owner, review_id: review.review_id, review_digest: review.review_digest };
const context = auditContext.checkedAuditAssistanceContext({ schema_version: "bluefire.assistance-context.v1", context_digest: `sha256:${"a".repeat(64)}`, selected, capabilities: [], analysis_only: true, limitations: ["Operator imports do not independently prove collection or effective access."], reference_summary: {
  phase: review.source.phase, runner_source: review.source.provenance, cleanup: review.source.cleanup, collection_provenance: "operator_import",
  reported_delivery_state: review.correlation.audit.reported_delivery_state, source_event_count: review.correlation.audit.source_event_count, counts: review.correlation.audit.counts,
  reads: review.correlation.reads.map(row => ({ purpose: row.purpose, reader: row.reader, status: row.status, worker_outcome: row.worker_outcome, matched_event_count: row.audit_event_ids.length, full_object_bytes_proven: false })),
  independent_collection_proven: false, effective_access_claim: false,
} }, selected);
const provider = { provider_id: "audit-provider", kind: "chat_completions", model: "unit-model" };

function envelope(body: AssistanceRequest): AssistanceEnvelope {
  if (!("selection" in body)) throw new Error("Expected saved audit selection");
  return { job: { schema_version: "bluefire.job.v1", kind: "assistance.turn", job_id: assistanceJobId(body.submission_id), state: "completed", request: { submitted_request: body }, progress: {} }, turn: { schema_version: "bluefire.assistance-turn.v1", status: "completed", can_start_new_turn: true, message: "The imported record matches the synthetic read. Collection is not independently proven.", context_digest: body.context_digest, selected: body.selection, plan: [], active_child: null, next_action: null, results: [], continuation: null, limitations: context.limitations } };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const tree = (showAudit = true) => <QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider>{showAudit ? <S3Audit owner={owner} /> : <div>Another view</div>}<ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>;
  const view = render(tree());
  return { ...view, leaveAuditView: () => view.rerender(tree(false)) };
}

it.each(["assist", "auto"] as const)("opens the actual saved audit in %s and retains one read-only request across reload", async autonomy => {
  vi.spyOn(s3AuditApi, "list").mockResolvedValue(checkedAuditHistory(corpus.history as AuditHistory, owner));
  vi.spyOn(s3AuditApi, "read").mockResolvedValue(review);
  const save = vi.spyOn(s3AuditApi, "save");
  const get = vi.spyOn(auditContext, "auditAssistanceContext").mockResolvedValue(context);
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async body => envelope(body));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => envelope(readAssistanceReceipt()!));
  const view = mount(), user = userEvent.setup();
  await user.click((await screen.findAllByRole("button", { name: /Baseline reads.*Probe/ }))[0]!);
  await user.click(await screen.findByRole("button", { name: "Explain review" }));
  await waitFor(() => expect(get).toHaveBeenCalledWith(selected));
  expect(screen.getByText("Operator-imported evidence. Collection is not independently verified. Explanation only; no cloud operations or changes.")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("Development activity")).not.toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("AI mode"), autonomy);
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), "Explain the missing evidence.");
  await user.dblClick(screen.getByRole("button", { name: "Start work" }));
  await screen.findByText("The imported record matches the synthetic read. Collection is not independently proven.");
  expect(submit).toHaveBeenCalledTimes(1);
  const body = submit.mock.calls[0]![0];
  expect(body).toMatchObject({ selection: selected, context_digest: context.context_digest, autonomy, provider_id: provider.provider_id });
  expect(screen.getByRole("link", { name: "Saved cloud exercise" })).toHaveAttribute("href", `/s3-access?exercise=${owner}`);
  expect(screen.queryByRole("link", { name: /Source rule and evidence/ })).not.toBeInTheDocument();
  expect(JSON.stringify(body)).not.toContain(corpus.cases[0]!.input.logs[0]!.data);
  expect(readAssistanceHistory()).toContainEqual(body);
  expect(save).not.toHaveBeenCalled();
  view.leaveAuditView();
  expect(await screen.findByText("The imported record matches the synthetic read. Collection is not independently proven.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Saved cloud exercise" })).toHaveAttribute("href", `/s3-access?exercise=${owner}`);
  expect(submit).toHaveBeenCalledTimes(1);
  view.unmount();
  mount();
  await screen.findByText("The imported record matches the synthetic read. Collection is not independently proven.");
  expect(submit).toHaveBeenCalledTimes(1);
});

it("ends audit selection ownership when leaving its detail without losing the draft or starting work", async () => {
  vi.spyOn(s3AuditApi, "list").mockResolvedValue(checkedAuditHistory(corpus.history as AuditHistory, owner));
  vi.spyOn(s3AuditApi, "read").mockResolvedValue(review);
  const get = vi.spyOn(auditContext, "auditAssistanceContext").mockResolvedValue(context);
  const submit = vi.spyOn(api, "submitAssistance");
  const view = mount(), user = userEvent.setup();
  await user.click((await screen.findAllByRole("button", { name: /Baseline reads.*Probe/ }))[0]!);
  await user.click(await screen.findByRole("button", { name: "Explain review" }));
  await waitFor(() => expect(get).toHaveBeenCalledWith(selected));
  await user.selectOptions(screen.getByLabelText("AI mode"), "assist");
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  const draft = "Explain the unresolved collection evidence.";
  await user.type(screen.getByLabelText("What would you like to do?"), draft);
  expect(screen.getByRole("button", { name: "Start work" })).toBeEnabled();
  const contextReads = get.mock.calls.length;

  view.leaveAuditView();
  expect(screen.getByText("Another view")).toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Previous selection" })).toHaveTextContent("This selection is from another view. Reopen its source before starting new work. Your draft is preserved.");
  expect(screen.getByLabelText("What would you like to do?")).toHaveValue(draft);
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(get).toHaveBeenCalledTimes(contextReads);
  await user.click(screen.getByRole("button", { name: "Start work" }));
  expect(submit).not.toHaveBeenCalled();
  expect(readAssistanceReceipt()).toBeUndefined();
});

it("refuses changed selections, dispatch capabilities, and operation-bearing audit receipts", () => {
  expect(auditContext.checkedAuditAssistanceContext(context, selected)).toEqual(context);
  for (const changed of [{ ...selected, review_digest: `sha256:${"b".repeat(64)}` }, { ...selected, review_id: "not-a-job" }]) expect(() => auditContext.checkedAuditAssistanceContext(context, changed)).toThrow();
  expect(() => auditContext.checkedAuditAssistanceContext({ ...context, analysis_only: undefined }, selected)).toThrow();
  expect(() => auditContext.checkedAuditAssistanceContext({ ...context, capabilities: [{ id: "graph.propose_and_validate", title: "Wrong", available: true, supported_autonomy: ["assist"], reason: "Wrong", native_path: "/builder" }] }, selected)).toThrow();
  const body: AssistanceRequest = { submission_id: "01234567-89ab-4def-8123-456789abcdef", context_digest: context.context_digest, selection: selected, message: "Explain", autonomy: "assist", provider_id: provider.provider_id };
  const valid = envelope(body);
  expect(matchesAssistanceReceipt(valid, body)).toBe(true);
  expect(matchesAssistanceReceipt({ ...valid, turn: { ...valid.turn, plan: [{ step_id: "step-1", capability_id: "graph.propose_and_validate", title: "Wrong", detector_ref: "none", reason: "Wrong" }] } }, body)).toBe(false);
});

it("encodes and parses an exact review source route while rejecting partial or repeated bindings", () => {
  const href = auditContext.auditReviewSourceHref(selected);
  const query = new URL(href, "http://localhost").searchParams;
  expect(auditContext.auditReviewSourceSelection(owner, query)).toEqual(selected);
  expect(() => auditContext.auditReviewSourceHref({ ...selected, review_digest: "bad" })).toThrow();
  expect(() => auditContext.auditReviewSourceSelection(owner, new URLSearchParams({
    exercise: owner, audit_review: review.review_id,
  }))).toThrow();
  expect(() => auditContext.auditReviewSourceSelection(owner, new URLSearchParams([
    ["exercise", owner], ["audit_review", review.review_id], ["audit_review", review.review_id],
    ["audit_digest", review.review_digest],
  ]))).toThrow();
  expect(() => auditContext.auditReviewSourceSelection("job-" + "f".repeat(32), query)).toThrow();
});
