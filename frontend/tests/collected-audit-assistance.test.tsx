import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { S3Audit } from "../src/pages/S3Audit";
import { api } from "../src/lib/api";
import * as auditContext from "../src/lib/audit-assistance";
import { s3AuditApi } from "../src/lib/s3-audit";
import { assistanceJobId, readAssistanceReceipt, type AssistanceEnvelope, type AssistanceRequest } from "../src/lib/assistance";
import { AssistanceProvider } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";
import { collectedReview, collectedSummary } from "./s3-audit-collected-fixture";

const owner = collectedReview.workflow_job_id;
const selected: auditContext.AuditAssistanceSelection = { kind: "s3_audit_review", workflow_job_id: owner, review_id: collectedReview.review_id, review_digest: collectedReview.review_digest };
const data = collectedReview.receipt.result.data;
const context = auditContext.checkedAuditAssistanceContext({
  schema_version: "bluefire.assistance-context.v1", selected, context_digest: `sha256:${"a".repeat(64)}`,
  analysis_only: true, capabilities: [], limitations: ["Authenticated retrieval does not prove integrity, complete delivery or effective access."],
  reference_summary: {
    schema_version: "bluefire.s3-collected-audit-summary.v1", phase: collectedReview.phase,
    runner_source: "runner_reported", cleanup: "verified", collection_provenance: "authenticated_source_retrieval",
    reported_delivery_state: data.delivery_state, source_event_count: data.usage.events, collected_file_count: data.usage.files,
    discovery_truncated: data.discovery.truncated,
    reads: [...data.correlations.probe.reads, ...data.correlations.legitimate.reads].map(row => ({
      purpose: row.purpose, reader: row.reader, status: row.status, worker_outcome: row.worker_outcome,
      matched_event_count: row.audit_event_ids.length, full_object_bytes_proven: false,
    })),
    raw_bytes_retained: false, log_integrity_proven: false, independent_collection_proven: false, effective_access_claim: false,
  },
}, selected);
const provider = { provider_id: "collected-audit-provider", kind: "chat_completions", model: "unit-model" };
const answer = "The authenticated retrieval remains incomplete. Integrity and effective access are unproven.";

function envelope(body: AssistanceRequest): AssistanceEnvelope {
  if (!("selection" in body)) throw new Error("Expected selected review");
  return {
    job: { schema_version: "bluefire.job.v1", kind: "assistance.turn", job_id: assistanceJobId(body.submission_id), state: "completed", request: { submitted_request: body }, progress: {} },
    turn: { schema_version: "bluefire.assistance-turn.v1", status: "completed", can_start_new_turn: true, message: answer,
      context_digest: body.context_digest, selected: body.selection, plan: [], active_child: null, next_action: null, results: [], continuation: null, limitations: context.limitations },
  };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider><S3Audit owner={owner} /><ExperimentAssistant providers={[provider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
}

it.each(["assist", "auto"] as const)("explains the exact collected review in %s without dispatch or reload duplication", async autonomy => {
  vi.spyOn(s3AuditApi, "list").mockResolvedValue({ schema_version: "bluefire.s3-audit-reviews.v2", workflow_job_id: owner,
    reads: [], reviews: [], collections: [collectedSummary], maximum_collections: 2, maximum_reviews: 32, maximum_input_bytes: 524288, maximum_expanded_bytes: 1048576 });
  vi.spyOn(s3AuditApi, "read").mockResolvedValue(collectedReview);
  const save = vi.spyOn(s3AuditApi, "save");
  const get = vi.spyOn(auditContext, "auditAssistanceContext").mockResolvedValue(context);
  const submit = vi.spyOn(api, "submitAssistance").mockImplementation(async body => envelope(body));
  vi.spyOn(api, "assistanceTurn").mockImplementation(async () => envelope(readAssistanceReceipt()!));
  const view = mount(), user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: /Collected audit/ }));
  await user.click(await screen.findByRole("button", { name: "Explain review" }));
  await waitFor(() => expect(get).toHaveBeenCalledWith(selected));
  expect(screen.getByText("Authenticated source retrieval. Integrity and delivery completeness are not established. Explanation only; no cloud operations or changes.")).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
  await user.selectOptions(screen.getByLabelText("AI mode"), autonomy);
  await user.selectOptions(screen.getByLabelText("Provider"), provider.provider_id);
  await user.type(screen.getByLabelText("What would you like to do?"), "Explain the collected evidence.");
  await user.dblClick(screen.getByRole("button", { name: "Start work" }));
  await screen.findByText(answer);
  expect(submit).toHaveBeenCalledTimes(1);
  const body = submit.mock.calls[0]![0];
  expect(body).toMatchObject({ selection: selected, context_digest: context.context_digest, autonomy });
  expect(Object.keys(body).sort()).toEqual(["autonomy", "context_digest", "message", "provider_id", "selection", "submission_id"]);
  expect(save).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: /Approve|Execute/ })).not.toBeInTheDocument();
  view.unmount();
  mount();
  await screen.findByText(answer);
  expect(submit).toHaveBeenCalledTimes(1);
});

it.each([
  { schema_version: "bluefire.s3-collected-audit-summary.v2" },
  { collection_provenance: "operator_import" },
  { reported_delivery_state: "complete" },
  { runner_source: "synthetic" },
  { cleanup: "unknown" },
  { phase: ["baseline"] },
  { source_event_count: 501 },
  { source_event_count: -1 },
  { collected_file_count: 5 },
  { collected_file_count: true },
  { discovery_truncated: true, reported_delivery_state: "incomplete" },
  { raw_bytes_retained: true },
  { log_integrity_proven: true },
  { effective_access_claim: true },
  { independent_collection_proven: true },
  { receipt: collectedReview.receipt },
])("rejects unsupported collected context summary %j", changed => {
  expect(() => auditContext.checkedAuditAssistanceContext({ ...context, reference_summary: { ...context.reference_summary, ...changed } }, selected)).toThrow();
});

it("requires three ordered bounded read summaries and the exact selected review", () => {
  const summary = context.reference_summary;
  expect(auditContext.checkedAuditAssistanceContext(context, selected)).toEqual(context);
  for (const reads of [summary.reads.slice(0, 2), [...summary.reads].reverse(), [...summary.reads, summary.reads[0]], summary.reads.map(row => ({ ...row, matched_event_count: 501 })), summary.reads.map(row => ({ ...row, full_object_bytes_proven: true })), summary.reads.map(row => ({ ...row, audit_event_ids: [] }))]) {
    expect(() => auditContext.checkedAuditAssistanceContext({ ...context, reference_summary: { ...summary, reads } }, selected)).toThrow();
  }
  expect(() => auditContext.checkedAuditAssistanceContext(context, { ...selected, review_digest: `sha256:${"b".repeat(64)}` })).toThrow();
  expect(() => auditContext.checkedAuditAssistanceContext({ ...context, reference_summary: undefined }, selected)).toThrow();
});
