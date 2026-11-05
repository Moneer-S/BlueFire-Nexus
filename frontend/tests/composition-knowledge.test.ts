import { afterEach, expect, it, vi } from "vitest";
import { request } from "../src/lib/api";
import { checkedCompositionKnowledge, compositionKnowledgeApi } from "../src/lib/composition-knowledge";
import { knowledgeFixture } from "./composition-knowledge-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn() }));
afterEach(() => vi.clearAllMocks());

it("reads exact saved attempts without invoking an execution endpoint", async () => {
  const { objective, value } = knowledgeFixture();
  const selected = objective.attempts.map(attempt => attempt.request.composition_attempt.attempt_id);
  vi.mocked(request).mockResolvedValue(value);
  const result = await compositionKnowledgeApi.read(objective, selected);
  expect(request).toHaveBeenCalledOnce();
  expect(request).toHaveBeenCalledWith(`/composition/objectives/${objective.owner.job_id}/knowledge`, { method: "POST", body: JSON.stringify({ schema_version: "bluefire.composition-knowledge-query.v1", attempt_ids: selected }) });
  expect(result.attempts[0]?.run_status).toBe("failed");
  expect(result.attempts[0]?.findings[0]?.applicability.status).toBe("historical_only");
});

it.each(["owner", "attempt", "run", "record", "current", "nested-summary", "unknown-summary", "omitted-attempt", "duplicate-attempt", "hidden-truncation"])("refuses %s mismatch instead of presenting different saved evidence", (fault) => {
  const { objective, value } = knowledgeFixture();
  const selected = objective.attempts.map(attempt => attempt.request.composition_attempt.attempt_id);
  const raw = value as unknown as { owner_id: string; attempts: Array<Record<string, unknown>> };
  const row = raw.attempts[0]!;
  const finding = (row.findings as Array<Record<string, unknown>>)[0]!;
  if (fault === "owner") raw.owner_id = `job-${"f".repeat(32)}`;
  if (fault === "attempt") row.attempt_id = `attempt-${"f".repeat(32)}`;
  if (fault === "run") row.run_id = "run-another";
  if (fault === "record") (finding.record_ref as Record<string, unknown>).evidence_id = "evidence-other";
  if (fault === "current") (finding.applicability as Record<string, unknown>).status = "current";
  if (fault === "nested-summary") finding.summary = { raw_artifact: { records: ["private body"] } };
  if (fault === "unknown-summary") finding.summary = { path: "generated/private-records.jsonl" };
  if (fault === "omitted-attempt") raw.attempts.pop();
  if (fault === "duplicate-attempt") raw.attempts[1] = structuredClone(row);
  if (fault === "hidden-truncation") row.findings_total = 12;
  expect(() => checkedCompositionKnowledge(value, objective, selected)).toThrow(/selected saved attempts/);
});

it.each([
  ["observed_filesystem", { size_bytes: 1, sha256: `sha256:${"1".repeat(64)}`, permission_status: "available", effective_access: "not_evaluated", permission_mode_octal: "0640", group_write_bit: false, other_write_bit: false, non_owner_write_bit: false }],
  ["observed_collection", { size_bytes: 1, sha256: "2".repeat(64), container: "jsonl", record_count: 4, redacted_record_count: 1, retained_record_count: 3, empty_record_count: 0 }],
  ["observed_process_snapshot", { process_id: 40, parent_process_id: 39, platform: "linux" }],
  ["observed_receiver_binding", { sha256: `sha256:${"3".repeat(64)}`, bytes_received: 17, receiver_process_id: 32 }],
  ["runner_result", { runner_status: "success", reported_outcome: "permission_denied", reported_reader: "non_owner", reported_mode: "0600", reported_sha256: "4".repeat(64), reported_record_count: 4, reported_control_revision: 2 }],
  ["evidence_gap", { observation_available: false }],
  ["record_metadata", {}],
] as const)("accepts the complete %s safe summary projection", (semanticKind, summary) => {
  const { objective, value } = knowledgeFixture();
  const selected = objective.attempts.map(attempt => attempt.request.composition_attempt.attempt_id);
  const finding = value.attempts[0]!.findings[0]!;
  finding.semantic_kind = semanticKind;
  finding.summary = summary;
  expect(checkedCompositionKnowledge(value, objective, selected)).toBe(value);
});

it("does not send duplicate, empty or over-limit queries", async () => {
  const { objective } = knowledgeFixture(9);
  const ids = objective.attempts.map(attempt => attempt.request.composition_attempt.attempt_id);
  for (const selected of [[], [ids[0]!, ids[0]!], ids]) await expect(compositionKnowledgeApi.read(objective, selected)).rejects.toThrow();
  expect(request).not.toHaveBeenCalled();
});
