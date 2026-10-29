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

it.each(["owner", "attempt", "run", "record", "current", "nested-summary", "omitted-attempt", "duplicate-attempt", "hidden-truncation"])("refuses %s mismatch instead of presenting different saved evidence", (fault) => {
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
  if (fault === "omitted-attempt") raw.attempts.pop();
  if (fault === "duplicate-attempt") raw.attempts[1] = structuredClone(row);
  if (fault === "hidden-truncation") row.findings_total = 12;
  expect(() => checkedCompositionKnowledge(value, objective, selected)).toThrow(/selected saved attempts/);
});

it("does not send duplicate, empty or over-limit queries", async () => {
  const { objective } = knowledgeFixture(9);
  const ids = objective.attempts.map(attempt => attempt.request.composition_attempt.attempt_id);
  for (const selected of [[], [ids[0]!, ids[0]!], ids]) await expect(compositionKnowledgeApi.read(objective, selected)).rejects.toThrow();
  expect(request).not.toHaveBeenCalled();
});
