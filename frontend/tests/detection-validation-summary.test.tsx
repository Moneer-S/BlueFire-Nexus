import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { DetectionValidationSummary } from "../src/components/DetectionValidationSummary";
import { recordedDetectionSummary } from "../src/lib/detection-validation-summary";
import type { DetectionResource } from "../src/types";

const id = `detection-${"a".repeat(20)}`;
const digest = `sha256:${"b".repeat(64)}`;
function saved(): DetectionResource {
  return { kind: "detections", id, status: "benign_evaluated", digest, created_at: "2026-10-25", updated_at: "2026-10-25", document: {
    candidate_id: id, revision: 1, definition_digest: digest, state: "benign_evaluated", target_language: "sqlite",
    parser_backend: { name: "SQLite bounded executor", version: "3.46" },
    malicious_fixture_ids: ["positive-a", "positive-b"], benign_fixture_ids: ["benign-a", "benign-b", "benign-c"],
    match_count: 22, benign_match_count: 0,
    validation: { source_rule_executed: true, query_sha256: digest, executed_query_sha256: digest,
      evaluated_fixture_ids: ["positive-a", "positive-b"], matched_fixture_ids: ["positive-a"],
      benign_evaluated_fixture_ids: ["benign-a", "benign-b", "benign-c"], benign_matched_fixture_ids: [],
      last_execution: { fixture_ids: ["observed-a"], matched_fixture_ids: ["observed-a"] } },
  } };
}

it("uses separate recorded fixture populations instead of cumulative matches or last observed execution", () => {
  const resource = saved(), before = structuredClone(resource);
  expect(recordedDetectionSummary(resource, id)).toEqual({ revision: 1, parser: "Parsed", malicious: "1 / 2 matched", benign: "0 / 3 matched" });
  expect(resource).toEqual(before);
});

it("retains a recorded zero-positive result without inventing a passing fixture check", () => {
  const resource = saved();
  resource.document.validation!.matched_fixture_ids = [];
  resource.document.state = "rejected";
  expect(recordedDetectionSummary(resource, id).malicious).toBe("0 / 2 matched");
});

it.each(["missing", "duplicate", "foreign", "wrong-population", "query-drift"])("leaves %s fixture attribution unavailable", condition => {
  const resource = saved(), validation = resource.document.validation!;
  if (condition === "missing") delete validation.evaluated_fixture_ids;
  if (condition === "duplicate") validation.matched_fixture_ids = ["positive-a", "positive-a"];
  if (condition === "foreign") validation.matched_fixture_ids = ["another-record"];
  if (condition === "wrong-population") validation.evaluated_fixture_ids = ["observed-a"];
  if (condition === "query-drift") validation.executed_query_sha256 = `sha256:${"c".repeat(64)}`;
  expect(recordedDetectionSummary(resource, id).malicious).toBe("Unavailable");
});

it("uses YARA's recorded source binding and keeps its benign matches distinct", () => {
  const resource = saved();
  resource.document.target_language = "yara";
  resource.document.parser_backend = { name: "YARA-Python", version: "4.5" };
  Object.assign(resource.document.validation!, { source_sha256: digest, executed_source_sha256: digest, benign_matched_fixture_ids: ["benign-b"] });
  expect(recordedDetectionSummary(resource, id)).toMatchObject({ parser: "Parsed", malicious: "1 / 2 matched", benign: "1 / 3 matched" });
});

it("does not divide internal observed-plus-fixture matches by the malicious fixture population", () => {
  const resource = saved();
  Object.assign(resource.document, { target_language: "internal", parser_backend: { name: "bluefire-structured-matcher", version: "1.0" },
    match_count: 1, lifecycle_history: [{ action: "exercise_fixtures" }, { action: "evaluate_benign" }] });
  resource.document.validation = { source_rule_executed: true, fixture_backend: "bluefire-structured-matcher", benign_fixture_backend: "bluefire-structured-matcher" };
  expect(recordedDetectionSummary(resource, id)).toMatchObject({ malicious: "1 / 2 matched", benign: "0 / 3 matched" });
  resource.document.lifecycle_history!.push({ action: "exercise_observed" });
  expect(recordedDetectionSummary(resource, id)).toMatchObject({ malicious: "Unavailable", benign: "0 / 3 matched" });
});

it("keeps structural-only and failed parser checks separate from authoritative parsing", () => {
  const resource = saved();
  resource.document.target_language = "spl";
  resource.document.state = "hypothesis";
  resource.document.validation = { syntax_checked: true, authoritative_backend_validated: false };
  expect(recordedDetectionSummary(resource, id)).toMatchObject({ parser: "Structural only", malicious: "Unavailable", benign: "Unavailable" });
  resource.document.lifecycle_history = [{ action: "parse", outcome: "rejected" }];
  expect(recordedDetectionSummary(resource, id).parser).toBe("Failed");
});

it("requires the selected saved revision identity rather than reusing a run-linked or older selection", () => {
  expect(recordedDetectionSummary(undefined, id).malicious).toBe("Unavailable");
  expect(recordedDetectionSummary(saved(), "different-candidate").revision).toBeUndefined();
  const resource = saved();
  resource.document.revision = undefined;
  expect(recordedDetectionSummary(resource, id).parser).toBe("Unavailable");
});

it("links keyboard review to the existing Fixtures action and identifies unvalidated rule edits", async () => {
  const onFixtures = vi.fn();
  const view = render(<DetectionValidationSummary resource={saved()} selectedId={id} sourceEdited onFixtures={onFixtures} />);
  const summary = within(screen.getByRole("region", { name: "Recorded validation summary" }));
  expect(summary.getByText("Saved revision checks · v1")).toBeVisible();
  expect(summary.getByText("Saved revision only; current rule edits are not covered.")).toBeVisible();
  summary.getByRole("button", { name: "Review fixtures" }).focus();
  await userEvent.setup().keyboard("{Enter}");
  expect(onFixtures).toHaveBeenCalledTimes(1);
  const next = saved();
  next.id = `detection-${"d".repeat(20)}`;
  next.document.candidate_id = next.id;
  next.document.revision = 2;
  next.document.state = "parsed";
  next.document.malicious_fixture_ids = [];
  next.document.benign_fixture_ids = [];
  next.document.validation = { query_compiled: true, source_rule_executed: false };
  view.rerender(<DetectionValidationSummary resource={next} selectedId={next.id} sourceEdited={false} onFixtures={onFixtures} />);
  expect(summary.getByText("Saved revision checks · v2")).toBeVisible();
  expect(summary.getAllByText("Unavailable")).toHaveLength(2);
  expect(summary.queryByText("1 / 2 matched")).not.toBeInTheDocument();
});
