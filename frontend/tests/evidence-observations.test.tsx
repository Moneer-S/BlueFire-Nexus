import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { EvidenceRecords } from "../src/components/EvidenceRecords";
import type { EvidenceRecord } from "../src/types";

const digest = "a".repeat(64);
function metadata(): EvidenceRecord {
  const fields = { path: "staged/bundle.jsonl", size_bytes: 840, sha256: digest };
  return { evidence_id: "evidence-file", provenance: "observed", step_id: "stage_records",
    producer: "collector.filesystem.sandbox.v1", behavior_id: "sandbox.collection.stage.v1", confidence: 1,
    content: { ...fields, artifact_type: "collector_observation", observation_kind: "filesystem", observed_fields: { ...fields } },
    limitations: ["independent filesystem metadata and digest observation only"] };
}
function semantics(container: string): EvidenceRecord {
  const record = metadata();
  const fields = { path: `staged/bundle.${container}`, size_bytes: 840, sha256: digest, container,
    record_count: 8, redacted_record_count: 5, retained_record_count: 2, empty_record_count: 1 };
  return { ...record, producer: "collector.collection-semantics.sandbox.v1",
    content: { ...fields, artifact_type: "collector_observation", observation_kind: "collection_semantics", observed_fields: { ...fields } },
    limitations: ["aggregate counts of reviewed synthetic fixture values only; no record values retained"] };
}

it("explains metadata before raw details and does not claim contents from a 100% confidence score", async () => {
  const record = metadata();
  const original = JSON.stringify(record);
  Object.freeze(record.content!.observed_fields); Object.freeze(record.content); Object.freeze(record);
  render(<EvidenceRecords records={[record]} />);
  expect(screen.getByText("File metadata observed")).toBeVisible();
  expect(screen.getByText("staged/bundle.jsonl")).toBeVisible();
  expect(screen.getByText("840 bytes")).toBeVisible();
  expect(screen.getByText(digest)).toBeVisible();
  expect(screen.getByText(/does not establish record counts or whether values were redacted/)).toBeVisible();
  expect(screen.queryByText("Records inspected")).not.toBeInTheDocument();
  expect(screen.getByText(/Reported confidence: 100%/)).toHaveTextContent("does not measure detection accuracy or broader coverage");
  expect(screen.getByText(record.limitations![0]!)).toBeVisible();
  const raw = screen.getByLabelText("Evidence content evidence-file");
  expect(raw).not.toBeVisible();
  await userEvent.click(screen.getByText("Show technical evidence content"));
  expect(raw).toBeVisible(); expect(raw).toHaveTextContent('"size_bytes": 840');
  expect(JSON.stringify(record)).toBe(original);
});

it.each(["jsonl", "ustar", "gzip"])("shows independently observed synthetic counts for %s without inventing detector coverage", container => {
  render(<EvidenceRecords records={[semantics(container)]} />);
  expect(screen.getByText("Collection contents observed")).toBeVisible();
  for (const [label, value] of [["Records inspected", "8"], ["Redacted values", "5"], ["Original values retained", "2"], ["Empty values", "1"]]) {
    expect(within(screen.getByText(label!).parentElement!).getByText(value!)).toBeVisible();
  }
  expect(screen.getByText(/Individual values were not retained as evidence/)).toBeVisible();
  expect(screen.getByText(/Reported confidence: 100%/)).toHaveTextContent("does not measure detection accuracy");
});

it("recognizes the older direct sandbox observer without requiring collector-specific fields", () => {
  render(<EvidenceRecords records={[{ ...metadata(), producer: "sandbox-observer.v1",
    content: { artifact_type: "file_observation", path: "staged/bundle.jsonl", size_bytes: 840, sha256: digest, modified_ns: 1234 } }]} />);
  expect(screen.getByText("File metadata observed")).toBeVisible();
  expect(screen.getByText("840 bytes")).toBeVisible();
  expect(screen.queryByText("Records inspected")).not.toBeInTheDocument();
});

it.each(["unknown producer", "executed", "missing counts", "inconsistent fields", "inconsistent counts", "unknown container"])("leaves %s evidence uninterpreted and preserves its original content", variation => {
  const record = semantics("jsonl");
  if (variation === "unknown producer") record.producer = "external.custom-observer.v1";
  if (variation === "executed") record.provenance = "executed";
  if (variation === "missing counts") delete record.content!.retained_record_count;
  if (variation === "inconsistent fields") record.content!.size_bytes = 900;
  if (variation === "inconsistent counts") {
    record.content!.record_count = 9;
    (record.content!.observed_fields as Record<string, unknown>).record_count = 9;
  }
  if (variation === "unknown container") {
    record.content!.container = "custom";
    (record.content!.observed_fields as Record<string, unknown>).container = "custom";
  }
  const original = JSON.stringify(record.content, null, 2);
  render(<EvidenceRecords records={[record]} />);
  expect(screen.queryByText("Collection contents observed")).not.toBeInTheDocument();
  expect(screen.queryByText("Records inspected")).not.toBeInTheDocument();
  expect(screen.getByText(/No readable summary is available for this evidence format/)).toBeVisible();
  expect(screen.getByLabelText("Evidence content evidence-file").textContent).toBe(original);
  expect(screen.getByText(record.limitations![0]!)).toBeVisible();
});

it("retains legacy summaries and does not turn missing evidence or invalid confidence into positive observations", () => {
  render(<EvidenceRecords records={[{ id: "legacy", kind: "Custom measurement", provenance: "unknown", confidence: Number.NaN,
    fields: { summary: "The source did not provide a measurement.", other: 7 }, limitations: ["No independent collector was available."] }]} />);
  expect(screen.getByText("Custom measurement")).toBeVisible();
  expect(screen.getByText("The source did not provide a measurement.")).toBeVisible();
  expect(screen.getByText(/Reported confidence: Not reported/)).toBeVisible();
  expect(screen.queryByText("File metadata observed")).not.toBeInTheDocument();
});
