import { expect, it } from "vitest";
import { receiverControlReport } from "../src/lib/receiver-report";
import { retainedReceiverFixture } from "./receiver-retained-fixture";

it("exports outcome semantics without nested private evidence or installation metadata", () => {
  const value = retainedReceiverFixture();
  const result = value.phases[2]!.result!;
  Object.assign(result.run, { private_export_canary: "PRIVATE-RUN-MUST-NOT-EXPORT" });
  Object.assign(result.receiver_observation, { private_export_canary: "PRIVATE-OBSERVATION-MUST-NOT-EXPORT" });
  Object.assign(result.source_binding, { private_export_canary: "PRIVATE-SOURCE-MUST-NOT-EXPORT" });
  const terminal = result.receiver_observation.terminal as Record<string, unknown>;
  Object.assign(terminal.decision as Record<string, unknown>, { private_export_canary: "PRIVATE-DECISION-MUST-NOT-EXPORT" });
  const report = receiverControlReport(value);
  expect(report).not.toContain("MUST-NOT-EXPORT");
  expect(report).toContain('"record_counts"');
  expect(report).toContain('"redacted": 2');
  expect(report).toContain('"authenticated": true');
  expect(report).toContain(result.artifact!.sha256);
  expect(report).toContain("Legitimate use: established");
  expect(report).toContain("Receiver cleanup: verified_closed; run cleanup: complete");
});

it("distinguishes linked historical baseline from fresh retest outcomes", () => {
  const value = retainedReceiverFixture("legitimate", "completed", true);
  const report = receiverControlReport(value);
  expect(report).toContain(`Original baseline lineage: ${value.context.source_baseline!.run_id}`);
  expect(report).toContain("historical lineage, not a fresh execution");
  expect(report).not.toContain("## Baseline");
  expect(report).toContain("## Redaction required");
});

it("keeps absent observation counts unknown rather than zero", () => {
  const value = retainedReceiverFixture();
  const result = value.phases[2]!.result!;
  result.receiver_observation = {};
  const report = receiverControlReport(value);
  expect(report).toContain('"total": null');
  expect(report).toContain('"authenticated": null');
});
