import type { ReceiverContext, ReceiverDefenseEnvelope, ReceiverPhaseResult } from "./receiver-defense-types";
import { phaseTitle, policyTitle, receiverOutcome } from "./receiver-defense";

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function evidenceSummary(result: ReceiverPhaseResult) {
  const decision = object(object(result.receiver_observation.terminal).decision);
  const semantics = object(decision.semantics);
  const count = (key: string) => typeof semantics[key] === "number" && Number.isSafeInteger(semantics[key]) && Number(semantics[key]) >= 0 ? semantics[key] : null;
  // This is a summary export, not a serialization of the private hydrated run.
  return {
    run_id: result.run_id,
    decision: result.decision,
    policy_id: result.policy_id,
    authenticated: typeof decision.authenticated === "boolean" ? decision.authenticated : null,
    record_counts: {
      total: count("record_count"),
      redacted: count("redacted_record_count"),
      retained: count("retained_record_count"),
      empty: count("empty_record_count"),
    },
    artifact: result.artifact ? { sha256: result.artifact.sha256, size_bytes: result.artifact.size_bytes } : null,
    legitimate_use: result.legitimate_use ? { baseline_run_id: result.legitimate_use.baseline_run_id, established: result.legitimate_use.established } : null,
  };
}

export function receiverControlReport(envelope: ReceiverDefenseEnvelope & { context: ReceiverContext }): string {
  const lines = ["# Receiver control test", "", envelope.context.scenario_title, "", `Status: ${envelope.status}`, "",
    "This local lab experiment measures prevention separately from detection. The summary excludes runner profiles, installation paths, raw output, process identities and complete run evidence.", ""];
  if (envelope.control) lines.push("## Retained policy", "", `Desired policy: ${policyTitle[envelope.control.desired_policy_id]}`, `Policy state: ${envelope.control.status}`, `Receiver state: ${envelope.control.receiver_state}`, `Owner: ${envelope.control.owner_job_id}`, `Control digest: ${envelope.control.control_digest}`, "", "The policy is scoped to this saved control test and its exact-bound linked retests. Independently created tests do not inherit it. A stopped receiver is not an active production defense.", "");
  if (envelope.context.source_baseline) lines.push(`Original baseline lineage: ${envelope.context.source_baseline.run_id}`, "", "The original baseline is historical lineage, not a fresh execution in this retest.", "");
  for (const phase of envelope.phases) {
    lines.push(`## ${phaseTitle[phase.phase]}`, "", `Policy: ${policyTitle[phase.policy_id]}`, `Outcome: ${receiverOutcome(phase)}`, `Receiver cleanup: ${phase.cleanup.receiver}; run cleanup: ${phase.cleanup.run}`, "");
    if (phase.result) lines.push("```json", JSON.stringify(evidenceSummary(phase.result), null, 2), "```", "");
    if (phase.result?.legitimate_use) lines.push(`Legitimate use: ${phase.result.legitimate_use.established ? "established" : "not established"}`, "");
  }
  lines.push("## Limitations", "", ...envelope.limitations.map((item) => `- ${item}`), "", "Unverified or missing evidence is not a prevention pass. No general detection or prevention coverage is established.", "");
  return lines.join("\n");
}
