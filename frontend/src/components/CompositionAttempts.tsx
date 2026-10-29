import type { Ref } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { compositionPack, compositionRecord, FILE_ACCESS_PACK, MACOS_FILE_ACCESS_PACK, type CompositionObjective } from "../lib/composition";
import { Badge, Callout, DataList, sentence } from "./Primitives";
import { FileAccessRetestComparison } from "./FileAccessRetestComparison";
import { CompositionKnowledge } from "./CompositionKnowledge";

export function CompositionAttempts({ objective, selectedAttemptRef }: { objective: CompositionObjective; selectedAttemptRef?: Ref<HTMLLIElement> }) {
  const [params] = useSearchParams();
  const macOS = compositionPack(objective.grant.document) === MACOS_FILE_ACCESS_PACK;
  const fileAccess = macOS || compositionPack(objective.grant.document) === FILE_ACCESS_PACK;
  const selectedAttempt = params.get("attempt");
  const comparePath = (attempt: string) => {
    const next = new URLSearchParams(params);
    next.set("control", objective.grant.document.environment.control_owner_id);
    next.set("objective", objective.owner.job_id);
    next.set("pack", FILE_ACCESS_PACK);
    next.set("attempt", attempt);
    return `/composition?${next}`;
  };
  return <section className="composition-section" aria-label="Attempt evidence"><h2>Attempts</h2>
    {objective.attempts.length ? <CompositionKnowledge objective={objective} /> : null}
    {fileAccess && !macOS && selectedAttempt && !objective.attempts.some(attempt => attempt.request.composition_attempt.attempt_id === selectedAttempt)
      ? <Callout title="This attempt is not part of the selected objective">Choose a recorded attempt below to open its comparison.</Callout> : null}
    {!objective.attempts.length ? <p>No attempt has been dispatched.</p> : <ol className="composition-attempts">{objective.attempts.map((attempt, index) => {
      const progress = attempt.progress;
      const result = compositionRecord(progress.verified_result);
      const outcome = compositionRecord(result.objective);
      const receiver = compositionRecord(result.receiver_result);
      const access = compositionRecord(macOS ? result.macos_file_access_result : result.file_access_result);
      const cleanup = compositionRecord(result.cleanup);
      const verified = typeof progress.verified_result_digest === "string" && typeof result.run_id === "string";
      const selected = selectedAttempt === attempt.request.composition_attempt.attempt_id;
      return <li key={attempt.job_id} ref={selected ? selectedAttemptRef : undefined} className={selected ? "composition-selected-attempt" : undefined} tabIndex={selected ? -1 : undefined} aria-label={selected ? "Selected attempt comparison" : undefined}><header><h3>Attempt {index + 1}</h3><Badge tone={outcome.established === true && verified ? "success" : "neutral"}>{verified ? outcome.established === true ? "Objective established" : "Objective not established" : sentence(attempt.state)}</Badge></header>
        {fileAccess && !macOS ? selectedAttempt === attempt.request.composition_attempt.attempt_id
          ? <FileAccessRetestComparison objective={objective} attempt={attempt} />
          : <Link className="file-access-retest-open" to={comparePath(attempt.request.composition_attempt.attempt_id)}>Compare with the recorded baseline</Link> : null}
        <DataList items={[
          { label: "Progress", value: sentence(String(progress.phase ?? attempt.state)) },
          { label: "Settlement", value: sentence(String(progress.settlement ?? "pending")) },
          fileAccess ? { label: macOS ? "Original request closure" : "Probe request cleanup", value: String(cleanup.request ?? (macOS ? progress.macos_file_access_request_state : undefined) ?? "unverified") } : { label: "Receiver cleanup", value: String(cleanup.receiver ?? (progress.receiver_closed === true ? "verified_closed" : "unverified")) },
          ...(macOS ? [
            { label: "Attempt artifacts", value: cleanup.attempt_artifacts === "not_created" ? "Not created" : "Unverified" },
            { label: "Original workers", value: cleanup.workers === "retained" ? "Retained" : "Unverified" },
            { label: "Whole-enrollment cleanup", value: cleanup.whole_enrollment === false ? "Not performed" : "Not established" },
          ] : [{ label: "Native cleanup", value: String(cleanup.run ?? (compositionRecord(progress.native_cleanup).no_effects ? "Verified no effects" : compositionRecord(progress.native_cleanup).report ? "Verified receipt cleanup" : "unverified")) }]),
        ]} />
        {verified ? <><DataList items={fileAccess ? [
          { label: "Fresh non-owner read", value: access.probe_verified === true ? access.non_owner_decision === (macOS ? "denied" : "permission_denied") ? "Permission denied" : sentence(String(access.non_owner_decision)) : "Unknown: probe identity not verified" },
          { label: "Fresh owner read", value: access.owner_verified === true ? sentence(String(access.owner_decision)) : "Unknown: owner read not verified" },
          { label: "Resource generation", value: String(access.resource_generation) }, { label: "Control revision", value: String(access.control_revision) },
          { label: "Records", value: String(access.record_count) }, { label: "Content digest", value: <code>{String(access.sha256)}</code> },
        ] : Object.entries(receiver).map(([label, value]) => ({ label: label.replaceAll("_", " "), value: <span>{String(value)}</span> }))} /><Link to={`/runs/${encodeURIComponent(String(result.run_id))}`}>Inspect verified run evidence</Link></> : <><p>{String(progress.verified_result_problem ?? "No verified objective conclusion is available.")}</p>{macOS && typeof progress.finalized_run_id === "string" ? <Link to={`/runs/${encodeURIComponent(progress.finalized_run_id)}`}>Inspect finalized run evidence</Link> : null}</>}
        {macOS ? <p>Original-producer metadata, not independent telemetry. Attempt closure does not remove the retained resource or workers.</p> : null}
      </li>;
    })}</ol>}
  </section>;
}
