import { Link } from "react-router-dom";
import { compositionRecord, type CompositionObjective } from "../lib/composition";
import { Badge, DataList, sentence } from "./Primitives";

export function CompositionAttempts({ objective }: { objective: CompositionObjective }) {
  return <section className="composition-section" aria-label="Attempt evidence"><h2>Attempts</h2>
    {!objective.attempts.length ? <p>No attempt has been dispatched.</p> : <ol className="composition-attempts">{objective.attempts.map((attempt, index) => {
      const progress = attempt.progress;
      const result = compositionRecord(progress.verified_result);
      const outcome = compositionRecord(result.objective);
      const receiver = compositionRecord(result.receiver_result);
      const cleanup = compositionRecord(result.cleanup);
      const verified = typeof progress.verified_result_digest === "string" && typeof result.run_id === "string";
      return <li key={attempt.job_id}><header><h3>Attempt {index + 1}</h3><Badge tone={outcome.established === true && verified ? "success" : "neutral"}>{verified ? outcome.established === true ? "Objective established" : "Objective not established" : sentence(attempt.state)}</Badge></header>
        <DataList items={[
          { label: "Progress", value: sentence(String(progress.phase ?? attempt.state)) },
          { label: "Settlement", value: sentence(String(progress.settlement ?? "pending")) },
          { label: "Receiver cleanup", value: String(cleanup.receiver ?? (progress.receiver_closed === true ? "verified_closed" : "unverified")) },
          { label: "Native cleanup", value: String(cleanup.run ?? (compositionRecord(progress.native_cleanup).no_effects ? "Verified no effects" : compositionRecord(progress.native_cleanup).report ? "Verified receipt cleanup" : "unverified")) },
        ]} />
        {verified ? <><DataList items={Object.entries(receiver).map(([label, value]) => ({ label: label.replaceAll("_", " "), value: <span>{String(value)}</span> }))} /><Link to={`/runs/${encodeURIComponent(String(result.run_id))}`}>Inspect verified run evidence</Link></> : <p>{String(progress.verified_result_problem ?? "No verified objective conclusion is available.")}</p>}
      </li>;
    })}</ol>}
  </section>;
}
