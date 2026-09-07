import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { phaseTitle, receiverJobValid, receiverPhases } from "../lib/receiver-defense";
import { Button, ErrorState, LoadingState, formatDate, sentence } from "./Primitives";

export function ReceiverSavedTests() {
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors.at(-1);
  const history = useQuery({ queryKey: ["receiver-tests", cursor], queryFn: async () => {
    const value = await api.receiverTests(cursor);
    if (value?.schema_version !== "bluefire.receiver-defense-list.v1" || !Array.isArray(value.jobs) || value.jobs.length > 128 || typeof value.truncated !== "boolean" ||
      (value.next_cursor !== null && (!receiverJobValid(value.next_cursor) || value.next_cursor === cursor)) || value.truncated !== (value.next_cursor !== null) ||
      value.jobs.some((job) => !receiverJobValid(job.job_id) || typeof job.title !== "string" || typeof job.status !== "string" || (job.phase !== null && !receiverPhases.includes(job.phase)))) throw new Error("The saved control-test list is incomplete. Refresh it before choosing a test.");
    return value;
  }, retry: false });
  if (history.error) return <><ErrorState title="Saved control tests unavailable" error={history.error} retry={() => { void history.refetch(); }} />{cursor ? <Button onClick={() => setCursors([])}>Return to newest tests</Button> : null}</>;
  if (!history.data) return <LoadingState label="Finding saved control tests" />;
  if (!history.data.jobs.length && !history.data.truncated && !cursor) return null;
  return <section className="receiver-saved-tests" aria-label="Saved control tests"><h2>Continue a saved test</h2><p>Unfinished work stays with its original experiment, receiver sessions and run approvals.</p>
    <ul>{history.data.jobs.map((job) => <li key={job.job_id}><Link to={`/compare?receiver_job=${encodeURIComponent(job.job_id)}`}><strong>{job.title}</strong><span>{sentence(job.status)}{job.phase ? ` · ${phaseTitle[job.phase]}` : ""}</span><small>{formatDate(job.updated_at ?? undefined)}</small></Link></li>)}</ul>
    <div className="receiver-actions">{cursor ? <Button onClick={() => setCursors((old) => old.slice(0, -1))}>Previous saved tests</Button> : null}{history.data.next_cursor ? <Button onClick={() => setCursors((old) => [...old, history.data!.next_cursor!])}>More saved tests</Button> : null}</div>
  </section>;
}
