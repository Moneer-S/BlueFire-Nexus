import { useMutation, useQuery } from "@tanstack/react-query";
import { MessageSquareText } from "lucide-react";
import { useLayoutEffect, useRef } from "react";
import { adPhaseLabels, type AdWorkflow } from "../lib/ad-smb";
import { adSmbAssistanceContext, adSmbAssistanceMatchesWorkflow, type AdSmbAssistanceSummary } from "../lib/ad-smb-assistance";
import { useAssistancePanel, usePublishAdSmbSelection } from "../state/AssistanceContext";
import { Button, ErrorState, sentence } from "./Primitives";

/** Captures the displayed saved result; native workflow controls keep their own lifecycle. */
export function AdSmbAssistanceAction({ workflow, disabled = false }: { workflow: AdWorkflow; disabled?: boolean }) {
  const panel = useAssistancePanel();
  const mounted = useRef(false);
  useLayoutEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const currentWorkflow = useRef(workflow);
  currentWorkflow.current = workflow;
  const capture = useMutation({ mutationFn: (source: AdWorkflow) => adSmbAssistanceContext(source.id, undefined, source), onSuccess: data => { if (mounted.current && adSmbAssistanceMatchesWorkflow(data, currentWorkflow.current)) panel?.setOpen(true); } });
  const captured = !capture.isPending && !capture.isError && capture.data && adSmbAssistanceMatchesWorkflow(capture.data, workflow) ? capture.data : undefined;
  const saved = panel?.selection && "kind" in panel.selection && panel.selection.kind === "ad_smb" && panel.selection.selected.workflow_job_id === workflow.id ? panel.selection.selected : undefined;
  const restored = useQuery({ queryKey: ["ad-smb-assistance-reopen", saved, workflow.id, workflow.revision, workflow.policy, workflow.stopped, workflow.pending, workflow.environment.provenance, workflow.operations.map(op => [op.id, op.phase, op.runId, op.state, op.digest])], queryFn: () => adSmbAssistanceContext(workflow.id, saved, workflow), enabled: Boolean(saved) && !captured && !disabled, retry: false, refetchOnWindowFocus: false });
  const restoredContext = restored.isSuccess && !restored.isFetching && adSmbAssistanceMatchesWorkflow(restored.data, workflow) ? restored.data : undefined;
  usePublishAdSmbSelection((captured ?? restoredContext)?.selected);
  if (!panel || (!workflow.operations.length && !workflow.pending)) return null;
  return <div className="ad-smb-actions">
    <Button disabled={disabled || capture.isPending} onClick={() => capture.mutate(workflow)}><MessageSquareText aria-hidden="true" />{capture.isPending ? "Checking saved result…" : "Explain saved result"}</Button>
    {capture.isError ? <ErrorState title="Saved explanation unavailable" error={capture.error} /> : null}
    {!captured && restored.isError ? <ErrorState title="Saved explanation unavailable" error={restored.error} /> : null}
  </div>;
}

export function AdSmbAssistanceEvidence({ summary }: { summary: AdSmbAssistanceSummary }) {
  return <div role="group" aria-label="Saved AD workflow summary">
    <p>{summary.provenance === "synthetic_fixture" ? "Synthetic fixture" : "Runner-reported evidence"} · revision {summary.revision}. Explanation only; effective access is not established.</p>
    <details className="assistant-source-details"><summary>Saved AD evidence and limits</summary>
      {summary.operations.map(operation => <div key={operation.operation_job_id}>
        <strong>{adPhaseLabels[operation.phase]}</strong><p>{sentence(operation.outcome.state)} · cleanup {sentence(operation.outcome.cleanup)}{operation.outcome.read_expectation ? ` · recorded read expectation ${sentence(operation.outcome.read_expectation)}` : ""}</p>
        <ul>{operation.tasks.map(task => <li key={task.step}>
          {task.observation && "reader" in task.observation ? `${sentence(task.observation.reader)} ${task.observation.purpose}: ${sentence(task.observation.state)}; local cleanup ${sentence(task.observation.local_cleanup)}.`
            : task.observation && "events" in task.observation ? `Saved audit: ${task.observation.events} events; completeness ${task.observation.normalization ? sentence(task.observation.normalization.reported_completeness) : task.observation.truncated ? "truncated" : "not independently verified"}.`
              : task.observation && "state" in task.observation ? `${sentence(task.observation.state)}; receiver completion ${task.observation.receiver_completed_at ?? "not recorded"}.`
                : "Observation unavailable; result remains unknown."}
          {" "}{task.provenance ? sentence(task.provenance) : "Provenance unavailable"}. Dispatch {sentence(task.dispatch)}.
        </li>)}</ul>
      </div>)}
      {summary.missing_phases.length ? <p>Stages not recorded: {summary.missing_phases.map(phase => adPhaseLabels[phase]).join(", ")}.</p> : null}
      {summary.pending_operation ? <p>The original workflow operation is unsettled. This explanation cannot recover or replace it.</p> : null}
      <p>Probe reads, legitimate reads, descriptor readback and audit remain separate observations. Remote reader identity, fresh server logon and independent verification are not established. Request times are not observation times.</p>
    </details>
  </div>;
}
