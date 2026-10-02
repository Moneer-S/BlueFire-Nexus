import { useIsMutating, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { evaluationLabel } from "../lib/detection-results";
import { registeredDetectionLink } from "../lib/run-handoffs";
import { buildDetectionEvaluationPlan, evaluationPlanTargets, evaluationReportMatches, evaluationSource, evaluationTarget, missingRevisedEvaluationRuns, sameEvaluationTarget,
  type DetectionEvaluationPlan, type EvaluationCaseInputs, type EvaluationPlanOptions } from "../lib/detection-evaluation-plan";
import type { DetectionResource, DetectionRunEvaluation, RunRecord } from "../types";
import { Button, Field } from "./Primitives";
import "./DetectionEvaluationQueue.css";

interface QueueProps {
  runIds: string[];
  baselineId: string;
  revisedId: string;
  resources: DetectionResource[];
  reports: DetectionRunEvaluation[];
  ready: boolean;
}
interface CaseOutcome { runId: string; state: "checking" | "pending" | "retained" | "unconfirmed" | "not-submitted"; report?: DetectionRunEvaluation; message?: string }
interface Attempt { plan: DetectionEvaluationPlan; selectionKey: string; stop: boolean }
const mutationKey = ["comparison-evaluation-queue"];
const selectionKey = (props: QueueProps) => JSON.stringify([props.runIds, props.baselineId, props.revisedId]);

export function DetectionEvaluationQueue(props: QueueProps) {
  const client = useQueryClient();
  // Mutation ownership lives in QueryClient, so even an ancestor's temporary
  // unmount cannot make a still-submitted request look idle on re-entry.
  const otherPending = useIsMutating({ mutationKey });
  const live = useRef(props);
  const mounted = useRef(false);
  const attemptRef = useRef<Attempt | undefined>(undefined);
  const reviewGeneration = useRef(0);
  const reviewing = useRef(false);
  const [preparing, setPreparing] = useState(false);
  const [preview, setPreview] = useState<{ options: EvaluationPlanOptions; plan: DetectionEvaluationPlan; selectionKey: string }>();
  const [inputs, setInputs] = useState<Record<string, EvaluationCaseInputs>>({});
  const [outcomes, setOutcomes] = useState<CaseOutcome[]>([]);
  const [notice, setNotice] = useState("");
  const [started, setStarted] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [unconfirmedCases, setUnconfirmedCases] = useState<string[]>([]);

  useLayoutEffect(() => {
    live.current = props;
    if (attemptRef.current && attemptRef.current.selectionKey !== selectionKey(props)) {
      attemptRef.current.stop = true;
      setStopping(true);
    }
  }, [props]);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; reviewGeneration.current += 1; if (attemptRef.current) attemptRef.current.stop = true; };
  }, []);

  const updateOutcome = (outcome: CaseOutcome) => {
    if (mounted.current) setOutcomes(current => [...current.filter(item => item.runId !== outcome.runId), outcome]);
  };
  const canContinue = (attempt: Attempt) => {
    if (attempt.stop || !mounted.current || selectionKey(live.current) !== attempt.selectionKey || !live.current.ready) return false;
    return [attempt.plan.baseline, attempt.plan.target].every(target => {
      const matches = live.current.resources.filter(resource => resource.id === target.id);
      const current = matches.length === 1 ? evaluationTarget(matches[0]!) : undefined;
      return current && sameEvaluationTarget(current, target);
    });
  };
  const evaluation = useMutation({
    mutationKey,
    retry: false,
    mutationFn: async (attempt: Attempt) => {
      const { plan } = attempt;
      for (const item of plan.cases) {
        if (!canContinue(attempt)) return "Stopped. No further evaluations were submitted.";
        updateOutcome({ runId: item.runId, state: "checking" });
        try {
          // Each dispatch reads current registry, history and the canonical run.
          // None of these reads starts evaluation or changes the frozen inputs.
          const [registry, history, source] = await Promise.all([
            api.detections(), api.detectionRunEvaluations(plan.target.id), api.runDetail(item.runId),
          ]);
          if (!canContinue(attempt)) return "Stopped. No further evaluations were submitted.";
          const checked = evaluationPlanTargets({ baselineId: plan.baseline.id, revisedId: plan.target.id,
            resources: registry.candidates, reports: history.evaluations });
          if (!sameEvaluationTarget(checked.baseline, plan.baseline) || !sameEvaluationTarget(checked.target, plan.target)) throw new Error("The saved revision identity changed after review.");
          const currentSource = evaluationSource(source, item.runId);
          if (!currentSource || currentSource.manifestIdentity !== item.source.manifestIdentity) throw new Error("The source run identity changed after review.");
          if (history.evaluations.some(report => report.source.run_id === item.runId)) throw new Error("This run now has a retained revised-rule result. Review the comparison again.");
        } catch (error) {
          updateOutcome({ runId: item.runId, state: "not-submitted", message: error instanceof Error ? error.message : "The selected records could not be verified." });
          return "Stopped before submission. Review the current records before planning again.";
        }
        if (!canContinue(attempt)) return "Stopped. No further evaluations were submitted.";
        updateOutcome({ runId: item.runId, state: "pending" });
        try {
          const { evaluation: report } = await api.evaluateDetectionRun(plan.target.id, {
            run_id: item.runId, question: item.question, case_role: item.activity,
            activity_label: item.activity, evaluation_use: item.evaluationUse,
          });
          if (!evaluationReportMatches(report, plan.target, item)) throw new Error("The returned report does not match the reviewed revision, run or inputs.");
          // Stop does not erase an already submitted request's actual result.
          updateOutcome({ runId: item.runId, state: "retained", report });
          if (["Engine error", "Not enough evidence"].includes(evaluationLabel(report))) return "Stopped after a retained result that needs review. Remaining runs were not submitted.";
        } catch (error) {
          updateOutcome({ runId: item.runId, state: "unconfirmed", message: error instanceof Error ? error.message : "The evaluation response was unavailable." });
          if (mounted.current) setUnconfirmedCases(current => [...new Set([...current, JSON.stringify([plan.target.id, item.runId])])]);
          return "Stopped. The submitted outcome is unconfirmed; a report may already be retained. Check retained history before considering another evaluation. Nothing will retry automatically.";
        }
      }
      return attempt.stop ? "Stopped. The submitted evaluation has settled; no further evaluations were submitted." : "Every planned evaluation has a retained result.";
    },
    onSuccess: message => { if (mounted.current) setNotice(message); },
    onSettled: (_data, _error, attempt) => {
      // Invalidate even after a timeout: a lost response does not imply no report.
      void client.invalidateQueries({ queryKey: ["detection-evaluations", attempt.plan.target.id] });
    },
  });

  const review = async () => {
    if (reviewing.current || client.isMutating({ mutationKey }) || !live.current.ready) return;
    reviewing.current = true;
    const generation = ++reviewGeneration.current;
    const captured = live.current;
    const key = selectionKey(captured);
    const current = () => mounted.current && generation === reviewGeneration.current && selectionKey(live.current) === key;
    setPreparing(true);
    try {
      const [registry, history] = await Promise.all([api.detections(), api.detectionRunEvaluations(captured.revisedId)]);
      const sources: RunRecord[] = [];
      const manifestDigests: Record<string, string> = {};
      for (const id of missingRevisedEvaluationRuns(captured.runIds, history.evaluations)) {
        if (!current()) return;
        const source = await api.runDetail(id);
        const binding = evaluationSource(source, id);
        if (!binding) throw new Error("A selected run has no supported, finalized manifest.");
        const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(binding.manifestIdentity));
        manifestDigests[id] = `sha256:${Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("")}`;
        sources.push(source);
      }
      const options = { runIds: [...captured.runIds], baselineId: captured.baselineId, revisedId: captured.revisedId, resources: registry.candidates, reports: history.evaluations, sources, manifestDigests };
      const plan = buildDetectionEvaluationPlan(options);
      if (!current()) return;
      setInputs(Object.fromEntries(plan.cases.map(item => [item.runId, { question: item.question, activity: item.activity, evaluationUse: item.evaluationUse }])));
      setPreview({ options, plan, selectionKey: key });
      setOutcomes([]); setNotice(""); setStarted(false); setStopping(false); attemptRef.current = undefined;
    } catch (error) { if (current()) setNotice(error instanceof Error ? error.message : "The evaluation preview could not be prepared."); }
    finally { reviewing.current = false; if (mounted.current && generation === reviewGeneration.current) setPreparing(false); }
  };
  const start = () => {
    if (!preview || started || reviewing.current || attemptRef.current || client.isMutating({ mutationKey }) || !live.current.ready || selectionKey(live.current) !== preview.selectionKey) return;
    try {
      const plan = buildDetectionEvaluationPlan({ ...preview.options, inputs });
      if (!plan.cases.length) return;
      const attempt = { plan, selectionKey: preview.selectionKey, stop: false };
      if (!canContinue(attempt)) { setNotice("The selected records changed. Review the missing evaluations again."); return; }
      attemptRef.current = attempt;
      setStarted(true); setNotice("");
      evaluation.mutate(attempt);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Review the evaluation inputs."); }
  };
  let missing = 0;
  try { missing = missingRevisedEvaluationRuns(props.runIds, props.reports).length; } catch { /* The comparison owns invalid selection messaging. */ }
  const stalePreview = preview && preview.selectionKey !== selectionKey(props);
  if (!preview && !started && !preparing && !notice && (!props.ready || !missing) && !otherPending) return null;
  const edit = (runId: string, key: keyof EvaluationCaseInputs, value: string) => setInputs(current => ({ ...current, [runId]: { ...current[runId]!, [key]: value } }));

  return <section className="evaluation-queue" aria-label="Evaluate missing revised results">
    <h3>Evaluate missing revised results</h3>
    <p>Review each selected run, then start one evaluation at a time. Existing results, including errors and uncertain evidence, stay unchanged.</p>
    <p className="field-note">Stopping or leaving this view prevents later submissions. A request already submitted may finish and retain a report. This browser does not cancel server work or resume the queue.</p>
    {!evaluation.isPending ? <Button disabled={!props.ready || preparing || Boolean(otherPending) || (!missing && !started)} onClick={() => { void review(); }}>{preparing ? "Preparing evaluation preview" : started ? "Review remaining evaluations" : "Review missing revised evaluations"}</Button> : null}
    {otherPending && !evaluation.isPending ? <p role="status">An earlier evaluation sequence is still settling. Wait for its submitted request before preparing another.</p> : null}
    {stalePreview ? <p role="status">The comparison selection changed. This preview cannot submit more evaluations.</p> : null}
    {preview ? <>
      <p><strong>{preview.plan.title} · revision {preview.plan.target.revision}</strong> · {preview.plan.cases.length} missing result{preview.plan.cases.length === 1 ? "" : "s"}, in comparison order.</p>
      {!preview.plan.cases.length ? <p>Every selected run already has a revised-rule evaluation.</p> : null}
      {!started && preview.plan.cases.some(item => unconfirmedCases.includes(JSON.stringify([preview.plan.target.id, item.runId]))) ? <p role="alert">An earlier submission for a remaining run is still unconfirmed. A fresh history read does not prove it failed to persist; starting again could repeat that evaluation.</p> : null}
      <ol className="evaluation-queue-cases">{preview.plan.cases.map((item, index) => {
        const values = inputs[item.runId]!;
        const outcome = outcomes.find(result => result.runId === item.runId);
        return <li key={item.runId}><fieldset disabled={started || Boolean(stalePreview) || Boolean(otherPending)}><legend>Case {index + 1} · {item.source.label}</legend>
          <Field label="Experiment question" hint="Optional; blank uses the selected rule and run."><textarea rows={2} maxLength={1000} value={values.question} onChange={event => edit(item.runId, "question", event.target.value)} /></Field>
          <div className="two-column"><Field label="Activity label"><select value={values.activity} onChange={event => edit(item.runId, "activity", event.target.value)}><option value="unknown">Unknown / not assigned</option><option value="attack">Attack activity</option><option value="benign">Benign activity</option></select></Field>
            <Field label="Use of this data"><select value={values.evaluationUse} onChange={event => edit(item.runId, "evaluationUse", event.target.value)}><option value="unspecified">Not specified</option><option value="development">Development data</option><option value="independent">Independent test data</option></select></Field></div>
        </fieldset>
        <p role="status">{outcome?.state === "retained" && outcome.report ? <>Evaluation retained: {evaluationLabel(outcome.report)}. <Link to={registeredDetectionLink(item.runId, preview.plan.target.id)}>Review retained evaluation</Link></>
          : outcome?.state === "pending" ? "Evaluation submitted; awaiting its outcome."
          : outcome?.state === "unconfirmed" ? `Submitted outcome unconfirmed. ${outcome.message ?? ""}`
          : outcome?.state === "not-submitted" ? `Not submitted. ${outcome.message ?? ""}`
          : outcome?.state === "checking" && evaluation.isPending && !stopping ? "Checking current records before submission."
          : started ? "Not submitted." : "Ready for your review."}</p></li>;
      })}</ol>
      <p className="field-note">Activity and independent data use are operator declarations. Recorded development use takes precedence; these labels do not prove independence or deployed prevention.</p>
      {!started ? <Button variant="primary" disabled={!props.ready || preparing || Boolean(stalePreview) || Boolean(otherPending) || !preview.plan.cases.length} onClick={start}>Start evaluations</Button> : null}
    </> : null}
    {evaluation.isPending ? <Button disabled={stopping} onClick={() => { if (attemptRef.current) attemptRef.current.stop = true; setStopping(true); }}>{stopping ? "Stopping further submissions" : "Stop after current evaluation"}</Button> : null}
    {notice ? <p role="status">{notice}</p> : null}
  </section>;
}
