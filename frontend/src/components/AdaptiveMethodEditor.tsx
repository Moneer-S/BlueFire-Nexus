import { displayTitle } from "../lib/display-title";
import { useState } from "react";
import type { ActionDefinition, Behavior, Scenario, ScenarioStep } from "../types";
import { adaptiveExecutionIssues, adaptiveOutcomeLabels, applyAdaptiveStep, applyAdaptiveV2Step, availableAdaptiveMethods, methodKey, removeAdaptiveStep, type AdaptiveMethod, type AdaptiveOutcome } from "../lib/adaptive-execution";
import { Button, Field } from "./Primitives";

export function AdaptiveMethodEditor({ scenario, step, behaviors, actions, selectedAction, onChange }: {
  scenario: Scenario; step: ScenarioStep; behaviors: ReadonlyMap<string, Behavior>; actions: ReadonlyMap<string, ActionDefinition>;
  selectedAction: string; onChange: (scenario: Scenario) => void;
}) {
  const saved = scenario.adaptive_execution?.steps.find(item => item.step_id === step.id);
  const savedPolicyV2 = scenario.adaptive_execution?.schema_version === "bluefire.adaptive-execution.v2" ? scenario.adaptive_execution : undefined;
  const savedV2 = Boolean(savedPolicyV2);
  const options = availableAdaptiveMethods(step, behaviors, actions);
  const primary = options.find(method => method.behavior_id === step.behavior_id && (!selectedAction || method.action_id === selectedAction));
  const [editing, setEditing] = useState(Boolean(saved));
  const [methods, setMethods] = useState<AdaptiveMethod[]>(() => structuredClone(saved?.methods ?? (primary ? [primary] : [])));
  const [outcomes, setOutcomes] = useState<AdaptiveOutcome[]>(scenario.adaptive_execution?.eligible_outcomes ?? ["blocked", "failed", "partial"]);
  const [failure, setFailure] = useState<"stop" | "deterministic">(scenario.adaptive_execution?.on_provider_failure ?? "stop");
  const [multiBudget, setMultiBudget] = useState(savedV2);
  const [experimentRetryCap, setExperimentRetryCap] = useState(savedPolicyV2?.max_retries ?? 1);
  const savedStepRetryCap = savedPolicyV2?.steps.find(item => item.step_id === step.id)?.max_retries ?? 1;
  const [stepRetryCap, setStepRetryCap] = useState(savedStepRetryCap);
  const [error, setError] = useState("");
  const selected = new Set(methods.map(methodKey));
  const available = new Set(options.map(methodKey));
  const missing = methods.filter(method => !available.has(methodKey(method)));
  const maximumStepRetryCap = Math.max(0, Math.min(3, methods.length - 1));
  const otherStepRetryCapacity = scenario.adaptive_execution?.schema_version === "bluefire.adaptive-execution.v2"
    ? scenario.adaptive_execution.steps.filter(entry => entry.step_id !== step.id).reduce((sum, entry) => sum + entry.max_retries, 0)
    : scenario.adaptive_execution?.steps.filter(entry => entry.step_id !== step.id).length ?? 0;
  const totalRetryCapacity = Number.isFinite(stepRetryCap) ? otherStepRetryCapacity + stepRetryCap : Number.NaN;
  const maximumExperimentRetryCap = Number.isFinite(totalRetryCapacity) ? Math.min(8, totalRetryCapacity) : 0;
  const validMultiBudget = !multiBudget || (Number.isInteger(experimentRetryCap) && experimentRetryCap >= 1
    && experimentRetryCap <= maximumExperimentRetryCap && Number.isInteger(stepRetryCap)
    && stepRetryCap >= 1 && stepRetryCap <= maximumStepRetryCap);
  const ready = methods.length >= 2 && methods.length <= 4 && outcomes.length > 0 && !missing.length
    && validMultiBudget
    && methods.some(method => method.behavior_id === step.behavior_id && (!selectedAction || method.action_id === selectedAction));
  const issues = adaptiveExecutionIssues(scenario, behaviors, actions, selectedAction ? { [step.id]: selectedAction } : {}).filter(issue => issue.stepId === step.id);
  const changed = JSON.stringify(methods) !== JSON.stringify(saved?.methods ?? [])
    || JSON.stringify(outcomes) !== JSON.stringify(scenario.adaptive_execution?.eligible_outcomes ?? [])
    || failure !== scenario.adaptive_execution?.on_provider_failure || multiBudget !== savedV2
    || (multiBudget && (experimentRetryCap !== (savedPolicyV2?.max_retries ?? 1)
      || stepRetryCap !== savedStepRetryCap))
    || issues.length > 0;
  const apply = () => {
    try {
      const next = multiBudget
        ? applyAdaptiveV2Step(scenario, step.id, methods, {
          eligible_outcomes: outcomes,
          on_provider_failure: failure,
          max_retries: experimentRetryCap,
          step_max_retries: stepRetryCap,
        }, behaviors, actions, selectedAction)
        : applyAdaptiveStep(scenario, step.id, methods, { eligible_outcomes: outcomes, on_provider_failure: failure }, behaviors, actions, selectedAction);
      onChange(next);
      setError("");
    }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Review these retry choices before applying them."); }
  };
  if (!saved && !options.length) return null;
  return <section className="adaptive-method-editor" aria-label="Adaptive retry choices">
    <h3>Try another method</h3>
    <p>Auto may choose from your reviewed methods. Assist asks for review; Off follows the saved steps.</p>
    {!editing ? <Button size="small" onClick={() => setEditing(true)}>Configure adaptive retry</Button> : <>
      <p>Select 2–4 exact methods, including the primary method. Parameters and required inputs stay exactly as reviewed.</p>
      {issues.map(issue => <p className="field-error" role="alert" key={issue.message}>{issue.message}</p>)}
      <fieldset className="adaptive-method-options"><legend>Permitted methods</legend>{options.map(method => {
        const key = methodKey(method), action = actions.get(method.action_id)!;
        return <label className="check-row" key={key}><input type="checkbox" checked={selected.has(key)} disabled={!selected.has(key) && methods.length >= 4}
          onChange={event => { setError(""); setMethods(event.target.checked ? [...methods, method] : methods.filter(item => methodKey(item) !== key)); }} />
          <span><strong>{displayTitle(action.title)}</strong><small>{behaviors.get(method.behavior_id)?.title !== action.title ? `${displayTitle(behaviors.get(method.behavior_id)?.title ?? "")} · ` : ""}{action.platforms.join(" / ")}{method.behavior_id === step.behavior_id ? " · Primary step" : ""}</small></span></label>;
      })}</fieldset>
      {missing.map(method => <div className="adaptive-unavailable" key={methodKey(method)}><p>One selected method is no longer available.</p><Button size="small" onClick={() => setMethods(methods.filter(item => methodKey(item) !== methodKey(method)))}>Remove unavailable choice</Button><details><summary>Method identity</summary><code>{method.behavior_id} / {method.action_id}</code></details></div>)}
      <fieldset className="adaptive-outcome-options"><legend>Consider a retry after</legend>{(Object.keys(adaptiveOutcomeLabels) as AdaptiveOutcome[]).map(outcome => <label className="check-row" key={outcome}><input type="checkbox" checked={outcomes.includes(outcome)} onChange={event => setOutcomes(event.target.checked ? [...outcomes, outcome] : outcomes.filter(item => item !== outcome))} /><span>{adaptiveOutcomeLabels[outcome]}</span></label>)}</fieldset>
      <Field label="If the model cannot choose" hint="This setting and eligible outcomes apply to all adaptive steps in this experiment."><select value={failure} onChange={event => setFailure(event.target.value as "stop" | "deterministic")}><option value="stop">Stop and clean up</option><option value="deterministic">Use the saved route · deterministic fallback</option></select></Field>
      <fieldset className="adaptive-budget-mode"><legend>Retry budget</legend>
        <label className="check-row"><input type="radio" name={`retry-budget-${step.id}`} checked={!multiBudget} onChange={() => { setMultiBudget(false); setError(""); }} /><span><strong>One retry across this experiment</strong><small>{savedV2 ? "Restores the single-retry limit and removes per-step caps." : "Keeps the current single-retry limit."}</small></span></label>
        <label className="check-row"><input type="radio" name={`retry-budget-${step.id}`} checked={multiBudget} onChange={() => { setMultiBudget(true); setError(""); }} /><span><strong>Set limits for more alternatives</strong><small>Set separate experiment-wide and per-step caps. No limit increases until you choose them.</small></span></label>
      </fieldset>
      {multiBudget ? <div className="adaptive-budget-fields">
        <p>Each retry is one additional method after the step's initial method. These caps are part of the reviewed experiment and still need fresh Execute approval.</p>
        <Field label="Maximum extra tries across this experiment" hint={`Counts all adaptive steps together. Current step caps allow up to ${Number.isFinite(totalRetryCapacity) ? totalRetryCapacity : "Unknown"}; the maximum is 8.`}>
          <input type="number" min={1} max={maximumExperimentRetryCap} step={1} value={Number.isFinite(experimentRetryCap) ? experimentRetryCap : ""}
            onChange={event => setExperimentRetryCap(event.target.value === "" ? Number.NaN : Number(event.target.value))} />
        </Field>
        <Field label="Maximum extra tries for this step" hint={`A method can be selected only once. With ${methods.length} methods, this step allows up to ${maximumStepRetryCap} extra tries (maximum 3).`}>
          <input type="number" min={1} max={maximumStepRetryCap} step={1} value={Number.isFinite(stepRetryCap) ? stepRetryCap : ""}
            onChange={event => setStepRetryCap(event.target.value === "" ? Number.NaN : Number(event.target.value))} />
        </Field>
        {!validMultiBudget && maximumStepRetryCap < 1 ? <p className="field-error" role="alert">Select at least two distinct methods before setting a per-step retry cap.</p> : null}
        {!validMultiBudget && stepRetryCap > maximumStepRetryCap && maximumStepRetryCap >= 1 ? <p className="field-error" role="alert">This step's cap exceeds its available distinct methods. Lower the cap or select more methods.</p> : null}
        {!validMultiBudget && experimentRetryCap > maximumExperimentRetryCap ? <p className="field-error" role="alert">The experiment-wide cap cannot exceed the sum of the configured step caps.</p> : null}
      </div> : null}
      <p className="adaptive-choice-status" role="status">{methods.length} of 2–4 methods selected. {multiBudget ? `Up to ${Number.isFinite(experimentRetryCap) ? experimentRetryCap : "—"} extra tries across this experiment; each step has a separate cap.` : "One retry maximum across this experiment."} Run review sets the time, step, target and cleanup limits.{changed ? " Choices are not applied yet." : " Choices are saved in the working graph."}</p>
      {error ? <p className="field-error" role="alert">{error}</p> : null}
      <div className="adaptive-editor-actions"><Button size="small" variant="primary" onClick={apply} disabled={!ready || !changed}>Apply retry choices</Button>{saved ? <Button size="small" onClick={() => onChange(removeAdaptiveStep(scenario, step.id))}>Remove adaptive retry</Button> : <Button size="small" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>}</div>
    </>}
  </section>;
}

export function AdaptiveRepair({ scenario, behaviors, actions, overrides, onSelect, onChange, readOnly }: {
  scenario: Scenario; behaviors: ReadonlyMap<string, Behavior>; actions: ReadonlyMap<string, ActionDefinition>; overrides: Record<string, string>;
  onSelect: (step: string) => void; onChange: (scenario: Scenario) => void; readOnly?: boolean;
}) {
  const issues = adaptiveExecutionIssues(scenario, behaviors, actions, overrides);
  if (!issues.length) return null;
  return <section className="adaptive-repair" aria-label="Retry choices need attention"><strong>Review retry choices before saving or running</strong>
    {issues.map(issue => <div key={`${issue.stepId}:${issue.message}`}><p>{issue.message}</p>{issue.missingStep
      ? <Button size="small" disabled={readOnly} onClick={() => onChange(removeAdaptiveStep(scenario, issue.stepId))}>Remove choices for deleted step</Button>
      : <Button size="small" onClick={() => onSelect(issue.stepId)}>Review step choices</Button>}</div>)}
  </section>;
}
