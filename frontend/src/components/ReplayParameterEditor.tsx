import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { parameterValuesEqual } from "../lib/parameters";
import type { Behavior, ParameterSpec, Scenario } from "../types";
import { ParameterField } from "./ParameterField";
import { Button, Callout, sentence } from "./Primitives";

export type ReplayParameterOverrides = Record<string, Record<string, unknown>>;
export interface ReplayParameterEditorProps {
  scenario: Scenario;
  behaviors: readonly Behavior[];
  value: ReplayParameterOverrides;
  onChange: (value: ReplayParameterOverrides) => void;
  /** The caller must clear prior review and prevent preparation/submission while false. */
  onValidityChange?: (valid: boolean) => void;
  disabled?: boolean;
}

const owns = (object: object, key: string) => Object.prototype.hasOwnProperty.call(object, key);
const fieldKey = (step: string, parameter: string) => `${step}:${parameter}`;
const label = (name: string) => sentence(name.replaceAll("_", " "));
const displayValue = (value: unknown) => value === undefined ? "Not set in original" : value === null ? "Null in original" : Array.isArray(value) ? value.length ? value.join(", ") : "Empty list" : typeof value === "boolean" ? value ? "Yes" : "No" : value === "" ? "Empty text" : String(value);

function valueError(spec: ParameterSpec, value: unknown): string | undefined {
  if (spec.enum?.length && !spec.enum.some((item) => parameterValuesEqual(item, value))) return "Choose an allowed value.";
  if (spec.type === "integer" || spec.type === "number") {
    if (typeof value !== "number" || !Number.isFinite(value)) return "Enter a number before reviewing this change.";
    if (spec.type === "integer" && !Number.isInteger(value)) return "Enter a whole number.";
    if (spec.minimum != null && value < spec.minimum) return `Enter ${spec.minimum} or more.`;
    if (spec.maximum != null && value > spec.maximum) return `Enter ${spec.maximum} or less.`;
  } else if (spec.type === "boolean" && typeof value !== "boolean") return "Choose a boolean value.";
  else if (spec.type === "string" && typeof value !== "string") return "Enter text for this change.";
  else if (spec.type === "string_list" && (!Array.isArray(value) || !value.every((item) => typeof item === "string"))) return "Enter a list of text values.";
  return undefined;
}

function draftError(spec: ParameterSpec, draft: string): string | undefined {
  return valueError(spec, spec.type === "string_list" ? draft.split(",").map((item) => item.trim()).filter(Boolean) : draft.trim() ? Number(draft) : undefined);
}

export function ReplayParameterEditor(props: ReplayParameterEditorProps) {
  // Source/catalog replacements discard local edit buffers even if IDs were reused.
  const sourceKey = JSON.stringify([props.scenario, props.behaviors.map((item) => [item.id, item.parameters])]);
  return <ParameterChanges key={sourceKey} {...props} />;
}

function ParameterChanges({ scenario, behaviors, value, onChange, onValidityChange, disabled = false }: ReplayParameterEditorProps) {
  const behaviorMap = useMemo(() => new Map(behaviors.map((item) => [item.id, item])), [behaviors]);
  const rows = scenario.steps.map((step, index) => ({ step, index, behavior: behaviorMap.get(step.behavior_id) }));
  const [editing, setEditing] = useState<Record<string, boolean>>({});
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const draftsRef = useRef(drafts);
  const editingRef = useRef(editing);
  const pendingEmission = useRef<string | undefined>(undefined);
  const editorRef = useRef<HTMLElement>(null);
  const pendingFocus = useRef<{ key: string; target: "input" | "button" } | undefined>(undefined);
  const validityCallback = useRef(onValidityChange);
  validityCallback.current = onValidityChange;

  const errorsFor = (overrides: ReplayParameterOverrides, numericDrafts: Record<string, string>, active: Record<string, boolean>) => {
    const errors: Record<string, string> = {};
    for (const [stepId, parameters] of Object.entries(overrides)) {
      const row = rows.find(({ step }) => step.id === stepId);
      if (!row?.behavior || !parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
        errors[stepId] = "This override has no available step or parameter definition.";
        continue;
      }
      for (const name of Object.keys(parameters)) if (!row.behavior.parameters.some((spec) => spec.name === name)) errors[fieldKey(stepId, name)] = "This parameter is unavailable. Remove its override or review the advanced input.";
    }
    for (const { step, behavior } of rows) for (const spec of behavior?.parameters ?? []) {
      const key = fieldKey(step.id, spec.name);
      const parameters = overrides[step.id] ?? {};
      const overridden = owns(parameters, spec.name);
      const error = owns(numericDrafts, key) ? draftError(spec, numericDrafts[key]!) : overridden || active[key] ? valueError(spec, overridden ? parameters[spec.name] : step.parameters[spec.name]) : undefined;
      if (error) errors[key] = error;
    }
    return errors;
  };
  const reportValidity = (nextValue = value, nextDrafts = draftsRef.current, nextEditing = editingRef.current) => validityCallback.current?.(!Object.keys(errorsFor(nextValue, nextDrafts, nextEditing)).length);
  const receiveValue = useRef(value);
  useEffect(() => {
    if (receiveValue.current !== value) {
      const ownEcho = pendingEmission.current === JSON.stringify(value);
      pendingEmission.current = undefined;
      receiveValue.current = value;
      if (!ownEcho) {
        draftsRef.current = {}; editingRef.current = {};
        setDrafts({}); setEditing({});
      }
    }
    reportValidity();
    // Value replacement is the external reset boundary; callbacks may be recreated per render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  useEffect(() => {
    const requested = pendingFocus.current;
    if (!requested) return;
    const row = Array.from(editorRef.current?.querySelectorAll<HTMLElement>("[data-parameter-key]") ?? []).find((item) => item.dataset.parameterKey === requested.key);
    row?.querySelector<HTMLElement>(requested.target === "input" ? "input, select" : "button")?.focus();
    pendingFocus.current = undefined;
  }, [editing]);

  const emit = (next: ReplayParameterOverrides) => {
    reportValidity(next);
    if (JSON.stringify(next) === JSON.stringify(value)) return;
    pendingEmission.current = JSON.stringify(next);
    onChange(next);
  };
  const start = (stepId: string, name: string) => {
    if (disabled) return;
    const key = fieldKey(stepId, name);
    pendingFocus.current = { key, target: "input" };
    editingRef.current = { ...editingRef.current, [key]: true };
    setEditing(editingRef.current);
    reportValidity();
  };
  const reset = (stepId: string, name: string) => {
    if (disabled) return;
    const key = fieldKey(stepId, name);
    pendingFocus.current = { key, target: "button" };
    const nextDrafts = { ...draftsRef.current }; delete nextDrafts[key];
    const nextEditing = { ...editingRef.current }; delete nextEditing[key];
    draftsRef.current = nextDrafts; editingRef.current = nextEditing;
    setDrafts(nextDrafts); setEditing(nextEditing);
    const next = { ...value, [stepId]: { ...value[stepId] } };
    delete next[stepId]![name];
    if (!Object.keys(next[stepId]!).length) delete next[stepId];
    emit(next);
  };
  const captureDraft = (event: FormEvent<HTMLDivElement>, stepId: string, spec: ParameterSpec) => {
    if (disabled || spec.enum?.length || !(event.target instanceof HTMLInputElement) || (event.target.type !== "number" && spec.type !== "string_list")) return;
    draftsRef.current = { ...draftsRef.current, [fieldKey(stepId, spec.name)]: event.target.value };
    setDrafts(draftsRef.current);
    reportValidity();
  };
  const change = (stepId: string, spec: ParameterSpec, nextValue: unknown) => {
    if (disabled || nextValue === undefined || valueError(spec, nextValue)) return;
    const key = fieldKey(stepId, spec.name);
    if (owns(draftsRef.current, key) && draftError(spec, draftsRef.current[key]!)) return;
    const next = { ...value, [stepId]: { ...value[stepId], [spec.name]: nextValue } };
    const source = scenario.steps.find((step) => step.id === stepId)!;
    if (owns(source.parameters, spec.name) && parameterValuesEqual(source.parameters[spec.name], nextValue)) {
      delete next[stepId]![spec.name];
      if (!Object.keys(next[stepId]!).length) delete next[stepId];
    }
    emit(next);
  };
  const errors = errorsFor(value, drafts, editing);
  const knownKeys = new Set(rows.flatMap(({ step, behavior }) => (behavior?.parameters ?? []).map((spec) => fieldKey(step.id, spec.name))));
  const unavailable = Object.entries(errors).filter(([key]) => !knownKeys.has(key));
  return <section ref={editorRef} className="replay-parameter-editor" aria-label="Replay parameter changes">
    <p>Choose a value to change. Original values stay untouched; reset an override to use the original again. The server checks the complete replay before it runs.</p>
    {unavailable.length ? <Callout tone="danger" title="Some overrides need attention"><ul>{unavailable.map(([key, error]) => <li key={key}>{key}: {error}</li>)}</ul></Callout> : null}
    {rows.map(({ step, index, behavior }) => <details key={step.id} className="replay-parameter-step" open={index === 0 || Boolean(value[step.id])}>
      <summary><strong>Step {index + 1}: {behavior?.title ?? label(step.id)}</strong><span> · {Object.keys(value[step.id] ?? {}).length} overrides</span></summary>
      <fieldset disabled={disabled} aria-label={`Step ${index + 1}: ${behavior?.title ?? label(step.id)}`}>
        {!behavior ? <p>Parameter definitions are unavailable for this step.</p> : !behavior.parameters.length ? <p>This step has no configurable parameters.</p> : behavior.parameters.map((spec) => {
          const key = fieldKey(step.id, spec.name);
          const overridden = owns(value[step.id] ?? {}, spec.name);
          const active = Boolean(editing[key]) || overridden;
          const original = step.parameters[spec.name];
          const changed = overridden && !parameterValuesEqual(original, value[step.id]![spec.name]);
          const current = owns(drafts, key) ? drafts[key] : overridden ? value[step.id]![spec.name] : original;
          const errorId = `replay-parameter-error-${step.id}-${spec.name}`;
          return <div key={spec.name} data-parameter-key={key} className="replay-parameter-row" role="group" aria-label={label(spec.name)} aria-invalid={Boolean(errors[key])} aria-describedby={errors[key] ? errorId : undefined} onChangeCapture={(event) => captureDraft(event, step.id, spec)}>
            <p><strong>{label(spec.name)}</strong><span> · Original: {displayValue(original)}</span></p>
            {active ? <><ParameterField spec={{ ...spec, name: label(spec.name) }} value={current} onChange={(next) => change(step.id, spec, next)} /><p className="field-note">{errors[key] ? "Unfinished change · review is unavailable" : changed ? "Override changed" : overridden ? "Override matches original" : "Original value retained"}</p><Button size="small" disabled={disabled} onClick={() => reset(step.id, spec.name)} aria-label={`Reset ${label(spec.name)} to original`}>Use original</Button></> : <Button size="small" disabled={disabled} onClick={() => start(step.id, spec.name)} aria-label={`Change ${label(spec.name)}`}>Change value</Button>}
            {errors[key] ? <p className="field-error" role="alert" id={errorId}>{errors[key]}</p> : null}
          </div>;
        })}
      </fieldset>
    </details>)}
    {!rows.length ? <p>This experiment has no steps to edit.</p> : null}
  </section>;
}
