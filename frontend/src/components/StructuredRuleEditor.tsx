import { buildStructuredSelection, readStructuredSelection, structuredRuleFields, structuredRuleLimits, structuredRuleOperators, structuredRuleSuggestions, type StructuredRuleCondition, type StructuredRuleDraft } from "../lib/structured-rule-selection";
import { Button, Field } from "./Primitives";
import "./StructuredRuleEditor.css";

const operatorLabels = { equals: "Equals (exact type and value)", contains: "Contains (ignore case)", startswith: "Starts with (ignore case)", endswith: "Ends with (ignore case)" };

export function StructuredRuleEditor({ source, draft, onDraft, onApply, disabled = false }: {
  source: string; draft: StructuredRuleDraft | null; onDraft: (value: StructuredRuleDraft | null) => void;
  onApply: (source: string) => void; disabled?: boolean;
}) {
  if (draft && draft.source !== source) return <div role="alert"><p>The retained condition edits belong to a different selection. The current selection has not been changed.</p><details><summary>Inspect retained condition edits</summary><pre>{JSON.stringify(draft.conditions, null, 2)}</pre></details><Button disabled={disabled} onClick={() => onDraft(null)}>Discard condition edits</Button></div>;
  const original = readStructuredSelection(source);
  if (!original.supported) return <div role="status"><strong>Visual editing unavailable</strong><p>{original.reason}</p></div>;
  const activeDraft = draft?.source === source ? draft : null;
  const pending = activeDraft !== null;
  const conditions = activeDraft?.conditions ?? original.conditions;
  const checked = buildStructuredSelection(conditions);
  const change = (next: StructuredRuleCondition[]) => onDraft({ source, conditions: next });
  const update = (index: number, next: Partial<StructuredRuleCondition>) => change(conditions.map((condition, at) => at === index ? { ...condition, ...next } : condition));
  return <section className="structured-rule-editor" aria-label="Visual rule conditions">
    <h4>Match all these conditions</h4>
    <p>Each condition must match the same observed record. Counts are whole numbers; permission bits do not establish effective access. Text operators ignore case; equality preserves the value's type.</p>
    {conditions.map((condition, index) => {
      const field = structuredRuleFields.find(item => item.key === condition.field)!;
      return <fieldset className="structured-condition" key={index} disabled={disabled}>
        <legend>Condition {index + 1}</legend>
        <div className="structured-condition-controls">
          <Field label="Field"><select aria-label={`Field for condition ${index + 1}`} value={condition.field} onChange={event => update(index, { field: event.target.value, operator: "equals" })}>{structuredRuleFields.map(item => <option key={item.key} value={item.key}>{item.label}</option>)}</select></Field>
          <Field label="Match"><select aria-label={`Operator for condition ${index + 1}`} value={condition.operator} onChange={event => update(index, { operator: event.target.value })}>{structuredRuleOperators(condition.field).map(operator => <option key={operator} value={operator}>{operatorLabels[operator]}</option>)}</select></Field>
          <div className="structured-condition-value"><Field label="Value" hint={field.type === "integer" ? "Non-negative whole number" : field.key === "permission_mode_octal" ? "Four octal digits; leading zeros are preserved." : undefined}>
            {field.type === "boolean" ? <select aria-label={`Value for condition ${index + 1}`} value={["true", "false"].includes(condition.value) ? condition.value : ""} onChange={event => update(index, { value: event.target.value })}><option value="" disabled>Choose Yes or No</option><option value="true">Yes</option><option value="false">No</option></select>
              : <input aria-label={`Value for condition ${index + 1}`} type="text" maxLength={structuredRuleLimits.stringLength} inputMode={field.type === "integer" ? "numeric" : undefined} value={condition.value} onChange={event => update(index, { value: event.target.value })} />}
          </Field>{structuredRuleSuggestions[field.key] ? <select aria-label={`Suggested value for condition ${index + 1}`} value="" onChange={event => update(index, { value: event.target.value })}><option value="" disabled>Use a suggested value</option>{structuredRuleSuggestions[field.key]!.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select> : null}</div>
          <Button size="small" aria-label={`Remove ${field.label} condition ${index + 1}`} onClick={() => change(conditions.filter((_, at) => at !== index))}>Remove</Button>
        </div>
      </fieldset>;
    })}
    {!checked.ok ? <p role="alert">{checked.error}</p> : null}
    <p role="status">{pending ? "Condition edits have not been applied. Apply or discard them before saving a revision or editing advanced JSON." : "These conditions match the current selection. Editing them does not save a revision or evaluate a run. Suggested values are optional; custom text is preserved."}</p>
    <div className="candidate-actions">
      <Button size="small" disabled={disabled || conditions.length >= structuredRuleLimits.conditions} onClick={() => change([...conditions, { field: "observation_kind", operator: "equals", value: "" }])}>Add condition</Button>
      <Button size="small" disabled={disabled || !pending || !checked.ok} onClick={() => { if (checked.ok) onApply(JSON.stringify(checked.selection, null, 2)); }}>Apply conditions</Button>
      {pending ? <Button size="small" disabled={disabled} onClick={() => onDraft(null)}>Discard condition edits</Button> : null}
    </div>
  </section>;
}
