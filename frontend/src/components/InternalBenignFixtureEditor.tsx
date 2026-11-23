import { useMemo } from "react";
import { buildInternalBenignFixtures, internalBenignFixtureLimits, nextInternalBenignFixtureName, readInternalBenignFixtures, type InternalBenignFixtureDraft, type InternalBenignFixtureSample } from "../lib/internal-benign-fixtures";
import { structuredRuleFields, structuredRuleSuggestions } from "../lib/structured-rule-selection";
import { Button, Field } from "./Primitives";
import "./InternalBenignFixtureEditor.css";

export function InternalBenignFixtureEditor({ source, draft, onDraft, onApply, selection, disabled = false }: {
  source: string;
  draft: InternalBenignFixtureDraft | null;
  onDraft: (value: InternalBenignFixtureDraft | null) => void;
  onApply: (source: string) => void;
  selection?: Record<string, unknown>;
  disabled?: boolean;
}) {
  const original = useMemo(() => readInternalBenignFixtures(source), [source]);
  if (draft && draft.source !== source) return <div role="alert"><p>These sample edits belong to different JSON inputs. The current inputs have not been changed.</p><details><summary>Inspect retained sample edits</summary><pre>{JSON.stringify(draft.samples, null, 2)}</pre></details><Button disabled={disabled} onClick={() => onDraft(null)}>Discard sample edits</Button></div>;
  if (!original.supported) return <div role="status"><p>Use JSON for these samples. {original.reason}</p></div>;
  const samples = draft?.samples ?? original.samples;
  const checked = buildInternalBenignFixtures(samples);
  const selectedFields = [...new Set(Object.keys(selection ?? {}).map(key => key.split("|")[0]!))];
  const change = (next: InternalBenignFixtureSample[]) => onDraft({ source, samples: next });
  const update = (index: number, next: Partial<InternalBenignFixtureSample>) => change(samples.map((sample, at) => at === index ? { ...sample, ...next } : sample));

  return <section className="internal-benign-editor" aria-label="Authored benign samples">
    <h4>Describe benign samples</h4>
    <p>Author synthetic records that represent benign activity, then evaluate them with your notes. These inputs are not observed evidence. Calling a sample benign does not prevent a match.</p>
    <p><strong>Omitted fields are unknown.</strong> A missing rule field causes a nonmatch; that result does not establish benign coverage. Add only facts you intend to supply. Remove a field to leave it out.</p>
    {samples.map((sample, sampleIndex) => {
      const missing = selectedFields.filter(field => field !== "fixture_id" && !sample.fields.some(input => input.field === field));
      return <fieldset className="internal-benign-sample" key={sampleIndex} disabled={disabled}>
        <legend>Sample {sampleIndex + 1}</legend>
        <Field label="Sample name" hint="Unique within this set. Use letters, numbers, dots, underscores, colons or hyphens."><input aria-label={`Sample name ${sampleIndex + 1}`} type="text" value={sample.fixtureId} maxLength={internalBenignFixtureLimits.nameLength} onChange={event => update(sampleIndex, { fixtureId: event.target.value })} /></Field>
        {sample.fields.map((input, fieldIndex) => {
          const field = structuredRuleFields.find(item => item.key === input.field);
          const updateField = (next: Partial<typeof input>) => update(sampleIndex, { fields: sample.fields.map((item, at) => at === fieldIndex ? { ...item, ...next } : item) });
          const suffix = `${fieldIndex + 1} for sample ${sampleIndex + 1}`;
          return <div className="internal-benign-field" key={fieldIndex}>
            <Field label="Field"><select aria-label={`Field ${suffix}`} value={input.field} onChange={event => updateField({ field: event.target.value, value: "" })}><option value="">Choose a field</option>{structuredRuleFields.map(item => <option key={item.key} value={item.key}>{item.label}</option>)}</select></Field>
            <div className="internal-benign-value"><Field label="Value" hint={field?.type === "integer" ? "Non-negative whole number. Blank is incomplete; remove the row to omit it." : field?.key === "permission_mode_octal" ? "Four octal digits. Mode bits do not establish effective access." : field?.type === "string" ? "An empty value is an authored empty string. Remove the row to omit it." : undefined}>
              {field?.type === "boolean" ? <select aria-label={`Value ${suffix}`} value={input.value} onChange={event => updateField({ value: event.target.value })}><option value="">Choose Yes or No</option>{!["", "true", "false"].includes(input.value) ? <option value={input.value}>Choose again: retained value is invalid</option> : null}<option value="true">Yes</option><option value="false">No</option></select>
                : field?.type === "string" ? <textarea aria-label={`Value ${suffix}`} rows={2} value={input.value} maxLength={internalBenignFixtureLimits.stringLength} onChange={event => updateField({ value: event.target.value })} />
                  : <input aria-label={`Value ${suffix}`} disabled={!field} type="text" inputMode={field?.type === "integer" ? "numeric" : undefined} value={input.value} maxLength={internalBenignFixtureLimits.stringLength} onChange={event => updateField({ value: event.target.value })} />}
            </Field>{field && structuredRuleSuggestions[field.key] ? <select aria-label={`Suggested value ${suffix}`} value="" onChange={event => updateField({ value: event.target.value })}><option value="" disabled>Use a suggested value</option>{structuredRuleSuggestions[field.key]!.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select> : null}</div>
            <Button size="small" aria-label={`Remove field ${fieldIndex + 1} from sample ${sampleIndex + 1}`} onClick={() => update(sampleIndex, { fields: sample.fields.filter((_, at) => at !== fieldIndex) })}>Remove field</Button>
          </div>;
        })}
        {missing.length ? <p className="internal-benign-missing">Missing rule fields: {missing.map(name => structuredRuleFields.find(field => field.key === name)?.label ?? name).join(", ")}. This sample cannot match all the rule's conditions.</p> : null}
        <div className="candidate-actions"><Button size="small" disabled={sample.fields.length >= internalBenignFixtureLimits.fields} onClick={() => update(sampleIndex, { fields: [...sample.fields, { field: "", value: "" }] })}>Add field to sample {sampleIndex + 1}</Button><Button size="small" onClick={() => change(samples.filter((_, at) => at !== sampleIndex))}>Remove sample {sampleIndex + 1}</Button></div>
      </fieldset>;
    })}
    {draft && !checked.ok ? <p role="alert">{checked.error}</p> : null}
    <p role="status">{draft ? "Sample edits have not been applied. Apply or discard them before editing JSON or evaluating benign samples." : "Editing or applying these samples does not evaluate the rule. Evaluation is a separate action."}</p>
    <div className="candidate-actions">
      <Button size="small" disabled={disabled || samples.length >= internalBenignFixtureLimits.samples} onClick={() => change([...samples, { fixtureId: nextInternalBenignFixtureName(samples), fields: [] }])}>Add sample</Button>
      <Button size="small" disabled={disabled || !draft || !checked.ok} onClick={() => { if (!disabled && draft && draft.source === source && checked.ok) onApply(JSON.stringify(checked.fixtures)); }}>Apply samples</Button>
      {draft ? <Button size="small" disabled={disabled} onClick={() => onDraft(null)}>Discard sample edits</Button> : null}
    </div>
  </section>;
}
