import { permissionSelection, type PermissionCondition } from "./PermissionConditionControl";
import { Field } from "./Primitives";
import { StructuredRuleEditor } from "./StructuredRuleEditor";
import { buildStructuredSelection, readStructuredSelection, structuredRuleLimits } from "../lib/structured-rule-selection";
import type { ManualInternalConditions } from "../lib/manual-detection-definition";

export function NewInternalRuleConditions({ value, onChange }: { value: ManualInternalConditions; onChange: (value: ManualInternalConditions) => void }) {
  const pending = value.draft ? buildStructuredSelection(value.draft.conditions) : null;
  const oversized = pending?.ok && JSON.stringify(pending.selection, null, 2).length > structuredRuleLimits.sourceLength;
  const loadStarter = (starter: string) => {
    const selection = starter === "collection" ? { artifact_type: "collector_observation", observation_kind: "collection_semantics" } : permissionSelection(starter as PermissionCondition);
    const read = readStructuredSelection(JSON.stringify(selection));
    if (read.supported) onChange({ ...value, draft: { source: value.source, conditions: read.conditions } });
  };
  return <section aria-label="New internal rule conditions">
    <p>Choose the fields this rule will match, then apply the conditions before saving the rule draft. Apply keeps the definition here; it does not save, parse or evaluate a rule.</p>
    <Field label="Condition starter" hint="Choosing a starter replaces the conditions shown below. Apply to keep it, or discard condition edits to return to the last applied definition.">
      <select aria-label="Condition starter" value="" onChange={event => loadStarter(event.target.value)}>
        <option value="" disabled>Choose a starter (optional)</option>
        <option value="collection">Collection contents</option>
        <option value="staged">Staged file</option>
        <option value="world_writable">World-writable file</option>
        <option value="non_owner_writable">Non-owner writable file</option>
      </select>
    </Field>
    <StructuredRuleEditor purpose="creation" applyError={oversized ? "These conditions exceed the selection text limit. Shorten text values or remove conditions before applying. Your pending edits are still kept." : undefined} source={value.source} draft={value.draft} onDraft={draft => onChange({ ...value, draft })} onApply={source => { if (source.length <= structuredRuleLimits.sourceLength) onChange({ source, draft: null }); }} />
    {!value.draft ? <p role="status">{value.source !== "{}" ? "Applied conditions are ready to save as a rule draft." : "Add and apply at least one condition before saving."}</p> : null}
  </section>;
}
