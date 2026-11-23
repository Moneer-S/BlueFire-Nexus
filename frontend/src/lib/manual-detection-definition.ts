import { permissionSelection, type PermissionCondition } from "../components/PermissionConditionControl";
import { buildStructuredSelection, readStructuredRuleDraft, readStructuredSelection, structuredRuleLimits, type StructuredRuleDraft } from "./structured-rule-selection";

export interface ManualInternalConditions { source: string; draft: StructuredRuleDraft | null }
// Two verified source strings and the bounded condition values can each expand
// up to sixfold in JSON. Storage has its own lower limit and warning fallback.
const envelopeLength = 12 * structuredRuleLimits.sourceLength + 6 * structuredRuleLimits.conditions * structuredRuleLimits.stringLength + 8192;

/** One retained field keeps application and pending edits together across reload. */
export function readManualInternalConditions(text: string): ManualInternalConditions | null {
  if (!text || text.length > envelopeLength) return null;
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const record = value as Record<string, unknown>;
    if (Object.keys(record).length !== 2 || typeof record.source !== "string" || !readStructuredSelection(record.source).supported) return null;
    if (record.draft === null) return { source: record.source, draft: null };
    if (!record.draft || typeof record.draft !== "object" || Array.isArray(record.draft)) return null;
    const pending = record.draft as Record<string, unknown>;
    // Identical source text has already passed the same reader above.
    if (Object.keys(pending).length !== 2 || typeof pending.source !== "string"
      || (pending.source !== record.source && !readStructuredSelection(pending.source).supported)) return null;
    // Validate the original source separately so duplicating it in the envelope
    // cannot exhaust the shared draft parser's combined text budget. Its field,
    // operator, shape and value checks still apply to every pending condition.
    const checked = readStructuredRuleDraft(JSON.stringify({ ...pending, source: "{}" }));
    if (!checked) return null;
    return { source: record.source, draft: { source: pending.source, conditions: checked.conditions } };
  } catch { return null; }
}

export const isManualInternalConditionsText = (value: unknown): boolean => typeof value === "string" && (value === "" || readManualInternalConditions(value) !== null);

export function initialManualInternalConditions(condition: PermissionCondition): ManualInternalConditions {
  const original = readStructuredSelection(JSON.stringify(permissionSelection(condition)));
  return { source: "{}", draft: { source: "{}", conditions: original.supported ? original.conditions : [] } };
}

export function manualDetectionDefinition(language: string, internal: ManualInternalConditions) {
  if (language === "internal" && internal.draft !== null) return null;
  const original = readStructuredSelection(internal.source);
  const checked = original.supported ? buildStructuredSelection(original.conditions) : null;
  if (language === "internal" && !checked?.ok) return null;
  const selection = language === "internal" && checked?.ok ? checked.selection : permissionSelection("staged");
  return {
    selection,
    logsource: selection.observation_kind === "collection_semantics" ? { category: "collection", product: "bluefire" } : { category: "file_event", product: "generic" },
    predicted_fields: [...new Set(Object.keys(selection).map(key => key.split("|")[0]!))],
  };
}
