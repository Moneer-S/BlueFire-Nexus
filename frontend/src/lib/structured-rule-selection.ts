/** A deliberately small visual subset of the internal matcher's flat AND selection. */
export const structuredRuleFields = [
  { key: "artifact_type", label: "Evidence type", type: "string" },
  { key: "observation_kind", label: "Observation kind", type: "string" },
  { key: "path", label: "Observed path", type: "string" },
  { key: "container", label: "Collection format", type: "string" },
  { key: "record_count", label: "Total records", type: "integer" },
  { key: "retained_record_count", label: "Records retaining values", type: "integer" },
  { key: "redacted_record_count", label: "Redacted records", type: "integer" },
  { key: "empty_record_count", label: "Empty records", type: "integer" },
  { key: "permission_status", label: "Permission observation status", type: "string" },
  { key: "permission_mode_octal", label: "Permission mode (four octal digits)", type: "string" },
  { key: "group_write_bit", label: "Group write bit", type: "boolean" },
  { key: "other_write_bit", label: "Other write bit", type: "boolean" },
  { key: "non_owner_write_bit", label: "Group or other write bit", type: "boolean" },
  { key: "effective_access", label: "Effective access evaluation", type: "string" },
] as const;

export type StructuredRuleField = typeof structuredRuleFields[number]["key"];
export type StructuredRuleOperator = "equals" | "contains" | "startswith" | "endswith";
export type StructuredRuleCondition = { field: string; operator: string; value: string };
export type StructuredRuleDraft = { source: string; conditions: StructuredRuleCondition[] };
export const structuredRuleLimits = { conditions: 32, stringLength: 4096, sourceLength: 262144, draftLength: 1048576 } as const;

// Suggestions mirror emitted evidence/collector fields; custom string values remain editable.
export const structuredRuleSuggestions: Partial<Record<StructuredRuleField, ReadonlyArray<{ value: string; label: string }>>> = {
  artifact_type: [{ value: "collector_observation", label: "Independent observation" }, { value: "file_observation", label: "Legacy file observation" }],
  observation_kind: [{ value: "collection_semantics", label: "Collection contents" }, { value: "filesystem", label: "Filesystem metadata" }],
  container: [{ value: "jsonl", label: "JSONL records" }, { value: "gzip", label: "Gzip compressed records" }, { value: "ustar", label: "USTAR archive" }],
  permission_status: [{ value: "available", label: "Available" }, { value: "unavailable_windows", label: "Unavailable on Windows" }, { value: "unsupported_platform", label: "Unsupported platform" }],
  effective_access: [{ value: "not_evaluated", label: "Not evaluated" }],
};

export function structuredRuleOperators(field: string): StructuredRuleOperator[] {
  return structuredRuleFields.find(item => item.key === field)?.type === "string"
    ? ["equals", "contains", "startswith", "endswith"] : ["equals"];
}

type SelectionResult = { ok: true; selection: Record<string, string | boolean | number> } | { ok: false; error: string };

// JSON.parse accepts duplicate keys. Refuse visual rewriting rather than silently
// discarding an earlier condition. This scans already-validated JSON, not a new parser.
function hasDuplicateKeys(source: string): boolean {
  const keys = new Set<string>();
  let depth = 0, expectsKey = false;
  for (let at = 0; at < source.length; at += 1) {
    const char = source[at];
    if (char === '"') {
      const start = at;
      for (at += 1; at < source.length; at += 1) {
        if (source[at] === "\\") at += 1;
        else if (source[at] === '"') break;
      }
      if (depth === 1 && expectsKey) {
        const key = JSON.parse(source.slice(start, at + 1)) as string;
        if (keys.has(key)) return true;
        keys.add(key); expectsKey = false;
      }
    } else if (char === "{" || char === "[") { depth += 1; if (depth === 1) expectsKey = true; }
    else if (char === "}" || char === "]") depth -= 1;
    else if (char === "," && depth === 1) expectsKey = true;
  }
  return false;
}

export function buildStructuredSelection(conditions: readonly StructuredRuleCondition[]): SelectionResult {
  if (!conditions.length || conditions.length > structuredRuleLimits.conditions) return { ok: false, error: "Use between 1 and 32 conditions. An empty rule cannot be applied." };
  const selection: Record<string, string | boolean | number> = {};
  for (const [index, condition] of conditions.entries()) {
    const field = structuredRuleFields.find(item => item.key === condition.field);
    const refuse = (message: string): SelectionResult => ({ ok: false, error: `Condition ${index + 1}: ${message}` });
    if (!field) return refuse("choose a supported field.");
    if (!structuredRuleOperators(field.key).includes(condition.operator as StructuredRuleOperator)) return refuse("choose an operator supported by this field.");
    if (typeof condition.value !== "string") return refuse("the draft value must be text.");
    const key = field.key + (condition.operator === "equals" ? "" : `|${condition.operator}`);
    if (Object.hasOwn(selection, key)) return refuse("this field and operator are already present. Edit the existing condition instead.");
    let value: string | boolean | number = condition.value;
    if (field.type === "boolean") {
      if (value !== "true" && value !== "false") return refuse("choose Yes or No.");
      value = value === "true";
    } else if (field.type === "integer") {
      if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) return refuse("enter a non-negative whole number no larger than 9007199254740991.");
      value = Number(value);
    } else {
      if (value.length > structuredRuleLimits.stringLength) return refuse("text exceeds the visual editor's 4096-character limit. Keep it in advanced JSON.");
      if (field.key === "permission_mode_octal" && condition.operator === "equals" && !/^[0-7]{4}$/.test(value)) return refuse("enter four octal digits, such as 0660.");
    }
    selection[key] = value;
  }
  return { ok: true, selection };
}

export function readStructuredSelection(source: string): { supported: true; conditions: StructuredRuleCondition[] } | { supported: false; reason: string } {
  const unavailable = (reason: string) => ({ supported: false as const, reason });
  if (source.length > structuredRuleLimits.sourceLength) return unavailable("This selection exceeds the visual editor's text limit. Keep it unchanged in advanced structured inputs.");
  let value: unknown;
  try { value = JSON.parse(source); } catch { return unavailable("The selection is not valid JSON. Correct it in advanced structured inputs; its text has not been changed."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) return unavailable("The selection must be an object. Advanced structured inputs retain the original value.");
  if (hasDuplicateKeys(source)) return unavailable("This selection repeats a field and operator. Resolve the duplicate in advanced structured inputs; no condition has been discarded.");
  const entries = Object.entries(value);
  if (entries.length > structuredRuleLimits.conditions) return unavailable("This selection exceeds the visual editor's 32-condition limit. All conditions remain in advanced structured inputs.");
  const conditions: StructuredRuleCondition[] = [];
  for (const [key, expected] of entries) {
    const [name, operator, extra] = key.split("|");
    const field = structuredRuleFields.find(item => item.key === name);
    if (!field || extra !== undefined || (operator !== undefined && !["contains", "startswith", "endswith"].includes(operator))) return unavailable("This selection includes an unsupported field or operator. Use advanced structured inputs; no conditions have been removed.");
    if ((field.type === "string" && typeof expected !== "string")
      || (field.type === "boolean" && typeof expected !== "boolean")
      || (field.type === "integer" && (typeof expected !== "number" || !Number.isSafeInteger(expected) || expected < 0))) return unavailable("This selection includes a complex value or a value with a different type. Use advanced structured inputs; no values have been converted.");
    conditions.push({ field: field.key, operator: operator ?? "equals", value: String(expected) });
  }
  // Empty objects can be authored here, but cannot be applied until a condition is added.
  if (conditions.length) {
    const result = buildStructuredSelection(conditions);
    if (!result.ok) return unavailable(`${result.error} The original selection remains in advanced structured inputs.`);
  }
  return { supported: true, conditions };
}

/** Retain incomplete typed input, but never trust a stored arbitrary object as editor state. */
export function readStructuredRuleDraft(text: string): StructuredRuleDraft | null {
  if (!text || text.length > structuredRuleLimits.draftLength) return null;
  let value: unknown;
  try { value = JSON.parse(text); } catch { return null; }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const draft = value as Record<string, unknown>;
  if (Object.keys(draft).length !== 2 || typeof draft.source !== "string" || !readStructuredSelection(draft.source).supported
    || !Array.isArray(draft.conditions) || draft.conditions.length > structuredRuleLimits.conditions) return null;
  if (!draft.conditions.every(item => item && typeof item === "object" && !Array.isArray(item) && Object.keys(item).length === 3
    && typeof item.field === "string" && structuredRuleFields.some(field => field.key === item.field)
    && typeof item.operator === "string" && structuredRuleOperators(item.field).includes(item.operator as StructuredRuleOperator)
    && typeof item.value === "string" && item.value.length <= structuredRuleLimits.stringLength)) return null;
  return { source: draft.source, conditions: draft.conditions as StructuredRuleCondition[] };
}

export function isStructuredRuleDraftText(value: unknown): boolean {
  return typeof value === "string" && (value === "" || readStructuredRuleDraft(value) !== null);
}
