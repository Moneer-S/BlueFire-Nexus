import { structuredRuleFields } from "./structured-rule-selection";

/** A visual subset of authored fixtures, not the backend's full finite-JSON schema. */
export const internalBenignFixtureLimits = {
  samples: 16,
  fields: structuredRuleFields.length,
  nameLength: 200,
  stringLength: 4096,
  sourceBytes: 1024 * 1024,
  fixtureBytes: 1024 * 1024,
} as const;

export type InternalBenignFixtureField = { field: string; value: string };
export type InternalBenignFixtureSample = { fixtureId: string; fields: InternalBenignFixtureField[] };
export type InternalBenignFixtureDraft = { source: string; samples: InternalBenignFixtureSample[] };
type Fixture = Record<string, string | number | boolean>;
type BuildResult = { ok: true; fixtures: Fixture[] } | { ok: false; error: string };
type ReadResult = { supported: true; samples: InternalBenignFixtureSample[] } | { supported: false; reason: string };

// Each UTF-16 unit can require six characters when embedded in the draft's JSON.
// Include every allowed source/row value, names, field names and structural overhead.
const maximumDraftLength = 6 * (internalBenignFixtureLimits.sourceBytes
  + internalBenignFixtureLimits.samples * (internalBenignFixtureLimits.nameLength
    + internalBenignFixtureLimits.fields * (64 + internalBenignFixtureLimits.stringLength))) + 65536;
// A strict end assertion also rejects a final newline (JavaScript's $ alone does not).
const fixtureIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}(?![\s\S])/;
const wholeNumberPattern = /^(0|[1-9][0-9]*)(?![\s\S])/;
const byteLength = (value: string) => new TextEncoder().encode(value).byteLength;
const isObject = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);

function unicodeIsWellFormed(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

/** Scan already-valid JSON. Decoded duplicate keys and rounded numeric spellings cannot be rewritten safely. */
function inspectJsonTokens(source: string): { duplicateKeys: boolean; unsupportedNumber: boolean } {
  const objects: Array<Set<string> | null> = [];
  let unsupportedNumber = false;
  for (let at = 0; at < source.length; at += 1) {
    const char = source[at]!;
    if (char === '"') {
      const start = at;
      for (at += 1; at < source.length; at += 1) {
        if (source[at] === "\\") at += 1;
        else if (source[at] === '"') break;
      }
      let after = at + 1;
      while (/\s/.test(source[after] ?? "") && after < source.length) after += 1;
      if (source[after] === ":") {
        const key = JSON.parse(source.slice(start, at + 1)) as string;
        const keys = objects[objects.length - 1];
        if (keys?.has(key)) return { duplicateKeys: true, unsupportedNumber };
        keys?.add(key);
      }
    } else if (char === "{") objects.push(new Set());
    else if (char === "[") objects.push(null);
    else if (char === "}" || char === "]") objects.pop();
    else if (char === "-" || /[0-9]/.test(char)) {
      const start = at;
      while (at + 1 < source.length && /[0-9.eE+-]/.test(source[at + 1]!)) at += 1;
      const token = source.slice(start, at + 1);
      if (!wholeNumberPattern.test(token) || !Number.isSafeInteger(Number(token))) unsupportedNumber = true;
    }
  }
  return { duplicateKeys: false, unsupportedNumber };
}

export function buildInternalBenignFixtures(samples: readonly InternalBenignFixtureSample[]): BuildResult {
  const limits = internalBenignFixtureLimits;
  if (!samples.length || samples.length > limits.samples) return { ok: false, error: "Add between 1 and 16 authored samples before applying." };
  const ids = new Set<string>();
  const fixtures: Fixture[] = [];
  for (const [index, sample] of samples.entries()) {
    const refuse = (error: string): BuildResult => ({ ok: false, error: `Sample ${index + 1}: ${error}` });
    if (typeof sample.fixtureId !== "string" || !fixtureIdPattern.test(sample.fixtureId)) return refuse("use a unique name of 1–200 letters, numbers, dots, underscores, colons or hyphens, starting with a letter or number.");
    if (ids.has(sample.fixtureId)) return refuse("this sample name is already used.");
    ids.add(sample.fixtureId);
    if (sample.fields.length > limits.fields) return refuse("use each supported field at most once.");
    const fixture: Fixture = { fixture_id: sample.fixtureId };
    for (const input of sample.fields) {
      const field = structuredRuleFields.find(item => item.key === input.field);
      if (!field) return refuse("choose a field for each row, or remove its row to omit it.");
      if (Object.hasOwn(fixture, field.key)) return refuse(`${field.label} is already present. Remove the extra row.`);
      if (typeof input.value !== "string" || input.value.length > limits.stringLength) return refuse(`${field.label} exceeds the visual editor's 4096-character limit. Keep longer values in JSON.`);
      let value: string | number | boolean = input.value;
      if (field.type === "boolean") {
        if (value !== "true" && value !== "false") return refuse(`choose Yes or No for ${field.label}, or remove its row to omit it.`);
        value = value === "true";
      } else if (field.type === "integer") {
        if (!wholeNumberPattern.test(value) || !Number.isSafeInteger(Number(value))) return refuse(`${field.label} needs a non-negative whole number no larger than 9007199254740991.`);
        value = Number(value);
      } else {
        if (!unicodeIsWellFormed(value)) return refuse(`${field.label} contains an incomplete Unicode character. Keep it in JSON until corrected.`);
        if (value.includes("\r")) return refuse(`${field.label} contains carriage returns that a text box cannot preserve. Keep that value in JSON.`);
        if (field.key === "permission_mode_octal" && !/^[0-7]{4}(?![\s\S])/.test(value)) return refuse("permission mode needs four octal digits, such as 0660.");
      }
      fixture[field.key] = value;
    }
    fixtures.push(fixture);
  }
  // These scalar values serialize with the same UTF-8 byte length as backend compact JSON.
  if (byteLength(JSON.stringify(fixtures)) > limits.fixtureBytes) return { ok: false, error: "These samples exceed the one-megabyte fixture limit. Shorten or remove values before applying; your edits are kept." };
  return { ok: true, fixtures };
}

export function readInternalBenignFixtures(source: string): ReadResult {
  const unavailable = (reason: string): ReadResult => ({ supported: false, reason: `${reason} The original JSON has not been changed.` });
  if (source.length > internalBenignFixtureLimits.sourceBytes || byteLength(source) > internalBenignFixtureLimits.sourceBytes) return unavailable("This text exceeds the visual editor's one-megabyte input limit. Continue editing it in JSON.");
  if (!source.trim()) return { supported: true, samples: [] };
  let value: unknown;
  try { value = JSON.parse(source); } catch { return unavailable("Correct the sample JSON before using these fields."); }
  if (!Array.isArray(value) || value.length > internalBenignFixtureLimits.samples) return unavailable("Visual editing supports an array of at most 16 samples. Larger sets stay in JSON.");
  const tokens = inspectJsonTokens(source);
  if (tokens.duplicateKeys) return unavailable("A sample repeats a JSON key. Resolve it in JSON before using these fields.");
  if (tokens.unsupportedNumber) return unavailable("A number needs a different spelling or range from these whole-number inputs. Keep it in JSON.");
  const samples: InternalBenignFixtureSample[] = [];
  for (const row of value) {
    if (!isObject(row) || typeof row.fixture_id !== "string") return unavailable("Each sample needs a text fixture_id in JSON.");
    const fields: InternalBenignFixtureField[] = [];
    for (const [name, entry] of Object.entries(row)) {
      if (name === "fixture_id") continue;
      const field = structuredRuleFields.find(item => item.key === name);
      if (!field) return unavailable("These samples include a field outside the visual editor. Keep all fields in JSON.");
      if ((field.type === "string" && typeof entry !== "string")
        || (field.type === "boolean" && typeof entry !== "boolean")
        || (field.type === "integer" && (typeof entry !== "number" || !Number.isSafeInteger(entry) || entry < 0))) return unavailable("These samples include a complex value or a different field type. Keep all values in JSON.");
      fields.push({ field: name, value: String(entry) });
    }
    samples.push({ fixtureId: row.fixture_id, fields });
  }
  if (samples.length) {
    const checked = buildInternalBenignFixtures(samples);
    if (!checked.ok) return unavailable(checked.error);
  }
  return { supported: true, samples };
}

/** Accept incomplete, bounded text without interpreting it as an applied sample. */
export function readInternalBenignFixtureDraft(text: string): InternalBenignFixtureDraft | null {
  if (!text || text.length > maximumDraftLength) return null;
  let value: unknown;
  try { value = JSON.parse(text); } catch { return null; }
  if (inspectJsonTokens(text).duplicateKeys || !isObject(value) || Object.keys(value).length !== 2
    || typeof value.source !== "string" || !readInternalBenignFixtures(value.source).supported
    || !Array.isArray(value.samples) || value.samples.length > internalBenignFixtureLimits.samples) return null;
  for (const sample of value.samples) {
    if (!isObject(sample) || Object.keys(sample).length !== 2 || typeof sample.fixtureId !== "string"
      || sample.fixtureId.length > internalBenignFixtureLimits.nameLength || !Array.isArray(sample.fields)
      || sample.fields.length > internalBenignFixtureLimits.fields) return null;
    for (const field of sample.fields) {
      if (!isObject(field) || Object.keys(field).length !== 2 || typeof field.field !== "string"
        || (field.field !== "" && !structuredRuleFields.some(item => item.key === field.field))
        || typeof field.value !== "string" || field.value.length > internalBenignFixtureLimits.stringLength) return null;
    }
  }
  return { source: value.source, samples: value.samples as InternalBenignFixtureSample[] };
}

export function isInternalBenignFixtureDraftText(value: unknown): boolean {
  return typeof value === "string" && (value === "" || readInternalBenignFixtureDraft(value) !== null);
}

export function nextInternalBenignFixtureName(samples: readonly InternalBenignFixtureSample[]): string {
  const used = new Set(samples.map(sample => sample.fixtureId));
  let ordinal = 1;
  while (used.has(`benign-sample-${ordinal}`)) ordinal += 1;
  return `benign-sample-${ordinal}`;
}
