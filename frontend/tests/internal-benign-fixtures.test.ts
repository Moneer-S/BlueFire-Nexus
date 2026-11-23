import { describe, expect, it } from "vitest";
import { buildInternalBenignFixtures, internalBenignFixtureLimits, isInternalBenignFixtureDraftText, nextInternalBenignFixtureName, readInternalBenignFixtureDraft, readInternalBenignFixtures, type InternalBenignFixtureDraft, type InternalBenignFixtureSample } from "../src/lib/internal-benign-fixtures";
import { structuredRuleFields } from "../src/lib/structured-rule-selection";

const sample = (fields: Array<[string, string]> = [], fixtureId = "ordinary-1"): InternalBenignFixtureSample => ({ fixtureId, fields: fields.map(([field, value]) => ({ field, value })) });
const bytes = (value: string) => new TextEncoder().encode(value).byteLength;

function refuse(samples: InternalBenignFixtureSample[]) {
  const before = structuredClone(samples);
  const result = buildInternalBenignFixtures(samples);
  expect(result).toMatchObject({ ok: false, error: expect.any(String) });
  expect(result).not.toHaveProperty("fixtures");
  expect(samples).toEqual(before);
}

describe("authored internal benign fixtures", () => {
  it("preserves types, octal text, custom Unicode and explicit empty strings while leaving omitted fields absent", () => {
    const inputs = [sample([["record_count", "0"], ["group_write_bit", "false"], ["permission_mode_octal", "0660"], ["path", "  café/😀  "], ["container", ""]])];
    const expected = [{ fixture_id: "ordinary-1", record_count: 0, group_write_bit: false, permission_mode_octal: "0660", path: "  café/😀  ", container: "" }];
    expect(buildInternalBenignFixtures(inputs)).toEqual({ ok: true, fixtures: expected });
    expect(readInternalBenignFixtures(JSON.stringify(expected))).toEqual({ supported: true, samples: inputs });
    expect(expected[0]).not.toHaveProperty("other_write_bit");
    expect(expected[0]).not.toHaveProperty("retained_record_count");
  });

  it("allows partial samples but does not invent any matching fields", () => {
    expect(readInternalBenignFixtures("")).toEqual({ supported: true, samples: [] });
    expect(readInternalBenignFixtures("[]")).toEqual({ supported: true, samples: [] });
    expect(buildInternalBenignFixtures([sample()])).toEqual({ ok: true, fixtures: [{ fixture_id: "ordinary-1" }] });
    refuse([]);
  });

  it("generates a visible safe unused name without changing existing names", () => {
    const inputs = [sample([], "benign-sample-1"), sample([], "benign-sample-3"), sample([], "Benign-sample-2")];
    expect(nextInternalBenignFixtureName(inputs)).toBe("benign-sample-2");
    expect(inputs.map(item => item.fixtureId)).toEqual(["benign-sample-1", "benign-sample-3", "Benign-sample-2"]);
  });

  it.each(["", "a b", " name", "name ", "name\n", "-name", "_name", "é", "a/b", "a".repeat(201)])("refuses invalid sample name %j", name => refuse([sample([], name)]));

  it("uses exact unique names, including the backend's case-sensitive distinction and maximum length", () => {
    expect(buildInternalBenignFixtures([sample([], "a".repeat(200)), sample([], "A._:-0")]).ok).toBe(true);
    expect(buildInternalBenignFixtures([sample([], "a"), sample([], "A")]).ok).toBe(true);
    refuse([sample([], "same"), sample([], "same")]);
  });

  it.each(["", "-1", "-0", "01", "1.0", "1e3", "+1", " 1", "1\n", "9007199254740992"])("retains but cannot apply incomplete or ambiguous count %j", value => {
    const draft = { source: "", samples: [sample([["record_count", value]])] };
    expect(readInternalBenignFixtureDraft(JSON.stringify(draft))).toEqual(draft);
    refuse(draft.samples);
  });

  it("accepts the exact safe integer boundary", () => {
    expect(buildInternalBenignFixtures([sample([["record_count", "9007199254740991"]])])).toEqual({ ok: true, fixtures: [{ fixture_id: "ordinary-1", record_count: 9007199254740991 }] });
  });

  it.each(["", "0", "1", "False", "false\n"])("requires an explicit boolean choice for %j", value => refuse([sample([["group_write_bit", value]])]));
  it.each(["660", "0660\n", "0880", "0o660"])("refuses invalid octal mode %j", value => refuse([sample([["permission_mode_octal", value]])]));

  it("refuses unselected, unknown and duplicate fields without returning a partial sample", () => {
    refuse([sample([["path", "kept"], ["", ""]])]);
    refuse([sample([["path", "kept"], ["custom", "authored"]])]);
    refuse([sample([["path", "first"], ["path", "second"]])]);
  });

  it.each([
    '[{"fixture_id":"one","path":"first","path":"second"}]',
    String.raw`[{"fixture_id":"one","path":"first","\u0070ath":"second"}]`,
    '[{"fixture_id":"one","fixture_id":"two"}]',
    '[{"fixture_id":"one","custom":{"a":1,"a":2}}]',
    '[{"fixture_id":"one","path":null}]',
    '[{"fixture_id":"one","path":["a","b"]}]',
    '[{"fixture_id":"one","custom":"keep me"}]',
    '[{"fixture_id":"one","record_count":true}]',
    '[{"fixture_id":"one","other_write_bit":0}]',
    '[{"fixture_id":"one","permission_mode_octal":660}]',
    '[{"fixture_id":"one","record_count":9007199254740991.1}]',
    '[{"fixture_id":"one","record_count":1e3}]',
    '[{"fixture_id":"one","record_count":-0}]',
    '[{"fixture_id":"one","record_count":1e309}]',
    '[{"fixture_id":"one","path":"\\ud800"}]',
    '[{"fixture_id":"one","path":"first\\r\\nsecond"}]',
    '{', 'null', '{}', '[null]', '[[]]', '[{"path":"name omitted"}]',
  ])("keeps unsupported advanced JSON unavailable without any partial conversion: %s", source => {
    const result = readInternalBenignFixtures(source);
    expect(result).toMatchObject({ supported: false, reason: expect.stringContaining("has not been changed") });
    expect(result).not.toHaveProperty("samples");
  });

  it("does not mistake punctuation, quoted keys or numeric text for tokens", () => {
    const inputs = [sample([["path", '"path":1e309, {"path":false}, \\ [1,2]']])];
    const built = buildInternalBenignFixtures(inputs);
    if (!built.ok) throw new Error("valid literal text");
    expect(readInternalBenignFixtures(JSON.stringify(built.fixtures))).toEqual({ supported: true, samples: inputs });
  });

  it("enforces the visual sample and string bounds without redefining the backend's larger JSON schema", () => {
    const sixteen = Array.from({ length: 16 }, (_, index) => sample([["path", "x".repeat(4096)]], `sample-${index}`));
    expect(buildInternalBenignFixtures(sixteen).ok).toBe(true);
    refuse([...sixteen, sample()]);
    refuse([sample([["path", "x".repeat(4097)]])]);
    const largerSet = JSON.stringify(Array.from({ length: 17 }, (_, index) => ({ fixture_id: `sample-${index}` })));
    const longerText = JSON.stringify([{ fixture_id: "one", path: "x".repeat(4097) }]);
    expect(readInternalBenignFixtures(largerSet).supported).toBe(false);
    expect(readInternalBenignFixtures(longerText).supported).toBe(false);
    expect(readInternalBenignFixtures("[]".padEnd(internalBenignFixtureLimits.sourceBytes + 1)).supported).toBe(false);
  });

  it("counts UTF-8 bytes, accepts the exact fixture boundary and refuses one extra byte without losing the draft", () => {
    const names = structuredRuleFields.filter(field => field.type === "string" && field.key !== "permission_mode_octal").map(field => field.key);
    const inputs = Array.from({ length: 16 }, (_, index) => sample(names.map(name => [name, ""]), `sample-${index}`));
    const initial = buildInternalBenignFixtures(inputs);
    if (!initial.ok) throw new Error("empty strings are supported");
    let remaining = internalBenignFixtureLimits.fixtureBytes - bytes(JSON.stringify(initial.fixtures));
    for (const row of inputs) for (const field of row.fields) {
      if (remaining >= 3) {
        const count = Math.min(4096, Math.floor(remaining / 3));
        field.value = "漢".repeat(count); remaining -= count * 3;
      } else if (remaining) { field.value = "x".repeat(remaining); remaining = 0; }
    }
    expect(remaining).toBe(0);
    const result = buildInternalBenignFixtures(inputs);
    if (!result.ok) throw new Error(result.error);
    const output = JSON.stringify(result.fixtures);
    expect(bytes(output)).toBe(1048576);
    expect(readInternalBenignFixtures(output)).toEqual({ supported: true, samples: inputs });
    expect(readInternalBenignFixtures(JSON.stringify(result.fixtures, null, 2)).supported).toBe(false);
    inputs[15]!.fields[5]!.value += "x";
    refuse(inputs);
    const draft = { source: "", samples: inputs };
    expect(readInternalBenignFixtureDraft(JSON.stringify(draft))).toEqual(draft);
  });

  it("rejects lone surrogates without replacing their value", () => {
    for (const value of ["\ud800", "\udc00", "x\ud800y"]) {
      const input = sample([["path", value]]);
      refuse([input]);
      expect(input.fields[0]!.value).toBe(value);
    }
  });
});

describe("retained benign sample draft", () => {
  it("retains incomplete names, fields, duplicate entries and count text until explicit repair", () => {
    const draft: InternalBenignFixtureDraft = { source: " [ ] ", samples: [sample([["", ""], ["record_count", "1e"], ["record_count", ""]], "")] };
    expect(readInternalBenignFixtureDraft(JSON.stringify(draft))).toEqual(draft);
    expect(isInternalBenignFixtureDraftText(JSON.stringify(draft))).toBe(true);
    expect(isInternalBenignFixtureDraftText("")).toBe(true);
    expect(readInternalBenignFixtureDraft("")).toBeNull();
    refuse(draft.samples);
  });

  it("retains the maximum escaped rows and a supported source independently of the browser envelope cap", () => {
    const inputs = Array.from({ length: 16 }, (_, index) => sample(structuredRuleFields.map(field => [field.key, "\u0001".repeat(4096)]), `sample-${index}`));
    const source = "[]".padEnd(internalBenignFixtureLimits.sourceBytes, " ");
    const draft = { source, samples: inputs };
    const text = JSON.stringify(draft);
    expect(text.length).toBeGreaterThan(2 * 1024 * 1024);
    expect(readInternalBenignFixtureDraft(text)).toEqual(draft);
    refuse(inputs);
  });

  it.each([
    null, [], {}, { source: "", samples: [], extra: true },
    { source: "{", samples: [] }, { source: '[{"fixture_id":"x","custom":1}]', samples: [] },
    { source: "", samples: {} }, { source: "", samples: [null] },
    { source: "", samples: [{ fixtureId: "x", fields: [], extra: true }] },
    { source: "", samples: [{ fixtureId: false, fields: [] }] },
    { source: "", samples: [sample([], "x".repeat(201))] },
    { source: "", samples: [sample([["unknown", "kept"]])] },
    { source: "", samples: [sample([["path", "x".repeat(4097)]])] },
    { source: "", samples: [{ fixtureId: "x", fields: [{ field: "path", value: false }] }] },
    { source: "", samples: [{ fixtureId: "x", fields: [{ field: "path", value: "", extra: "keep" }] }] },
    { source: "", samples: Array.from({ length: 17 }, () => sample()) },
    { source: "", samples: [sample(Array.from({ length: 15 }, () => ["path", ""]))] },
  ])("refuses the entire malformed stored shape without partially restoring it (case %#)", value => {
    const text = JSON.stringify(value);
    expect(readInternalBenignFixtureDraft(text)).toBeNull();
    expect(isInternalBenignFixtureDraftText(text)).toBe(false);
  });

  it("rejects malformed text and duplicate draft keys", () => {
    expect(readInternalBenignFixtureDraft("{")).toBeNull();
    expect(readInternalBenignFixtureDraft('{"source":"","source":"[]","samples":[]}')).toBeNull();
    expect(isInternalBenignFixtureDraftText({ source: "", samples: [] })).toBe(false);
  });
});
