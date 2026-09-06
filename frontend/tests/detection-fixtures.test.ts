import { expect, it } from "vitest";
import { syntheticSelectionExample } from "../src/lib/detection-fixtures";

it("preserves production collector fields in a visibly synthetic internal example", () => {
  const selection = { artifact_type: "collector_observation", observation_kind: "filesystem", "path|startswith": "staged/" };
  expect(JSON.parse(syntheticSelectionExample("internal", selection))).toEqual([{ fixture_id: "synthetic-selection-example", artifact_type: "collector_observation", observation_kind: "filesystem", path: "staged/" }]);
});

it.each(["sqlite", "sigma", "yara", "spl"])("does not infer positive fixtures from %s metadata", (language) => {
  expect(syntheticSelectionExample(language, { artifact_type: "collector_observation" })).toBe("");
});

it.each([
  { path: "one", "path|endswith": "two" },
  { "nested.field": "value" },
  { "path|regex": "staged/.+" },
  { "path|contains|all": "staged/" },
  { path: ["one", "two"] },
  JSON.parse('{"__proto__":"untrusted"}') as Record<string, unknown>,
])("leaves ambiguous or unsupported selections for explicit fixture input", (selection) => {
  expect(syntheticSelectionExample("internal", selection)).toBe("");
});
