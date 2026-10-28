import { describe, expect, it } from "vitest";
import { inspectorMethodTitle } from "../src/lib/inspector-method-title";
import type { ActionDefinition, Behavior } from "../src/types";

const behavior = (id: string, title: string, actionIds: string[]): Behavior => ({
  id, title, purpose: "Registered method purpose.", execution_state: "action", safety_tier: "controlled",
  platforms: ["linux"], techniques: [], capabilities: [], inputs: [], outputs: [], parameters: [],
  action_ids: actionIds, telemetry: [], detection_hints: [], limitations: [],
});
const action = (id: string, title: string): ActionDefinition => ({
  id, title, purpose: "Registered action purpose.", safety_tier: "controlled", capabilities: [], platforms: ["linux"],
  inputs: [], outputs: [], parameters: [],
});
const jsonl = behavior("sandbox.collection.records.v1", "Collect selected records (native JSONL)", ["sandbox.collection.records.v1"]);
const tar = behavior("sandbox.collection.archive.v1", "Archive selected records (native TAR)", ["sandbox.collection.archive.v1"]);
const actions = new Map([
  ["sandbox.collection.records.v1", action("sandbox.collection.records.v1", "Collect selected records (native JSONL)")],
  ["sandbox.collection.archive.v1", action("sandbox.collection.archive.v1", "Archive selected records (native TAR)")],
]);

describe("inspector method title", () => {
  it.each([
    [jsonl, "Native JSONL"],
    [tar, "Native TAR"],
  ])("shows the registered concise method label for %s", (method, expected) => {
    expect(inspectorMethodTitle(method, actions)).toBe(expected);
  });

  it("keeps full titles when registered action metadata is missing, mismatched, or ambiguous", () => {
    const fullTitle = "Collect selected records (native JSONL)";
    expect(inspectorMethodTitle(jsonl, new Map())).toBe(fullTitle);
    const mismatched = new Map(actions).set(jsonl.action_ids[0]!, action(jsonl.action_ids[0]!, "Collect selected records (other JSONL)"));
    expect(inspectorMethodTitle(jsonl, mismatched)).toBe(fullTitle);
    const ambiguous: Behavior = { ...jsonl, action_ids: [...jsonl.action_ids, "sandbox.archive.tar.v1"] };
    expect(inspectorMethodTitle(ambiguous, actions)).toBe(fullTitle);
  });
});
