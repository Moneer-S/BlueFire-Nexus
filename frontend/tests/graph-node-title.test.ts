import { describe, expect, it } from "vitest";
import { graphNodeTitle } from "../src/lib/graph-node-title";

describe("graph node method suffix presentation", () => {
  it.each(["native JSONL", "native TAR", "portable ZIP", "natif JSONL", "C++/JSONL"])("exposes the exact existing %s suffix for an action", method => {
    const fullTitle = `Collect selected records (${method})`;
    expect(graphNodeTitle(fullTitle, "action")).toEqual({ fullTitle, title: "Collect selected records", method: `(${method})` });
  });

  it.each(["simulation", "research", undefined])("retains the complete title for %s behavior", state => {
    const fullTitle = "Collect selected records (native JSONL)";
    expect(graphNodeTitle(fullTitle, state)).toEqual({ fullTitle, title: fullTitle });
  });

  it("retains the complete title when an action node needs attention", () => {
    const fullTitle = "Collect selected records (native TAR)";
    expect(graphNodeTitle(fullTitle, "action", true)).toEqual({ fullTitle, title: fullTitle });
  });

  it("accepts a 24-character suffix without shortening it", () => {
    const method = `(${"A".repeat(22)})`;
    expect(graphNodeTitle(`Archive records ${method}`, "action")).toEqual({ fullTitle: `Archive records ${method}`, title: "Archive records", method });
  });

  it.each([
    "Collect selected records", "Collect records ()", "Collect records ( )",
    "Collect records ( native JSONL)", "Collect records (native JSONL )",
    `Collect records (${"A".repeat(23)})`, "Collect records (native (JSONL))",
    "Collect records (native JSONL) later", "Collect records(native JSONL)",
    "(native JSONL)", "  (native JSONL)", "Collect records (<JSONL>)",
    "Collect records (native\nJSONL)", "Collect records (native\tJSONL)",
  ])("preserves the original title for an unsupported suffix: %s", fullTitle => {
    expect(graphNodeTitle(fullTitle, "action")).toEqual({ fullTitle, title: fullTitle });
  });
});
