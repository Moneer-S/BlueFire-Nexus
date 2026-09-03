import { describe, expect, it } from "vitest";
import { demoScenario } from "../src/lib/demo";
import { parseScenarioDocument } from "../src/lib/scenario";

describe("scenario document parsing", () => {
  it("normalizes omitted optional scenario fields without mutating the source document", () => {
    const document = structuredClone(demoScenario) as unknown as Record<string, unknown>;
    const step = document.steps && Array.isArray(document.steps)
      ? document.steps[0] as Record<string, unknown>
      : {};
    delete step.parameters;
    delete step.inputs;
    delete step.alternates;
    document.steps = [step];
    document.edges = [];
    document.start = step.id;
    const provenance = document.provenance as Record<string, unknown>;
    delete provenance.notes;
    delete document.limitations;

    const parsed = parseScenarioDocument(document);

    expect(parsed.steps[0]).toMatchObject({ parameters: {}, inputs: {}, alternates: [] });
    expect(parsed.provenance).not.toHaveProperty("notes");
    expect(parsed.limitations).toEqual([]);
    expect(step).not.toHaveProperty("parameters");
    expect(step).not.toHaveProperty("inputs");
    expect(step).not.toHaveProperty("alternates");
    expect(provenance).not.toHaveProperty("notes");
    expect(document).not.toHaveProperty("limitations");
  });

  it("normalizes nullable list fields and provenance notes like the backend contract", () => {
    const document = structuredClone(demoScenario) as unknown as Record<string, unknown>;
    const step = (document.steps as Array<Record<string, unknown>>)[0]!;
    step.alternates = null;
    document.limitations = null;
    (document.provenance as Record<string, unknown>).notes = null;

    const parsed = parseScenarioDocument(document);

    expect(parsed.steps[0]!.alternates).toEqual([]);
    expect(parsed.limitations).toEqual([]);
    expect(parsed.provenance).not.toHaveProperty("notes");
  });

  it("rejects an explicitly empty provenance note", () => {
    const document = structuredClone(demoScenario);
    document.provenance.notes = "";

    expect(() => parseScenarioDocument(document)).toThrow(/provenance\.notes must be a non-empty string/);
  });

  it.each(["parameters", "inputs"])("continues to reject an explicit null %s field", (field) => {
    const document = structuredClone(demoScenario);
    (document.steps[0] as unknown as Record<string, unknown>)[field] = null;

    expect(() => parseScenarioDocument(document)).toThrow(new RegExp(`steps\\[0\\]\\.${field} must be an object`));
  });
});
