/** A visibly synthetic positive example for simple internal selections only. */
export function syntheticSelectionExample(language: string, selection: Record<string, unknown> | undefined): string {
  if (language !== "internal" || !selection || !Object.keys(selection).length) return "";
  const row: Record<string, unknown> = { fixture_id: "synthetic-selection-example" };
  for (const [key, expected] of Object.entries(selection)) {
    const [field, operator, extra] = key.split("|");
    if (!field || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(field) || ["__proto__", "prototype", "constructor"].includes(field) || Object.hasOwn(row, field) || extra !== undefined) return "";
    if (operator !== undefined && !["contains", "startswith", "endswith"].includes(operator)) return "";
    if (!["string", "number", "boolean"].includes(typeof expected) || (typeof expected === "number" && !Number.isFinite(expected))) return "";
    if (operator && typeof expected !== "string") return "";
    row[field] = expected;
  }
  return JSON.stringify([row], null, 2);
}
