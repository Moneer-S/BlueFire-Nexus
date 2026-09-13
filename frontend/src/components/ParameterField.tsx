import type { Behavior } from "../types";
import { parameterValueLabel, parameterValuesEqual } from "../lib/parameters";
import { Field, sentence } from "./Primitives";

export function ParameterField({ spec, value, onChange, behaviorId }: { behaviorId?: string; spec: Behavior["parameters"][number]; value: unknown; onChange: (value: unknown) => void }) {
  if (spec.enum?.length) {
    const selectedIndex = spec.enum.findIndex((item) => parameterValuesEqual(item, value));
    return <Field label={sentence(spec.name)} hint={spec.description}><select value={selectedIndex < 0 ? "" : String(selectedIndex)} onChange={(event) => { const index = Number.parseInt(event.target.value, 10); const member = spec.enum?.[index]; if (member !== undefined) onChange(structuredClone(member)); }}><option value="" disabled>Choose an allowed value</option>{spec.enum.map((item, index) => <option key={index} value={String(index)}>{parameterValueLabel(behaviorId, spec.name, item) ?? (Array.isArray(item) ? item.join(", ") : String(item))}</option>)}</select></Field>;
  }
  if (spec.type === "boolean") return <label className="check-row"><input type="checkbox" checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} /><span><strong>{sentence(spec.name)}</strong><small>{spec.description ?? "Boolean parameter"}</small></span></label>;
  return <Field label={sentence(spec.name)} hint={spec.description}><input type={spec.type === "integer" || spec.type === "number" ? "number" : "text"} value={Array.isArray(value) ? value.join(", ") : String(value ?? "")} min={spec.minimum ?? undefined} max={spec.maximum ?? undefined} step={spec.type === "integer" ? 1 : spec.type === "number" ? "any" : undefined} required={spec.required} onChange={(event) => {
    if (spec.type === "integer" || spec.type === "number") {
      if (!event.target.value) { onChange(undefined); return; }
      const numericValue = Number(event.target.value);
      if (Number.isFinite(numericValue) && (spec.type !== "integer" || Number.isInteger(numericValue))) onChange(numericValue);
      return;
    }
    onChange(spec.type === "string_list" ? event.target.value.split(",").map((item) => item.trim()).filter(Boolean) : event.target.value);
  }} /></Field>;
}
