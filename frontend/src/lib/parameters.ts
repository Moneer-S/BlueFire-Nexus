import type { ParameterSpec } from "../types";

export function shouldInitializeParameter(spec: ParameterSpec): boolean {
  return Boolean(spec.required) || (spec.default !== undefined && spec.default !== null);
}

export function initialParameterValue(spec: ParameterSpec): unknown {
  if (spec.default !== undefined && spec.default !== null) return structuredClone(spec.default);
  if (spec.enum?.length) return structuredClone(spec.enum[0]);
  if (spec.type === "boolean") return false;
  if (spec.type === "number") {
    const minimum = spec.minimum ?? Number.NEGATIVE_INFINITY;
    const maximum = spec.maximum ?? Number.POSITIVE_INFINITY;
    return minimum <= maximum ? Math.min(maximum, Math.max(minimum, 0)) : undefined;
  }
  if (spec.type === "integer") {
    const minimum = spec.minimum == null ? Number.NEGATIVE_INFINITY : Math.ceil(spec.minimum);
    const maximum = spec.maximum == null ? Number.POSITIVE_INFINITY : Math.floor(spec.maximum);
    if (minimum > maximum) return undefined;
    return Math.min(maximum, Math.max(minimum, 0));
  }
  if (spec.type === "string_list") return [];
  return "";
}

export function parameterValuesEqual(left: unknown, right: unknown): boolean {
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right)
      && left.length === right.length
      && left.every((item, index) => item === right[index]);
  }
  return Object.is(left, right);
}
