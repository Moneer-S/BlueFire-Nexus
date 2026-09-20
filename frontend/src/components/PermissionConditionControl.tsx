import { Field } from "./Primitives";

export type PermissionCondition = "staged" | "world_writable" | "non_owner_writable";
export const permissionConditionValues = ["staged", "world_writable", "non_owner_writable"] as const;

export function isPermissionCondition(value: unknown): value is PermissionCondition {
  return typeof value === "string" && permissionConditionValues.includes(value as PermissionCondition);
}

const conditions: Array<{ value: PermissionCondition; label: string; description: string }> = [
  { value: "staged", label: "Staged file", description: "Matches the existing staged-file starter." },
  { value: "world_writable", label: "World-writable file", description: "Requires the observed other-write bit; effective access is not established." },
  { value: "non_owner_writable", label: "Non-owner writable file", description: "Requires group or other write; effective access is not established." },
];

export function permissionSelection(condition: PermissionCondition): Record<string, unknown> {
  if (condition === "staged") return { artifact_type: "file_observation", "path|contains": "staged/" };
  return {
    artifact_type: "file_observation",
    permission_status: "available",
    [condition === "world_writable" ? "other_write_bit" : "non_owner_write_bit"]: true,
  };
}

export function permissionPredictedFields(condition: PermissionCondition): string[] {
  return condition === "staged"
    ? ["artifact_type", "path"]
    : ["artifact_type", "permission_status", condition === "world_writable" ? "other_write_bit" : "non_owner_write_bit"];
}

export function permissionConditionForSelection(selection: unknown): PermissionCondition | undefined {
  if (!selection || typeof selection !== "object" || Array.isArray(selection)) return undefined;
  const value = selection as Record<string, unknown>;
  for (const condition of conditions) {
    const expected = permissionSelection(condition.value);
    if (Object.keys(value).length === Object.keys(expected).length && Object.entries(expected).every(([key, field]) => value[key] === field)) return condition.value;
  }
  return undefined;
}

export function PermissionConditionControl({ value, onChange, disabled = false }: { value: PermissionCondition; onChange: (value: PermissionCondition) => void; disabled?: boolean }) {
  const selected = conditions.find((item) => item.value === value) ?? conditions[0]!;
  return <Field label="Detection condition" hint={selected.description}><select aria-label="Detection condition" value={value} onChange={(event) => onChange(event.target.value as PermissionCondition)} disabled={disabled}>{conditions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select>{value !== "staged" ? <small className="field-note">Permission bits describe observed metadata; effective access remains not evaluated.</small> : null}</Field>;
}
