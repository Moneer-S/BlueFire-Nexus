/** Recorded mode bits establish permission state, never effective access. */
export type PermissionFacts =
  | { status: "available"; mode: string; groupWrite: boolean; otherWrite: boolean }
  | { status: "unavailable_windows" | "unsupported_platform" }
  | { status: "invalid_metadata" };

export const permissionKeys = ["permission_status", "effective_access", "permission_mode_octal", "group_write_bit", "other_write_bit", "non_owner_write_bit"] as const;

export function permissionFacts(value: Record<string, unknown>): PermissionFacts | undefined {
  const present = permissionKeys.filter(key => key in value);
  if (!present.length) return;
  const invalid = { status: "invalid_metadata" } as const;
  const status = value.permission_status;
  if (value.effective_access !== "not_evaluated") return invalid;
  if (status === "unavailable_windows" || status === "unsupported_platform") {
    return present.length === 2 ? { status } : invalid;
  }
  if (status !== "available" || present.length !== permissionKeys.length
    || typeof value.permission_mode_octal !== "string" || !/^[0-7]{4}$/.test(value.permission_mode_octal)
    || typeof value.group_write_bit !== "boolean" || typeof value.other_write_bit !== "boolean" || typeof value.non_owner_write_bit !== "boolean"
    || value.group_write_bit !== ((Number.parseInt(value.permission_mode_octal[2]!, 8) & 2) !== 0)
    || value.other_write_bit !== ((Number.parseInt(value.permission_mode_octal[3]!, 8) & 2) !== 0)
    || value.non_owner_write_bit !== (value.group_write_bit || value.other_write_bit)) return invalid;
  return { status, mode: value.permission_mode_octal, groupWrite: value.group_write_bit, otherWrite: value.other_write_bit };
}
