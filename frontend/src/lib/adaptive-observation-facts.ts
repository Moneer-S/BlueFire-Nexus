/** Display only the closed facts retained by project_runtime_observations. */
export type ObservationFact = { label: string; value: string };
const object = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === "object" && !Array.isArray(value));
export const observationCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const counts: Record<string, string> = {
  record_count: "Records inspected", retained_record_count: "Records with original values",
  redacted_record_count: "Records with redacted values", empty_record_count: "Empty records",
  size_bytes: "Size in bytes", process_count: "Processes", file_count: "Files",
  entry_count: "Entries", reported_size_bytes: "Reported size in bytes",
};
const enums: Record<string, { label: string; values: Record<string, string> }> = {
  container: { label: "Format", values: { jsonl: "JSONL", gzip: "gzip", ustar: "USTAR", tar: "TAR" } },
  artifact_type: { label: "Record type", values: { file_observation: "File observation", collector_observation: "Collector observation", evidence_gap: "Evidence gap" } },
  observation_kind: { label: "Observation", values: { filesystem: "File metadata", collection_semantics: "Collection contents", process: "Process metadata" } },
};
const permissionKeys = ["permission_status", "effective_access", "permission_mode_octal", "group_write_bit", "other_write_bit", "non_owner_write_bit"];
const permissionUnavailable: Record<string, string> = {
  unavailable_windows: "Not collected on Windows", unsupported_platform: "Not collected on this platform", invalid_metadata: "Recorded permission metadata is invalid",
};

export function observationFacts(value: unknown, provenance: string): ObservationFact[] | null {
  if (!object(value)) return null;
  const allowed = [...Object.keys(counts), ...Object.keys(enums), ...permissionKeys];
  if (Object.keys(value).some(key => !allowed.includes(key))) return null;
  const result: ObservationFact[] = [];
  for (const [key, label] of Object.entries(counts)) {
    if (!(key in value)) continue;
    if (!observationCount(value[key])) return null;
    result.push({ label, value: value[key].toLocaleString("en-US") });
  }
  for (const [key, descriptor] of Object.entries(enums)) {
    if (!(key in value)) continue;
    const selected = value[key];
    if (typeof selected !== "string" || !Object.hasOwn(descriptor.values, selected)) return null;
    result.push({ label: descriptor.label, value: descriptor.values[selected]! });
  }
  const permissions = permissionKeys.filter(key => key in value);
  if (!permissions.length) return result;
  if (provenance !== "observed" || value.effective_access !== "not_evaluated"
    || !(value.artifact_type === "file_observation" || (value.artifact_type === "collector_observation" && value.observation_kind === "filesystem"))) return null;
  const status = value.permission_status;
  if (status !== "available") {
    if (typeof status !== "string" || !Object.hasOwn(permissionUnavailable, status) || permissions.length !== 2) return null;
    result.push({ label: "File permissions", value: permissionUnavailable[status]! });
  } else {
    const mode = value.permission_mode_octal;
    if (permissions.length !== permissionKeys.length || typeof mode !== "string" || !/^[0-7]{4}$/.test(mode)) return null;
    const bits = Number.parseInt(mode, 8), groupWrite = Boolean(bits & 0o020), otherWrite = Boolean(bits & 0o002);
    if (value.group_write_bit !== groupWrite || value.other_write_bit !== otherWrite || value.non_owner_write_bit !== (groupWrite || otherWrite)) return null;
    result.push({ label: "Permission mode", value: mode },
      { label: "Group write bit", value: groupWrite ? "Enabled" : "Not enabled" },
      { label: "Other write bit", value: otherWrite ? "Enabled" : "Not enabled" });
  }
  result.push({ label: "Effective access", value: "Not evaluated; mode bits do not establish access through parent directories or ACLs." });
  return result;
}
