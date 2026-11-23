import { permissionFacts } from "../lib/permission-facts";
import { DataList } from "./Primitives";

/** Render the decision's retained projection, not newer or unrelated run evidence. */
export function AdaptivePermissionObservations({ attempts }: { attempts: Record<string, unknown>[] }) {
  const observations = attempts.flatMap(attempt => (Array.isArray(attempt.evidence) ? attempt.evidence : []).flatMap((record: unknown) => {
    if (!record || typeof record !== "object" || Array.isArray(record)) return [];
    const evidence = record as Record<string, unknown>;
    if (evidence.provenance !== "observed" || typeof evidence.evidence_id !== "string") return [];
    const facts = evidence.facts;
    if (!facts || typeof facts !== "object" || Array.isArray(facts)) return [];
    const fields = facts as Record<string, unknown>;
    if (fields.artifact_type !== "file_observation"
      && !(fields.artifact_type === "collector_observation" && fields.observation_kind === "filesystem")) return [];
    const permissions = permissionFacts(fields);
    return permissions ? [{ evidenceId: evidence.evidence_id, permissions,
      position: typeof attempt.attempt_index === "number" && Number.isSafeInteger(attempt.attempt_index) && attempt.attempt_index >= 0 ? attempt.attempt_index + 1 : null,
      stepId: typeof attempt.step_id === "string" ? attempt.step_id : null,
    }] : [];
  }));
  if (!observations.length) return null;
  return <section className="adaptive-permission-observations" aria-label="Observed file permissions">
    <h4>Observed file permissions</h4>
    <p>Recorded permission facts available to this decision.</p>
    <p>Effective access not evaluated.</p>
    <ol>{observations.map(({ evidenceId, permissions, position, stepId }, index) => <li key={`${evidenceId}:${index}`}>
      <strong>Observation {index + 1}</strong>
      <p>{position === null ? "Source run position not recorded." : `From run position ${position}`}</p>
      {permissions.status === "available" ? <DataList items={[
        { label: "Mode", value: permissions.mode },
        { label: "Group write bit", value: permissions.groupWrite ? "Enabled" : "Not enabled" },
        { label: "Other write bit", value: permissions.otherWrite ? "Enabled" : "Not enabled" },
      ]}/> : <p>{permissions.status === "unavailable_windows" ? "Windows permissions not collected."
        : permissions.status === "unsupported_platform" ? "Permissions not collected on this platform."
          : "Permission metadata is incomplete or inconsistent."}</p>}
      <details><summary>Evidence reference</summary><DataList items={[
        { label: "Evidence", value: <code>{evidenceId}</code> },
        { label: "Source step", value: stepId ? <code>{stepId}</code> : "Not recorded" },
      ]}/></details>
    </li>)}</ol>
  </section>;
}
