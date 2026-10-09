import type { ScenarioDiagnostic } from "../lib/scenario-diagnostics";
import { Button } from "./Primitives";

export function GraphValidationFeedback({ state, findings, stepCount, routeCount, readOnly, name, onSelect }: {
  state: "idle" | "valid" | "invalid";
  findings: ScenarioDiagnostic[];
  stepCount: number;
  routeCount: number;
  readOnly?: boolean;
  name: (id: string) => string;
  onSelect: (id: string) => void;
}) {
  const affected = findings.some(finding => finding.stepId);
  const title = state === "valid" ? "Experiment validated" : state === "invalid" ? affected ? "Review the affected steps" : "Review the validation findings" : readOnly ? "Read-only view · not validated here" : "Validate this experiment before run review";
  const finding = (item: ScenarioDiagnostic) => <><span>{item.message}</span>{item.stepId ? <Button size="small" variant="ghost" onClick={() => onSelect(item.stepId!)}>Show {name(item.stepId)}</Button> : null}</>;
  return <div className={`validation-bar ${state}`} role={state === "invalid" ? "alert" : "status"}>
    <div><strong>{title}</strong>{findings[0] ? finding(findings[0]) : <span>{stepCount} steps · {routeCount} branches</span>}</div>
    {findings.length > 1 ? <details><summary>{findings.length} findings</summary><ul>{findings.slice(1).map((item, index) => <li key={index}>{finding(item)}</li>)}</ul></details> : null}
  </div>;
}
