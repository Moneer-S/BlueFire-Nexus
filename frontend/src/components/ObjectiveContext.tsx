import { ArrowLeft } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { objectiveById, objectiveReturnHref, type ObjectiveId } from "../lib/objectives";
import "./ObjectiveContext.css";

export function ObjectiveContext({ expected }: { expected: ObjectiveId }) {
  const [params] = useSearchParams();
  const requested = params.get("goal");
  if (!requested) return null;

  const objective = objectiveById(requested);
  if (!objective || objective.id !== expected) {
    const chooserParams = new URLSearchParams(params);
    chooserParams.delete("goal");
    const chooserQuery = chooserParams.toString();
    return <aside className="objective-context objective-context-mismatch" aria-label="Objective context">
      <p>This objective link does not match this workspace.</p>
      <Link to={chooserQuery ? `/getting-started?${chooserQuery}` : "/getting-started"}><ArrowLeft aria-hidden="true" />Choose an objective</Link>
    </aside>;
  }

  return <aside className="objective-context" aria-label="Selected objective">
    <div><span>{objective.label}</span><p>{objective.question}</p></div>
    <Link to={objectiveReturnHref(objective, params)}><ArrowLeft aria-hidden="true" />Change objective</Link>
  </aside>;
}
