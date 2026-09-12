import type { AdaptiveAuthorization } from "../lib/adaptive-execution";
import { adaptiveOutcomeLabels } from "../lib/adaptive-execution";
import { scopeLabel } from "../lib/run-review-labels";
import type { ApprovalEnvelope } from "../types";
import { DataList, sentence } from "./Primitives";
import "./AdaptiveAuthorizationReview.css";

export function AdaptiveAuthorizationReview({ authorization, envelope, autonomy }: { authorization: AdaptiveAuthorization; envelope?: ApprovalEnvelope | null; autonomy?: unknown }) {
  const behaviorName = (stepId: string, behaviorId: string) => String(envelope?.steps.find(step => step.step_id === stepId)?.options.find(option => option.behavior_id === behaviorId)?.contract.title ?? "Selected step");
  const methodName = (stepId: string, behaviorId: string, actionId: string) => String(envelope?.steps.find(step => step.step_id === stepId)?.options.find(option => option.behavior_id === behaviorId)?.actions.find(action => action.action_id === actionId)?.contract.title ?? behaviorName(stepId, behaviorId));
  return <section className="adaptive-authorization-review" aria-label="Reviewed adaptive execution">
    <h3>Permitted adaptive retry</h3>
    <p>{autonomy === "auto" ? "Auto may choose one of these methods from the observed result and continue within this approval." : autonomy === "assist" ? "Assist pauses a proposed change for your review." : "Off follows the saved primary methods and routes. The model will not choose a retry."} A new target, method, parameter, or wider effect needs a new decision.</p>
    <DataList items={[
      { label: "Objective", value: authorization.objective },
      { label: "Target", value: authorization.target_scope.scope_refs.map(scopeLabel).join("; ") },
      { label: "Environment", value: sentence(authorization.platform) },
      { label: "Retry after", value: authorization.policy.eligible_outcomes.map(outcome => adaptiveOutcomeLabels[outcome]).join(", ") },
      { label: "Limits", value: `One retry across the experiment · ${authorization.limits.max_steps} total steps · ${authorization.limits.max_seconds} seconds` },
      { label: "Created data", value: `Up to ${authorization.limits.max_artifacts.toLocaleString()} artifacts and ${authorization.limits.max_bytes.toLocaleString()} bytes` },
      { label: "Cleanup", value: authorization.cleanup_policy === "always" ? "Required on completion, failure and cancellation" : sentence(authorization.cleanup_policy) },
      { label: "Model failure", value: authorization.policy.on_provider_failure === "stop" ? "Stop and clean up" : "Use the saved route; record deterministic fallback, not live-model success" },
    ]}/>
    {authorization.steps.map(entry => <article key={entry.step_id}><h4>{behaviorName(entry.step_id, entry.methods[0]?.plan_step.behavior_id ?? "")}</h4>
      {entry.methods.map(choice => <div className="adaptive-reviewed-method" key={`${choice.plan_step.behavior_id}:${choice.plan_step.action_id}`}><strong>{methodName(entry.step_id, choice.plan_step.behavior_id, choice.plan_step.action_id)}</strong>
        <p>{choice.mutates ? "Changes the reviewed workspace" : "Read-only method"} · {sentence(choice.plan_step.safety_tier)} · {choice.cleanup_action_id ? "Receipt-based cleanup" : "No cleanup effects required"}</p>
        <DataList items={[
          { label: "Exact parameters", value: Object.entries(choice.plan_step.parameters).map(([name, value]) => `${sentence(name)}: ${JSON.stringify(value)}`).join("; ") || "No configurable parameters" },
          { label: "Required inputs", value: Object.entries(choice.plan_step.inputs).map(([name, binding]) => `${sentence(name)} from ${envelope?.steps.find(step => step.step_id === binding.from_step)?.options[0]?.contract.title ?? "the connected earlier step"}`).join("; ") || "No input from another step" },
          { label: "Capabilities", value: choice.capabilities.map(sentence).join(", ") },
        ]}/>
      </div>)}
    </article>)}
    <details><summary>Exact authorization and method identities</summary><pre>{JSON.stringify(authorization, null, 2)}</pre></details>
  </section>;
}
