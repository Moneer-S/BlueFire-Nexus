import { displayTitle } from "../lib/display-title";
import { ShieldCheck } from "lucide-react";
import { profileLabel, scopeLabel as accessLabel } from "../lib/run-review-labels";
import { memo } from "react";
import type { ApprovalBinding, ApprovalEnvelope, CatalogResponse } from "../types";
import { parameterValueLabel } from "../lib/parameters";
import type { AdaptiveAuthorization } from "../lib/adaptive-execution";
import { AdaptiveAuthorizationReview } from "./AdaptiveAuthorizationReview";
import { Badge, Callout, DataList, sentence } from "./Primitives";

export const CanonicalPlanReview = memo(function CanonicalPlanReview({ plan, cleanup, scope, binding, envelope, adaptiveAuthorization, catalog }: { plan: Record<string, unknown>; cleanup?: unknown; scope?: unknown; binding?: ApprovalBinding | null; envelope?: ApprovalEnvelope | null; adaptiveAuthorization?: AdaptiveAuthorization | null; catalog?: CatalogResponse }) {
  const steps = Array.isArray(plan.steps) ? plan.steps.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object") : [];
  const edges = Array.isArray(plan.edges) ? plan.edges : [];
  const digest = binding?.plan_digest ?? plan.plan_digest ?? plan.digest ?? plan.scenario_digest;
  const scopeRecord = scope && typeof scope === "object" ? scope as Record<string, unknown> : null;
  const scopeReferences = typeof scope === "string" ? [scope] : Array.isArray(scopeRecord?.scope_refs) ? scopeRecord.scope_refs.filter((item): item is string => typeof item === "string") : [];
  const scopeLabel = scopeReferences.length ? scopeReferences.map(accessLabel).join("; ") : "Not reported";
  const profileId = binding?.profile_id ?? String(plan.runner_profile_id ?? "");
  const cleanupRecord = cleanup && typeof cleanup === "object" ? cleanup as Record<string, unknown> : null;
  const cleanupPolicy = typeof cleanup === "string" ? cleanup : cleanupRecord?.policy;
  const cleanupLabel = plan.mode === "simulate"
    ? `Simulated cleanup; no external files are removed. Policy: ${sentence(String(cleanupPolicy ?? "not reported"))}.`
    : typeof cleanup === "string" ? sentence(cleanup) : cleanupRecord?.policy === "always" ? "Remove created lab files after the run" : sentence(String(cleanupRecord?.policy ?? "not reported"));
  return <section className="canonical-plan" aria-label="Canonical preflight plan">
    <header><div><span>{envelope ? "Ready for your review" : "Run review"}</span><strong>What this run will do</strong></div><Badge tone={envelope ? "warning" : "info"}>{steps.length} steps · {sentence(String(plan.mode ?? "not reported"))}</Badge></header>
    <DataList items={[
      { label: "Environment profile", value: profileId ? profileLabel(profileId) : "Not reported" },
      { label: "Requested access", value: scopeLabel },
      { label: "Cleanup", value: cleanupLabel },
      { label: "Full experiment", value: `${steps.length} steps and ${edges.length} routes, including hidden branches` },
    ]} />
    <div className="canonical-steps review-steps">{steps.map((step, index) => {
      const allowed = envelope?.steps.find((item) => item.step_id === step.step_id)?.options;
      const permittedCount = adaptiveAuthorization ? adaptiveAuthorization.steps.find(item => item.step_id === step.step_id)?.methods.length ?? 1 : allowed?.length;
      const selected = allowed?.find((option) => option.behavior_id === step.behavior_id);
      const behaviorId = typeof step.behavior_id === "string" ? step.behavior_id : undefined;
      const behavior = catalog?.behaviors.find(item => item.id === behaviorId);
      const settings = Object.entries(step.parameters && typeof step.parameters === "object" ? step.parameters as Record<string, unknown> : {}).filter(([name, value]) => !/(?:digest|sha256|_id)$/.test(name) && (typeof value === "string" || typeof value === "number" || typeof value === "boolean"));
      const title = selected?.contract.title ?? behavior?.title ?? sentence(String(step.step_id ?? "Unnamed step"));
      const purpose = selected?.contract.purpose ?? behavior?.purpose;
      return <article key={String(step.step_id ?? index)}>
        <span>{String(index + 1).padStart(2, "0")}</span>
        <div><strong>{displayTitle(String(title))}</strong>{purpose ? <p>{String(purpose)}</p> : null}
          <small>{step.action_id ? "Execute the selected method" : "Simulate this step"}{permittedCount && permittedCount > 1 ? ` · ${permittedCount} allowed methods` : ""}</small>
        </div>
        {settings.length ? <div className="review-step-settings"><DataList items={settings.slice(0, 4).map(([name, value]) => ({ label: sentence(name), value: parameterValueLabel(behaviorId, name, value) ?? (typeof value === "boolean" ? value ? "Yes" : "No" : String(value)) }))}/>{settings.length > 4 ? <small>{settings.length - 4} more settings in step details</small> : null}</div> : null}
        <details><summary>Step details</summary><dl>
          <div><dt>Step / method</dt><dd><code>{String(step.step_id)}</code><code>{String(step.action_id ?? step.simulation_id ?? step.behavior_id ?? "Unresolved")}</code></dd></div>
          <div><dt>Parameters</dt><dd><pre>{JSON.stringify(step.parameters ?? {}, null, 2)}</pre></dd></div>
          <div><dt>Input from</dt><dd><pre>{JSON.stringify(step.inputs ?? {}, null, 2)}</pre></dd></div>
          <div><dt>Outputs</dt><dd>{stringList(step.expected_outputs)}</dd></div>
          <div><dt>Required capabilities</dt><dd>{stringList(step.required_capabilities)}</dd></div>
        </dl></details>
      </article>;
    })}</div>
    {adaptiveAuthorization ? <AdaptiveAuthorizationReview authorization={adaptiveAuthorization} envelope={envelope} autonomy={plan.autonomy} /> : null}
    {envelope ? <ApprovalEnvelopeReview envelope={envelope} binding={binding} adaptive={Boolean(adaptiveAuthorization)} /> : null}
    <details><summary>Run identities and full plan</summary>
      <DataList items={[
        { label: "Profile ID", value: profileId || "Not reported" },
        { label: "Scope references", value: scopeReferences.join(", ") || "Not reported" },
        { label: "Plan digest", value: digest ? <code>{String(digest)}</code> : "Not reported" },
        { label: "State digest", value: binding ? <code>{binding.state_digest}</code> : "No Execute approval binding" },
        { label: "Scope digest", value: binding ? <code>{binding.target_scope_digest}</code> : "No Execute approval binding" },
        { label: "Envelope digest", value: envelope ? <code>{envelope.envelope_digest}</code> : "No Execute approval binding" },
      ]} />
      <pre>{JSON.stringify(plan, null, 2)}</pre>
    </details>
  </section>;
});

function stringList(value: unknown) {
  if (!Array.isArray(value)) return "Not reported";
  return value.map((item) => typeof item === "object" && item !== null ? String((item as Record<string, unknown>).name ?? (item as Record<string, unknown>).id ?? JSON.stringify(item)) : String(item)).join(", ") || "None";
}

function ApprovalEnvelopeReview({ envelope, binding, adaptive }: { envelope: ApprovalEnvelope; binding?: ApprovalBinding | null; adaptive?: boolean }) {
  return <section className="approval-envelope" aria-label="Complete Execute approval envelope">
    <header><div><span>{adaptive ? "Registered contracts" : "Allowed methods"}</span><strong>{adaptive ? "Inspect supporting method contracts" : "Review effects and alternatives"}</strong></div><Badge tone="warning">{envelope.steps.reduce((count, step) => count + step.options.length, 0)} methods</Badge></header><details><summary>{adaptive ? "All registered methods, effects and parameters" : "All permitted methods, effects and parameters"}</summary>
    {binding ? <p className="envelope-binding-note"><ShieldCheck/>Confirmation binds this envelope to state <code>{binding.state_digest}</code>, plan <code>{binding.plan_digest}</code>, and scope <code>{binding.target_scope_digest}</code>.</p> : null}
    <div className="envelope-steps">{envelope.steps.map((step, stepIndex) => <article key={step.step_id}><header><span>{String(stepIndex + 1).padStart(2, "0")}</span><strong>{displayTitle(String(step.options[0]?.contract.title ?? "Selected step"))}</strong><Badge>{step.options.length} option{step.options.length === 1 ? "" : "s"}</Badge></header>{step.options.map((option) => { const contract = option.contract; return <section className="envelope-option" key={`${step.step_id}-${option.behavior_id}`}><header><div><Badge tone={option.is_primary ? "info" : "violet"}>{option.is_primary ? "Primary" : adaptive ? "Registered alternative" : "Allowed alternative"}</Badge><strong>{contract.title ? displayTitle(String(contract.title)) : option.behavior_id}</strong><code>{option.behavior_id}</code></div><code title="Behavior contract digest">{option.contract_digest}</code></header><p>{String(contract.purpose ?? "No behavior purpose was reported.")}</p><dl><div><dt>Resolved parameters</dt><dd><pre>{JSON.stringify(option.resolved_parameters, null, 2)}</pre></dd></div><div><dt>Effects contract</dt><dd>{sentence(String(contract.execution_state ?? "not reported"))} · {sentence(String(contract.safety_tier ?? "not reported"))}</dd></div><div><dt>Expected outputs</dt><dd>{stringList(contract.outputs)}</dd></div><div><dt>Observables</dt><dd>{stringList(contract.telemetry)}{Array.isArray(contract.detection_hints) && contract.detection_hints.length ? ` · Detection hints: ${contract.detection_hints.map(String).join(", ")}` : ""}</dd></div></dl><div className="envelope-actions">{option.actions.length ? option.actions.map((action) => <article key={action.action_id}><header><div><Badge tone={action.contract.mutates ? "warning" : "info"}>{action.contract.mutates ? "Mutating action" : "Non-mutating action"}</Badge><strong>{action.contract.title ? displayTitle(String(action.contract.title)) : action.action_id}</strong><code>{action.action_id}</code></div><code title="Action contract digest">{action.contract_digest}</code></header><p>{String(action.contract.purpose ?? "No action purpose was reported.")}</p><DataList items={[{ label: "Capabilities", value: stringList(action.contract.capabilities) }, { label: "Platforms", value: stringList(action.contract.platforms) }, { label: "Effects", value: `${action.contract.mutates ? "Changes the reviewed target" : "Read-only"}; ${sentence(String(action.contract.safety_tier ?? "tier not reported"))}` }, { label: "Expected outputs", value: stringList(action.contract.outputs) }, { label: "Cleanup", value: String(action.contract.cleanup_action_id ?? "No cleanup action declared") }]} /><details><summary>Full deterministic action contract</summary><pre>{JSON.stringify(action.contract, null, 2)}</pre></details></article>) : <Callout tone="warning" title="No deterministic action contract">This option cannot authorize runner effects unless the backend resolves an installed action contract.</Callout>}</div><details><summary>Full behavior contract</summary><pre>{JSON.stringify(contract, null, 2)}</pre></details></section>; })}</article>)}</div>
    </details><details><summary>Raw complete approval envelope</summary><pre>{JSON.stringify(envelope, null, 2)}</pre></details>
  </section>;
}
