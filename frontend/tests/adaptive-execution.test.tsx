import { useState } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdaptiveMethodEditor, AdaptiveRepair } from "../src/components/AdaptiveMethodEditor";
import { CanonicalPlanReview } from "../src/components/CanonicalPlanReview";
import { adaptiveExecutionIssues, applyAdaptiveStep, applyAdaptiveV2Step, parseAdaptiveExecution, type AdaptiveAuthorization, type AdaptiveExecution, type AdaptiveExecutionV1 } from "../src/lib/adaptive-execution";
import { hasUsableStoredApprovalReview, storedRunApprovalPreflight } from "../src/lib/approvalReview";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { hasExecutePlanReview } from "../src/lib/run-configuration";
import { deleteScenarioGraphElements, parseScenarioDocument, selectScenarioAlternative } from "../src/lib/scenario";
import type { ActionDefinition, ApprovalEnvelope, Behavior, PreflightReport, RunJob, Scenario } from "../src/types";

const base = demoCatalog.behaviors.find(behavior => behavior.id === "sandbox.collection.stage.v1")!;
const primary: Behavior = { ...base, id: "sandbox.collection.records.v1", title: "Collect selected records", action_ids: ["sandbox.collection.records.v1"], compatible_behaviors: ["sandbox.collection.archive.v1"] };
const alternate: Behavior = { ...base, id: "sandbox.collection.archive.v1", title: "Archive selected records", action_ids: ["sandbox.collection.archive.v1"], compatible_behaviors: [primary.id] };
const third: Behavior = { ...base, id: "sandbox.collection.verify.v1", title: "Verify selected records", action_ids: ["sandbox.collection.verify.v1"], compatible_behaviors: [primary.id] };
primary.compatible_behaviors = [alternate.id, third.id];
const behaviors = new Map([...demoCatalog.behaviors, primary, alternate, third].map(behavior => [behavior.id, behavior]));
const actions = new Map([primary, alternate, third].map(behavior => [behavior.id, { ...demoCatalog.actions[0]!, id: behavior.id, title: behavior.title, platforms: ["linux", "windows"], mutates: true, cleanup_action_id: "sandbox.cleanup.v1" } as ActionDefinition]));
const scenario: Scenario = { ...structuredClone(demoScenario), steps: demoScenario.steps.map(step => step.id === "stage" ? { ...step, behavior_id: primary.id, parameters: { stage_variant: "primary" }, alternates: [alternate.id] } : step) };
const methods = [primary, alternate].map(behavior => ({ behavior_id: behavior.id, action_id: behavior.id }));
const policy: AdaptiveExecutionV1 = { schema_version: "bluefire.adaptive-execution.v1", steps: [{ step_id: "stage", methods }], eligible_outcomes: ["blocked", "failed", "partial"], max_retries: 1, on_provider_failure: "stop" };
const saved: Scenario = { ...scenario, adaptive_execution: policy };
const digest = `sha256:${"a".repeat(64)}`;

function Harness({ initial = scenario }: { initial?: Scenario }) {
  const [value, setValue] = useState(() => structuredClone(initial));
  const step = value.steps.find(item => item.id === "stage");
  return <>
    {step ? <AdaptiveMethodEditor key={JSON.stringify(value.adaptive_execution)} scenario={value} step={step} behaviors={behaviors} actions={actions} selectedAction="" onChange={setValue} /> : null}
    <AdaptiveRepair scenario={value} behaviors={behaviors} actions={actions} overrides={{}} onSelect={() => undefined} onChange={setValue} />
    <button onClick={() => setValue(parseScenarioDocument(JSON.parse(JSON.stringify(value))))}>Reopen working graph</button>
    <output aria-label="Saved working graph">{JSON.stringify(value)}</output>
  </>;
}
function current() { return JSON.parse(screen.getByLabelText("Saved working graph").textContent!) as Scenario; }

describe("explicit adaptive method authoring", () => {
  it("applies exactly selected methods and reopens their policy without changing parameters or inputs", async () => {
    const user = userEvent.setup(); render(<Harness />);
    await user.click(screen.getByRole("button", { name: "Configure adaptive retry" }));
    expect(screen.getByRole("button", { name: "Apply retry choices" })).toBeDisabled();
    expect(current().adaptive_execution).toBeUndefined();
    await user.click(screen.getByRole("checkbox", { name: /Archive selected records/ }));
    await user.click(screen.getByRole("checkbox", { name: "Partial result" }));
    await user.selectOptions(screen.getByRole("combobox", { name: /If the model cannot choose/ }), "deterministic");
    await user.click(screen.getByRole("button", { name: "Apply retry choices" }));
    const applied = current();
    expect(applied.adaptive_execution).toEqual({ ...policy, eligible_outcomes: ["blocked", "failed"], on_provider_failure: "deterministic" });
    expect(applied.steps).toEqual(scenario.steps);
    expect(applied.edges).toEqual(scenario.edges);
    await user.click(screen.getByRole("button", { name: "Reopen working graph" }));
    expect(current()).toEqual(applied);
    expect(screen.getByRole("checkbox", { name: /Archive selected records/ })).toBeChecked();
    expect(screen.getByRole("combobox", { name: /If the model cannot choose/ })).toHaveValue("deterministic");
    await user.click(screen.getByRole("checkbox", { name: /Collect selected records/ }));
    expect(screen.getByRole("button", { name: "Apply retry choices" })).toBeDisabled();
    expect(current()).toEqual(applied);
  });

  it("keeps v1 as the normal save path and only writes explicit v2 budgets after opt-in", async () => {
    const user = userEvent.setup(); render(<Harness />);
    await user.click(screen.getByRole("button", { name: "Configure adaptive retry" }));
    await user.click(screen.getByRole("checkbox", { name: /Archive selected records/ }));
    await user.click(screen.getByRole("button", { name: "Apply retry choices" }));
    expect(current().adaptive_execution).toEqual(policy);

    await user.click(screen.getByRole("radio", { name: /Set limits for more alternatives/ }));
    expect(screen.getByRole("spinbutton", { name: /Maximum extra tries across this experiment/ })).toHaveValue(1);
    expect(screen.getByRole("spinbutton", { name: /Maximum extra tries for this step/ })).toHaveValue(1);
    await user.click(screen.getByRole("checkbox", { name: /Verify selected records/ }));
    await user.clear(screen.getByRole("spinbutton", { name: /Maximum extra tries across this experiment/ }));
    await user.type(screen.getByRole("spinbutton", { name: /Maximum extra tries across this experiment/ }), "2");
    await user.clear(screen.getByRole("spinbutton", { name: /Maximum extra tries for this step/ }));
    await user.type(screen.getByRole("spinbutton", { name: /Maximum extra tries for this step/ }), "2");
    expect(screen.getByText(/still need fresh Execute approval/)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Apply retry choices" }));
    const applied = current();
    expect(applied.adaptive_execution).toEqual({ ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 2,
      steps: [{ step_id: "stage", methods: [methods[0]!, methods[1]!, { behavior_id: third.id, action_id: third.id }], max_retries: 2 }] });
    await user.click(screen.getByRole("button", { name: "Reopen working graph" }));
    expect(current()).toEqual(applied);
    expect(screen.getByRole("spinbutton", { name: /Maximum extra tries across this experiment/ })).toHaveValue(2);
    expect(screen.getByRole("spinbutton", { name: /Maximum extra tries for this step/ })).toHaveValue(2);
  });

  it("keeps removed alternatives visible until explicit repair and never widens an unchanged policy", async () => {
    const broken = { ...saved, steps: saved.steps.map(step => step.id === "stage" ? { ...step, alternates: [] } : step) };
    const user = userEvent.setup(); render(<Harness initial={broken} />);
    expect(adaptiveExecutionIssues(current(), behaviors, actions)).toHaveLength(1);
    expect(screen.getByRole("region", { name: "Retry choices need attention" })).toBeVisible();
    expect(current().adaptive_execution).toEqual(policy);
    await user.click(screen.getByRole("button", { name: "Apply retry choices" }));
    expect(current().steps.find(step => step.id === "stage")!.alternates).toEqual([alternate.id]);
    expect(current().adaptive_execution).toEqual(policy);
    expect(adaptiveExecutionIssues(current(), behaviors, actions)).toEqual([]);
  });

  it("retains orphaned choices after deletion and offers an explicit removal", async () => {
    const removed = deleteScenarioGraphElements(saved, ["stage"], []);
    expect(removed.adaptive_execution).toEqual(policy);
    expect(parseScenarioDocument(removed).adaptive_execution).toEqual(policy);
    const user = userEvent.setup(); render(<Harness initial={removed} />);
    expect(screen.getByText(/Retry choices still refer to a removed step/)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Remove choices for deleted step" }));
    expect(current()).not.toHaveProperty("adaptive_execution");
  });

  it("preserves the approved set when choosing another primary and refuses an unregistered pair", () => {
    const swapped = selectScenarioAlternative(saved, "stage", alternate.id, behaviors);
    expect(swapped.adaptive_execution).toEqual(policy);
    expect(adaptiveExecutionIssues(swapped, behaviors, actions)).toEqual([]);
    expect(() => applyAdaptiveStep(saved, "stage", [methods[0]!, { behavior_id: alternate.id, action_id: "unreviewed.action.v1" }], policy, behaviors, actions)).toThrow(/unavailable/);
    expect(saved.adaptive_execution).toEqual(policy);
  });

  it.each([
    ["missing policy", null],
    ["expanded retry limit", { ...policy, max_retries: 2 }],
    ["malformed provider failure policy", { ...policy, on_provider_failure: ["stop"] }],
    ["unregistered command", { ...policy, command: "not permitted" }],
    ["single-method alternative set", { ...policy, steps: [{ step_id: "stage", methods: [methods[0]] }] }],
    ["success as a retry outcome", { ...policy, eligible_outcomes: ["success"] }],
  ])("rejects malformed or expanded authority on restoration: %s", (_case, value) => {
    expect(() => parseAdaptiveExecution(value)).toThrow();
    expect(() => parseScenarioDocument({ ...scenario, adaptive_execution: value })).toThrow();
    expect(parseScenarioDocument(scenario)).not.toHaveProperty("adaptive_execution");
  });

  it.each([
    ["zero experiment cap", { ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 0, steps: [{ step_id: "stage", methods, max_retries: 1 }] }],
    ["experiment cap above eight", { ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 9, steps: [{ step_id: "stage", methods, max_retries: 1 }] }],
    ["per-step cap above distinct methods", { ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 2, steps: [{ step_id: "stage", methods, max_retries: 2 }] }],
    ["per-step cap above three", { ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 4, steps: [{ step_id: "stage", methods: [methods[0]!, methods[1]!, { behavior_id: third.id, action_id: third.id }, { behavior_id: "sandbox.collection.stage.v1", action_id: "sandbox.collection.stage.v1" }], max_retries: 4 }] }],
    ["experiment cap above step-cap sum", { ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 2, steps: [{ step_id: "stage", methods, max_retries: 1 }] }],
  ])("rejects invalid v2 retry authority: %s", (_case, value) => {
    expect(() => parseAdaptiveExecution(value)).toThrow();
  });

  it("preserves the explicitly selected v2 caps when editing one of several steps", () => {
    const broadMethods = [...methods, { behavior_id: third.id, action_id: third.id },
      { behavior_id: "sandbox.collection.stage.v1", action_id: "sandbox.collection.stage.v1" }];
    const second = { step_id: "verify", methods: broadMethods, max_retries: 2 };
    const multi: Scenario = { ...scenario, steps: [...scenario.steps, { ...scenario.steps[0]!, id: "verify" }],
      adaptive_execution: { ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 3,
        steps: [{ step_id: "stage", methods, max_retries: 1 }, second] } };
    const next = applyAdaptiveV2Step(multi, "stage", methods, { eligible_outcomes: ["failed"], on_provider_failure: "stop", max_retries: 3, step_max_retries: 1 }, behaviors, actions);
    expect(next.adaptive_execution).toMatchObject({ schema_version: "bluefire.adaptive-execution.v2", max_retries: 3,
      steps: [{ step_id: "stage", max_retries: 1 }, { step_id: "verify", max_retries: 2 }] });
  });

  it("accepts the documented maximum when per-step capacity covers it", () => {
    const fourMethods = [...methods, { behavior_id: third.id, action_id: third.id },
      { behavior_id: "sandbox.collection.stage.v1", action_id: "sandbox.collection.stage.v1" }];
    const maximum: AdaptiveExecution = { schema_version: "bluefire.adaptive-execution.v2",
      steps: [{ step_id: "stage", methods: fourMethods, max_retries: 3 }, { step_id: "verify", methods: fourMethods, max_retries: 3 },
        { step_id: "archive", methods: fourMethods, max_retries: 2 }], eligible_outcomes: ["failed"], max_retries: 8, on_provider_failure: "stop" };
    expect(parseAdaptiveExecution(maximum)).toEqual(maximum);
  });

  it("removes v2 caps only when the operator explicitly applies the v1 option", () => {
    const v2: Scenario = { ...scenario, adaptive_execution: { schema_version: "bluefire.adaptive-execution.v2", steps: [
      { step_id: "stage", methods, max_retries: 1 }, { step_id: "verify", methods, max_retries: 1 }],
      eligible_outcomes: ["failed"], max_retries: 2, on_provider_failure: "stop" } };
    const v1 = applyAdaptiveStep(v2, "stage", methods, { eligible_outcomes: ["failed"], on_provider_failure: "stop" }, behaviors, actions);
    expect(v1.adaptive_execution).toMatchObject({ schema_version: "bluefire.adaptive-execution.v1", max_retries: 1,
      steps: [{ step_id: "stage", methods }, { step_id: "verify", methods }] });
    expect(v1.adaptive_execution!.steps.every(step => !("max_retries" in step))).toBe(true);
  });

  it("removes retained v2 caps when the v1 option adds a newly configured step", () => {
    const stage = scenario.steps.find(item => item.id === "stage")!;
    const v2: Scenario = { ...scenario, steps: [...scenario.steps, { ...stage, id: "verify" }],
      adaptive_execution: { schema_version: "bluefire.adaptive-execution.v2", steps: [
        { step_id: "stage", methods, max_retries: 1 }], eligible_outcomes: ["failed"], max_retries: 1, on_provider_failure: "stop" } };
    const v1 = applyAdaptiveStep(v2, "verify", methods,
      { eligible_outcomes: ["failed"], on_provider_failure: "stop" }, behaviors, actions);
    expect(v1.adaptive_execution).toEqual({ schema_version: "bluefire.adaptive-execution.v1", max_retries: 1,
      eligible_outcomes: ["failed"], on_provider_failure: "stop", steps: [
        { step_id: "stage", methods }, { step_id: "verify", methods }] });
    expect(v1.adaptive_execution!.steps.every(step => !("max_retries" in step))).toBe(true);
  });
});

function reviewed(): { authorization: AdaptiveAuthorization; envelope: ApprovalEnvelope; report: PreflightReport } {
  const source = saved.steps.find(step => step.id === "stage")!;
  const authorization: AdaptiveAuthorization = {
    schema_version: "bluefire.adaptive-authorization.v1", scenario_digest: digest, plan_digest: digest, profile_digest: digest,
    objective: "Verify the selected records independently", target_scope: { scope_refs: ["sandbox.workspace"] }, platform: "linux", catalog_authority_digest: digest,
    policy, parameter_policy: "exact_reviewed_values_and_inputs", limits: { max_steps: 12, max_seconds: 90, max_artifacts: 32, max_bytes: 1048576 }, cleanup_policy: "always", authorization_digest: digest,
    steps: [{ step_id: "stage", methods: methods.map(method => ({ plan_step: { ...method, step_id: "stage", parameters: source.parameters, inputs: source.inputs, expected_outputs: ["bundle"], required_capabilities: ["filesystem.write"], safety_tier: "safe" },
      plan_step_digest: digest, behavior_contract_digest: digest, action_contract_digest: digest, execution_binding_digest: digest, capabilities: ["filesystem.write"], mutates: true, cleanup_action_id: "sandbox.cleanup.v1", cleanup_contract_digest: digest })) }],
  };
  const envelope: ApprovalEnvelope = { schema_version: "bluefire.approval-envelope.v1", scenario_id: saved.id, envelope_digest: digest, steps: [{ step_id: "stage", options: [primary, alternate].map(behavior => ({ behavior_id: behavior.id, is_primary: behavior.id === primary.id, contract_digest: digest, contract: { title: behavior.title }, resolved_parameters: source.parameters, actions: [{ action_id: behavior.id, contract_digest: digest, contract: { title: behavior.title } }] })) }] };
  return { authorization, envelope, report: { status: "approval_required", ready: false, plan: { mode: "execute", autonomy: "auto", runner_profile_id: "sandbox-execute.v1", steps: [authorization.steps[0]!.methods[0]!.plan_step], edges: [] }, adaptive_authorization: authorization, approval_envelope: envelope, approval_binding: { state_digest: digest, plan_digest: digest, target_scope_digest: digest, profile_id: "sandbox-execute.v1", maximum_tier: "safe" } } };
}

describe("reviewed adaptive authority", () => {
  it("shows exact methods, objective, data, failure, and cleanup bounds beside the canonical plan", () => {
    const { authorization, envelope, report } = reviewed();
    envelope.steps[0]!.options.push({ ...envelope.steps[0]!.options[1]!, behavior_id: "sandbox.collection.unselected.v1" });
    render(<CanonicalPlanReview plan={report.plan!} adaptiveAuthorization={authorization} envelope={envelope} binding={report.approval_binding} />);
    const review = screen.getByRole("region", { name: "Reviewed adaptive execution" });
    expect(within(review).getByText(/Auto may choose one of these methods from the observed result/)).toBeVisible();
    expect(within(review).getByText("Archive selected records")).toBeVisible();
    expect(within(review).getByText("Verify the selected records independently")).toBeVisible();
    expect(within(review).getByText(/12 total steps · 90 seconds/)).toBeVisible();
    expect(within(review).getAllByText(/Stage variant: "primary"/)).toHaveLength(2);
    expect(within(review).getByText("Stop and clean up")).toBeVisible();
    expect(within(review).getByText("Required on completion, failure and cancellation")).toBeVisible();
    expect(screen.queryByText("All permitted methods, effects and parameters")).not.toBeInTheDocument();
    expect(screen.getByText("Execute the selected method · 2 allowed methods")).toBeVisible();
    expect(screen.queryByText(/3 allowed methods/)).not.toBeInTheDocument();
  });

  it("labels Off and deterministic fallback without claiming a live model result", () => {
    const { authorization, envelope, report } = reviewed(); authorization.policy = { ...policy, on_provider_failure: "deterministic" };
    render(<CanonicalPlanReview plan={{ ...report.plan, autonomy: "off" }} adaptiveAuthorization={authorization} envelope={envelope} />);
    const review = screen.getByRole("region", { name: "Reviewed adaptive execution" });
    expect(within(review).getByText(/Off follows the saved primary methods/)).toBeVisible();
    expect(within(review).getByText(/record deterministic fallback, not live-model success/)).toBeVisible();
  });

  it("shows the v2 experiment and per-step caps in the fresh Execute review", () => {
    const { authorization, envelope, report } = reviewed();
    authorization.schema_version = "bluefire.adaptive-authorization.v2";
    authorization.policy = { ...policy, schema_version: "bluefire.adaptive-execution.v2", max_retries: 1,
      steps: [{ step_id: "stage", methods, max_retries: 1 }] };
    render(<CanonicalPlanReview plan={report.plan!} adaptiveAuthorization={authorization} envelope={envelope} binding={report.approval_binding} />);
    const review = screen.getByRole("region", { name: "Reviewed adaptive execution" });
    expect(within(review).getByText(/Up to 1 extra try across the experiment/)).toBeVisible();
    expect(within(review).getByText(/Step retry cap: up to 1 extra try after the initial method/)).toBeVisible();
  });

  it("requires the current adaptive review when restoring an opted-in pending approval", () => {
    const { report } = reviewed();
    const job = { job_id: "job", kind: "scenario.run", state: "awaiting_approval", request: { scenario: saved, approval_request_id: "approval", _run_submission_preflight: report }, progress: {}, approval_request: { ...report.approval_binding, approval_id: "approval", status: "pending", expires_at: "2099-01-01T00:00:00Z" } } as unknown as RunJob;
    expect(storedRunApprovalPreflight(job)).toBe(report);
    expect(hasExecutePlanReview(report, saved)).toBe(true);
    expect(hasUsableStoredApprovalReview({ ...report, adaptive_authorization: { ...report.adaptive_authorization!, plan_digest: "other" } })).toBe(false);
    delete report.adaptive_authorization;
    expect(storedRunApprovalPreflight(job)).toBeUndefined();
    expect(hasExecutePlanReview(report, saved)).toBe(false);
    expect(hasExecutePlanReview(report, scenario)).toBe(true);
  });
});
