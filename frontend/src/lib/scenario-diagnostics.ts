import { ApiError } from "./api";
import { inputLabel } from "./graph-view";
import type { Behavior, Scenario } from "../types";

export interface ScenarioDiagnostic { message: string; stepId?: string }
const fallback: ScenarioDiagnostic = { message: "Review the experiment’s steps, connections and parameters, then validate again." };
const maximumFindings = 8;
const identifierList = /^[a-z][a-z0-9_]*(?:, [a-z][a-z0-9_]*)*$/;
const parameterTypeRepairs: Record<string, string> = {
  string: "Enter text.", integer: "Enter a whole number.", number: "Enter a number.", boolean: "Choose on or off.", string_list: "Enter a list of text values.",
};

/** Project only known validation grammar; never render arbitrary server details. */
export function scenarioDiagnostics(details: unknown, scenario: Scenario, behaviors: ReadonlyMap<string, Behavior>, name: (id: string) => string): ScenarioDiagnostic[] {
  const steps = new Map(scenario.steps.map(step => [step.id, step]));
  const forStep = (id: string, repair: string): ScenarioDiagnostic => ({ stepId: id, message: `${name(id)}: ${repair}` });
  const parse = (detail: string): ScenarioDiagnostic[] => {
    const unreachable = detail.match(/^scenario contains unreachable steps: (.+)$/);
    if (unreachable && identifierList.test(unreachable[1]!)) {
      return unreachable[1]!.split(", ").filter(id => steps.has(id)).slice(0, maximumFindings)
        .map(id => forStep(id, "This step cannot be reached. Connect a route from an earlier step, or remove it."));
    }
    const graphErrors: Record<string, string> = {
      "scenario graph contains a cycle": "A route loops back to an earlier step. Remove the loop so every path can finish.",
      "scenario.steps contains duplicate IDs": "Two steps share the same identifier. Give each a unique Step ID in Technical details.",
      "scenario.edges contains duplicate outcome routes": "A step has more than one route for the same outcome. Keep one next step for each outcome.",
    };
    if (Object.hasOwn(graphErrors, detail)) return [{ message: graphErrors[detail]! }];
    if (detail === "scenario start step cannot have incoming edges" && steps.has(scenario.start)) return [forStep(scenario.start, "The first step cannot have an incoming route. Remove that route or choose a different first step.")];
    if (/^scenario start step does not exist: [a-z][a-z0-9_]*$/.test(detail)) return [{ message: "Choose an existing step as the first step of this experiment." }];
    if (/^edge references unknown (source|destination) step: [a-z][a-z0-9_]*$/.test(detail)) return [{ message: "A route refers to a removed step. Reconnect or remove that route." }];
    const match = detail.match(/^step ([a-z][a-z0-9_]*)([ .].*)$/);
    const step = match ? steps.get(match[1]!) : undefined;
    if (!step) return [];
    const suffix = match![2]!;
    const behavior = behaviors.get(step.behavior_id);
    const missingInputs = suffix.match(/^ is missing input bindings: (.+)$/);
    if (missingInputs && identifierList.test(missingInputs[1]!)) {
      const ports = missingInputs[1]!.split(", ");
      if (ports.every(port => behavior?.inputs.some(input => input.name === port))) return [forStep(step.id, `Choose compatible earlier outputs for these required inputs: ${ports.map(inputLabel).join(", ")}.`)];
    }
    const input = suffix.match(/^ input ([a-z][a-z0-9_]*) (is not guaranteed by all incoming paths|references unknown step [a-z][a-z0-9_]*|references unknown artifact [a-z][a-z0-9_]*\.[a-z][a-z0-9_]*|type does not match [a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)$/);
    if (input && behavior?.inputs.some(port => port.name === input[1])) return [forStep(step.id, `${inputLabel(input[1]!)} needs a compatible output from a step that runs on every incoming path. Reconnect this input in step details.`)];
    if (/^ binds unknown input ports: /.test(suffix)) return [forStep(step.id, "An input is no longer available for this method. Review its input connections.")];
    const parameter = suffix.match(/^\.parameters\.([a-z][a-z0-9_]*) (must have type (?:string|integer|number|boolean|string_list)|is not an allowed value|is below the minimum|exceeds the maximum)$/);
    if (parameter && behavior?.parameters.some(spec => spec.name === parameter[1])) {
      const reason = parameter[2]!;
      const repair = reason === "is not an allowed value" ? "Choose one of the allowed values."
        : reason === "is below the minimum" || reason === "exceeds the maximum" ? "Enter a value within the allowed range."
          : parameterTypeRepairs[reason.slice("must have type ".length)] ?? "Enter a value of the required type.";
      return [forStep(step.id, `${inputLabel(parameter[1]!)} is invalid. ${repair}`)];
    }
    if (/^\.parameters is missing fields: /.test(suffix)) return [forStep(step.id, "Complete the required parameters in step details.")];
    if (/^\.parameters has unknown fields: /.test(suffix)) return [forStep(step.id, "Some parameters are no longer supported by this method. Review this step’s method and parameters.")];
    if (/^ alternate [a-z][a-z0-9_.]* is not contract-compatible$/.test(suffix)) return [forStep(step.id, "An alternate method has incompatible inputs or outputs. Choose a compatible alternate.")];
    return [];
  };
  const findings = Array.isArray(details) ? details.slice(0, maximumFindings).flatMap(detail =>
    typeof detail === "string" && detail.length <= 1600 && !/[\r\n]/.test(detail) ? parse(detail) : []) : [];
  const distinct = findings.filter((finding, index) => findings.findIndex(other => other.message === finding.message && other.stepId === finding.stepId) === index);
  return distinct.length ? distinct.slice(0, maximumFindings) : [fallback];
}

export function scenarioAuthoringFailure(error: unknown, scenario: Scenario, behaviors: ReadonlyMap<string, Behavior>, name: (id: string) => string) {
  const rejected = error instanceof ApiError && error.status === 422 && ["scenario_invalid", "scenario_version_invalid"].includes(error.code);
  if (rejected) return { rejected, findings: scenarioDiagnostics(error.details, scenario, behaviors, name) };
  const messages: Record<string, string> = {
    service_unavailable: "The local service is unavailable. Check that BlueFire is running, then try again.",
    request_timeout: "The local service did not respond in time. Try again before reviewing a run.",
    browser_session_unavailable: "This browser session is unavailable. Relaunch BlueFire and open its new local tab.",
  };
  return { rejected: false, findings: [{ message: error instanceof ApiError && Object.hasOwn(messages, error.code) ? messages[error.code]! : "The request could not be completed. Try again; your working copy is preserved." }] as ScenarioDiagnostic[] };
}
