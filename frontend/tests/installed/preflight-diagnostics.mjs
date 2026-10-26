const MAX_PROBLEMS = 32;

const problemLabels = new Map([
  ["Explicit operator approval is required.", "approval_missing"],
  ["Execute requires an explicit runner profile.", "execute_profile_missing"],
  ["Execute requires an available Rust runner transport.", "runner_transport_unavailable"],
  ["Configured collectors are not ready for Execute.", "collector_readiness_refused"],
  ["Runner readiness could not be verified; check the selected profile and retry.", "runner_readiness_unverified"],
  ["Runner inventory is unavailable; verify the selected runner and retry.", "runner_inventory_unavailable"],
  ["Runner inventory is unavailable or invalid; verify the selected runner and retry.", "runner_inventory_invalid"],
  ["An enabled method needs tool setup or is unavailable on this runner.", "runner_action_unavailable"],
  ["Runner inventory is missing profile-enabled actions.", "runner_actions_missing"],
  ["Mutating Execute actions require cleanup_policy: always.", "cleanup_policy_refused"],
  ["Mutating Execute actions require the registered cleanup action.", "cleanup_action_missing"],
  ["The runner profile control-blocks its required cleanup action.", "cleanup_action_blocked"],
  ["The Execute plan has no registered cleanup step.", "cleanup_step_missing"],
  ["Execute requires an explicit target_scope", "target_scope_missing"],
  ["target_scope must contain only scope_refs", "target_scope_shape_invalid"],
  ["target_scope.scope_refs must be a non-empty string list", "target_scope_refs_invalid"],
  ["an Execute runner profile is required before scope can be resolved", "target_scope_profile_missing"],
]);

const problemPrefixes = [
  ["target scope is outside the selected profile: ", "target_scope_outside_profile"],
  ["Sandbox readiness changed after review;", "sandbox_readiness_changed"],
  ["Execute readiness binding is invalid;", "readiness_binding_invalid"],
  ["Execute readiness action binding is invalid;", "readiness_action_binding_invalid"],
  ["Execute readiness catalog binding is invalid;", "readiness_catalog_binding_invalid"],
  ["Execute readiness freshness is invalid;", "readiness_freshness_invalid"],
  ["Execute readiness expired;", "readiness_expired"],
  ["Runner inventory is missing enabled action(s): ", "runner_actions_missing"],
  ["Runner enabled action(s) are not ready: ", "runner_action_unavailable"],
];

const statusValues = new Set(["approval_required", "refused", "ready"]);
const planModes = new Set(["execute", "simulate"]);
const readinessSchemas = new Set(["bluefire.execute-readiness.v1"]);

function booleanOrNull(value) {
  return typeof value === "boolean" ? value : null;
}

function statusValue(value) {
  return typeof value === "string" && statusValues.has(value) ? value : "unknown";
}

function planMode(value) {
  return typeof value === "string" && planModes.has(value) ? value : "unknown";
}

function labelForProblem(value) {
  if (typeof value !== "string") return null;
  const exact = problemLabels.get(value);
  if (exact) return exact;
  for (const [prefix, label] of problemPrefixes) {
    if (value.startsWith(prefix)) return label;
  }
  return null;
}

function matchesExpectedProfile(value, expectedProfileId) {
  return typeof expectedProfileId === "string" && expectedProfileId.length > 0
    ? value === expectedProfileId
    : null;
}

function matchesExpectedActions(value, expectedActionIds) {
  if (!Array.isArray(expectedActionIds) || !Array.isArray(value)) return null;
  return value.length === expectedActionIds.length
    && value.every((action, index) => action === expectedActionIds[index]);
}

export function preflightDiagnostic(report, expected = {}) {
  const responseShapeValid = report !== null && typeof report === "object" && !Array.isArray(report)
    && typeof report.status === "string" && Array.isArray(report.problems);
  const expectedValues = expected !== null && typeof expected === "object" && !Array.isArray(expected)
    ? expected
    : {};
  const problems = responseShapeValid && Array.isArray(report.problems) ? report.problems : [];
  const inspected = problems.slice(0, MAX_PROBLEMS);
  const labels = [];
  let unknownProblemCount = 0;
  for (const problem of inspected) {
    const label = labelForProblem(problem);
    if (label === null) unknownProblemCount += 1;
    else if (!labels.includes(label)) labels.push(label);
  }
  const runnerReadiness = responseShapeValid ? report.runner_readiness : null;
  const readinessPresent = runnerReadiness !== null && typeof runnerReadiness === "object" && !Array.isArray(runnerReadiness);
  const profile = responseShapeValid && report.plan && typeof report.plan === "object"
    ? report.plan.runner_profile_id
    : undefined;
  const readinessProfile = readinessPresent ? runnerReadiness.profile_id : undefined;

  return {
    schema_version: "bluefire.installed-preflight-diagnostic.v1",
    response_shape_valid: responseShapeValid,
    status: responseShapeValid ? statusValue(report.status) : "unknown",
    ready: responseShapeValid ? booleanOrNull(report.ready) : null,
    approval_required: responseShapeValid ? booleanOrNull(report.approval_required) : null,
    plan_mode: responseShapeValid && report.plan && typeof report.plan === "object"
      ? planMode(report.plan.mode)
      : "unknown",
    runner_profile_matches_expected: matchesExpectedProfile(profile, expectedValues.profileId),
    runner_readiness_present: readinessPresent,
    runner_readiness_schema_valid: readinessPresent && readinessSchemas.has(runnerReadiness.schema_version),
    runner_readiness_profile_matches_expected: matchesExpectedProfile(readinessProfile, expectedValues.profileId),
    actions_match_expected: responseShapeValid
      ? matchesExpectedActions(report.actions, expectedValues.actionIds)
      : null,
    problem_count: Math.min(problems.length, MAX_PROBLEMS),
    problem_scan_truncated: problems.length > MAX_PROBLEMS,
    problem_labels: labels,
    unknown_problem_count: unknownProblemCount,
  };
}
