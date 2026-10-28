export interface PreflightDiagnosticExpectation {
  profileId?: string;
  actionIds?: string[];
}

export interface PreflightDiagnostic {
  schema_version: "bluefire.installed-preflight-diagnostic.v1";
  response_shape_valid: boolean;
  status: "approval_required" | "refused" | "ready" | "unknown";
  ready: boolean | null;
  approval_required: boolean | null;
  plan_mode: "execute" | "simulate" | "unknown";
  runner_profile_matches_expected: boolean | null;
  runner_readiness_present: boolean;
  runner_readiness_schema_valid: boolean;
  runner_readiness_profile_matches_expected: boolean | null;
  actions_match_expected: boolean | null;
  problem_count: number;
  problem_scan_truncated: boolean;
  problem_labels: string[];
  unknown_problem_count: number;
}

export function preflightDiagnostic(
  report: unknown,
  expected?: PreflightDiagnosticExpectation,
): PreflightDiagnostic;
