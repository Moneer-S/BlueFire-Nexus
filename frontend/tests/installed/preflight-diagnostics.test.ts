import { describe, expect, it } from "vitest";
import { preflightDiagnostic } from "./preflight-diagnostics.mjs";

const expected = {
  profileId: "sandbox-execute.v1",
  actionIds: ["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1"],
};

function validPreflight(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: "bluefire.preflight.v1",
    status: "refused",
    ready: false,
    mode: "execute",
    scenario_id: "fixture-scenario",
    runner_profile_id: expected.profileId,
    ai_enabled: false,
    autonomy: "off",
    ai_provider: {},
    actions: expected.actionIds,
    required_capabilities: [],
    approval_required: true,
    problems: ["Explicit operator approval is required."],
    plan: {
      schema_version: "bluefire.plan.v1",
      scenario_id: "fixture-scenario",
      objective: "fixture objective",
      mode: "execute",
      autonomy: "off",
      ai_enabled: false,
      ai_provider: {},
      runner_profile_id: expected.profileId,
      scenario_digest: "digest-value",
      steps: [],
      edges: [],
    },
    ...overrides,
  };
}

describe("installed preflight diagnostics", () => {
  it("projects only fixed fields and known labels for a refused response", () => {
    const diagnostic = preflightDiagnostic(validPreflight({
      status: "refused",
      ready: false,
      approval_required: true,
      actions: expected.actionIds,
      runner_readiness: { schema_version: "bluefire.execute-readiness.v1", profile_id: expected.profileId },
      problems: [
        "Explicit operator approval is required.",
        "target scope is outside the selected profile: secret-path-value",
        "unrecognized-secret-token-value",
      ],
    }), expected);

    expect(diagnostic).toEqual({
      schema_version: "bluefire.installed-preflight-diagnostic.v1",
      response_shape_valid: true,
      status: "refused",
      ready: false,
      approval_required: true,
      plan_mode: "execute",
      runner_profile_matches_expected: true,
      runner_readiness_present: true,
      runner_readiness_schema_valid: true,
      runner_readiness_profile_matches_expected: true,
      actions_match_expected: true,
      problem_count: 3,
      problem_scan_truncated: false,
      problem_labels: ["approval_missing", "target_scope_outside_profile"],
      unknown_problem_count: 1,
    });
    const serialized = JSON.stringify(diagnostic);
    expect(serialized).not.toContain("secret-path-value");
    expect(serialized).not.toContain("unrecognized-secret-token-value");
  });

  it("marks malformed responses without retaining supplied values", () => {
    const diagnostic = preflightDiagnostic(["secret", "runner/path"]);
    expect(diagnostic.response_shape_valid).toBe(false);
    expect(diagnostic.status).toBe("unknown");
    expect(diagnostic.ready).toBeNull();
    expect(diagnostic.problem_count).toBe(0);
    expect(JSON.stringify(diagnostic)).not.toContain("runner/path");
  });

  it("caps inspected problem data and reports truncation", () => {
    const problems = Array.from({ length: 40 }, (_, index) => `secret-token-${index}`);
    const diagnostic = preflightDiagnostic(validPreflight({ problems }));
    expect(diagnostic.problem_count).toBe(32);
    expect(diagnostic.problem_scan_truncated).toBe(true);
    expect(diagnostic.unknown_problem_count).toBe(32);
    expect(diagnostic.problem_labels).toEqual([]);
    expect(JSON.stringify(diagnostic)).not.toContain("secret-token-");
  });

  it("uses unknown for non-allowlisted status and problem strings", () => {
    const diagnostic = preflightDiagnostic(validPreflight({
      status: "secret-status",
      problems: ["Explicit operator approval is required. changed"],
    }));
    expect(diagnostic.status).toBe("unknown");
    expect(diagnostic.response_shape_valid).toBe(false);
    expect(diagnostic.problem_labels).toEqual([]);
    expect(diagnostic.unknown_problem_count).toBe(1);
    expect(JSON.stringify(diagnostic)).not.toContain("secret-status");
  });

  it("rejects missing or incorrect top-level schema versions", () => {
    expect(preflightDiagnostic(validPreflight({ schema_version: undefined })).response_shape_valid).toBe(false);
    expect(preflightDiagnostic(validPreflight({ schema_version: "bluefire.preflight.v0" })).response_shape_valid).toBe(false);
  });

  it("rejects missing or malformed plan and actions shapes", () => {
    expect(preflightDiagnostic(validPreflight({ plan: undefined })).response_shape_valid).toBe(false);
    expect(preflightDiagnostic(validPreflight({ plan: { schema_version: "bluefire.plan.v0" } })).response_shape_valid).toBe(false);
    expect(preflightDiagnostic(validPreflight({
      plan: { ...validPreflight().plan, steps: undefined },
    })).response_shape_valid).toBe(false);
    expect(preflightDiagnostic(validPreflight({ actions: undefined })).response_shape_valid).toBe(false);
    expect(preflightDiagnostic(validPreflight({ actions: "secret-actions" })).response_shape_valid).toBe(false);
    expect(preflightDiagnostic(validPreflight({ actions: ["safe", 42] })).response_shape_valid).toBe(false);
  });
});
