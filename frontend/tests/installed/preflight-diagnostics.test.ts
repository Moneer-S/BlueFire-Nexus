import { describe, expect, it } from "vitest";
import { preflightDiagnostic } from "./preflight-diagnostics.mjs";

const expected = {
  profileId: "sandbox-execute.v1",
  actionIds: ["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1"],
};

describe("installed preflight diagnostics", () => {
  it("projects only fixed fields and known labels for a refused response", () => {
    const diagnostic = preflightDiagnostic({
      status: "refused",
      ready: false,
      approval_required: true,
      plan: { mode: "execute", runner_profile_id: expected.profileId },
      actions: expected.actionIds,
      runner_readiness: { schema_version: "bluefire.execute-readiness.v1", profile_id: expected.profileId },
      problems: [
        "Explicit operator approval is required.",
        "target scope is outside the selected profile: secret-path-value",
        "unrecognized-secret-token-value",
      ],
    }, expected);

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
    const diagnostic = preflightDiagnostic({ status: "refused", problems });
    expect(diagnostic.problem_count).toBe(32);
    expect(diagnostic.problem_scan_truncated).toBe(true);
    expect(diagnostic.unknown_problem_count).toBe(32);
    expect(diagnostic.problem_labels).toEqual([]);
    expect(JSON.stringify(diagnostic)).not.toContain("secret-token-");
  });

  it("uses unknown for non-allowlisted status and problem strings", () => {
    const diagnostic = preflightDiagnostic({
      status: "secret-status",
      problems: ["Explicit operator approval is required. changed"],
    });
    expect(diagnostic.status).toBe("unknown");
    expect(diagnostic.problem_labels).toEqual([]);
    expect(diagnostic.unknown_problem_count).toBe(1);
    expect(JSON.stringify(diagnostic)).not.toContain("secret-status");
  });
});
