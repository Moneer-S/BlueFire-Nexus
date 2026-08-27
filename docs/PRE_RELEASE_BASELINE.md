# Pre-release baseline

This historical baseline maps the pre-1.0 local product surface. It does not satisfy a release gate or establish release readiness. The locked `bluefire acceptance run --release` contract is the machine-verifiable release authority.

## Product boundary

- BlueFire Nexus ships a Python control plane, packaged browser UI, typed catalogs, immutable run records, optional AI proposal handling, and a separately built Rust runner.
- Simulate never dispatches runner effects.
- Execute requires a compatible runner profile, explicit operator scope, current runner readiness, canonical preflight, a one-time approval gate, and receipt-bound cleanup for mutating actions.
- AI `off`, `assist`, and `auto` never create runner authority. Model output is schema-checked and policy-bounded before any accepted proposal changes a run.
- Runner self-report is `executed` evidence. Only configured independent collectors can create `observed` evidence.

## License and source posture

- The project package declares the MIT license and includes `LICENSE`.
- Third-party source intake is documented in `THIRD_PARTY_NOTICES.md` and `docs/SOURCE_INTAKE.md`.
- Research-source records carry pinned references, license review, attribution, exact ref, file-level review, use classification, security review, and update status.
- External research references are not fetched, vendored, or executed by the source registry.
- Optional parser/compiler integrations stay external adapters and require the pinned optional packages documented in `docs/DETECTION_LAB.md`.

## Proof surfaces

| Surface | Proof to inspect |
|---|---|
| Control plane | `tests_platform/` contract tests for planning, policy, jobs, bundles, replay, comparison, evidence, detections, API, storage, and runner integration |
| Runner boundary | `runner/` Rust tests plus `tests_platform/test_runner_*.py` identity, bootstrap, lifecycle, watchdog, and transport tests |
| Packaged wheel | `.github/workflows/tests.yml` native-wheel matrix plus `tools/verify_packaged_runner.py inspect` and `smoke` reports |
| Disposable smoke | `bluefire.installed-wheel-smoke.v1` reports include `disposable_workspace` proof with checkout isolation, no source overrides, sandbox containment, and zero retained files |
| UI authority | `frontend/tests/`, `tests_platform/test_ui_assets.py`, and packaged `bluefire/ui/` assets |
| Detection lifecycle | `docs/DETECTION_LAB.md`, `docs/SOURCE_INTAKE.md`, and detection service tests for lifecycle, fixtures, observed evidence, benign evaluation, revisions, and public baselines |

## Minimum review checklist

1. Confirm the branch head and `git status --short` before reviewing artifacts.
2. Run targeted tests for any touched files, then the full gates in `docs/DEVELOPMENT.md` before release.
3. Build the frontend before Python packaging whenever UI source changed.
4. Build platform wheels in the CI matrix and retain both `package-inspection.json` and `installed-wheel-smoke.json`.
5. Inspect `installed-wheel-smoke.json` for:
   - `verified: true`;
   - packaged bootstrap readiness;
   - installed-wheel import outside the checkout;
   - `disposable_workspace.work_root.outside_checkout: true`;
   - no source runner overrides;
   - all listed sandbox scopes inside the disposable work root;
   - zero retained files after cleanup.
6. Validate final run bundles before sharing, and review run artifacts for sensitive local context.

## Non-claims

- Bundle hashes are integrity checks, not digital signatures or non-repudiation.
- Comparison deltas are not causal proof.
- Demo screenshots and seeded browser data are not proof of live runner execution.
- The shipped runner is local/same-user only; cross-host enrollment, remote execution authority, cloud actions, and production SIEM adapters are not shipped.
- The MIT license does not grant authorization to test systems the operator does not own or control.
