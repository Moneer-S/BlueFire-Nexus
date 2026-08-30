# Development guide

BlueFire is a Python control plane, a separately built Rust runner, and a React/TypeScript frontend. Keep their authority boundaries explicit when making changes.

## Repository map

| Path | Responsibility |
|---|---|
| `bluefire/` | Python contracts, registry, planner, AI proposal boundary, policy, orchestration, storage, evidence, detections, API, CLI |
| `bluefire/catalog/` | Built-in behavior/action catalogs |
| `bluefire/data/` | Packaged scenarios, config, and research registry |
| `scenarios/` | Checkout copies of the eight canonical scenarios |
| `config/` | Declarative example configuration |
| `runner/` | Rust execution authority and boundary tests |
| `frontend/` | React/TypeScript source, unit tests, and Playwright tests |
| `bluefire/ui/` | Built frontend assets packaged by Python |
| `tests_platform/` | Python contract, integration, storage, and E2E tests |
| `docs/` | Public user, operator, and developer documentation |

## Python setup

Python 3.10 or newer:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Optional maintained detection adapters:

```bash
python -m pip install "pysigma==1.5.0" "pysigma-backend-sqlite==1.2.2" "yara-python==4.5.4"
```

The installed YARA adapter and reviewed upstream research record are both pinned to 4.5.4.

The optional SQLite backend pin is package version 1.2.2, upstream tag `v1.2.2`, commit
`cfc0a2dd75470f73e2e375c3e58aecc21a33fbc6`, and license LGPL-3.0-only. The official
plugin directory currently labels it `testing`, so keep the exact pin and focused conversion/
execution contract tests. Installing it is not evidence that an application path imported it or
executed generated SQL. The package declares pySigma as its only runtime dependency and does not
justify another `pip-audit` exception.

Do not install project dependencies globally. Keep test run stores, databases, sandboxes, caches, and build artifacts untracked.

## Python verification

```bash
python -m compileall -q bluefire tests_platform
python -m pytest
python -m ruff check bluefire tests_platform
python -m black --check bluefire tests_platform
python -m mypy bluefire
python -m bandit -r bluefire -ll
python -m pip_audit --ignore-vuln PYSEC-2026-2447
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
gitleaks git --redact --no-banner
python -m build
```

The single `pip-audit` exception is the reviewed, transitive optional pySigma/DiskCache advisory documented in [Security](../SECURITY.md); do not add or silently broaden exceptions.

Run targeted tests while iterating, then the complete suite. Do not weaken refusal, provenance, cleanup, or boundary assertions to obtain green.

## Rust setup and verification

Use the toolchain declared in `rust-toolchain.toml` and a repository-local target directory where host policy requires it.

```bash
cargo fmt --manifest-path runner/Cargo.toml -- --check
cargo clippy --manifest-path runner/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path runner/Cargo.toml --all
python tools/build_native_runner.py
./runner/target/release/bluefire-runner inventory --json
```

On Windows, the final command is `.\runner\target\release\bluefire-runner.exe inventory --json`.
The release helper uses fixed Cargo arguments, remaps the host home, workspace, checkout, Cargo
home, Rustup home, and target directory through encoded rustc flags, disables incremental
compilation, and rejects a binary that still contains one of those host paths. Set `CARGO`,
`CARGO_HOME`, `RUSTUP_HOME`, or `CARGO_TARGET_DIR` before invoking it when a controlled build
environment needs non-default paths. Do not add release flags through `RUSTFLAGS`; the helper
deliberately replaces inherited flags.

Runner tests may use only temporary roots and loopback. They must not need elevation, a host service, an external network, personal files, or persistent host changes.

## Frontend setup and verification

The workspace declares pnpm 11.19.0.

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm test:e2e
```

Chromium is the required default browser. For a local Firefox smoke after installing the pinned
Playwright browser, set `BLUEFIRE_CROSS_BROWSER=1` (PowerShell:
`$env:BLUEFIRE_CROSS_BROWSER = "1"`) before `pnpm test:e2e`; the same journeys then run in both
browsers.

`pnpm dev` and `pnpm dev:demo` are the deterministic sanitized hot-reload surface and refuse Execute. They deliberately expose no live API proxy: the production one-use browser capability and session cookie are bound to the Python listener's exact origin. For live control-plane testing, run `pnpm build`, launch `bluefire ui`, and open the exact capability-bearing URL printed after bind. `pnpm build` replaces `bluefire/ui` with production assets.

Before accepting UI changes, test keyboard navigation, focus/dialog behavior, loading/error/empty/refusal states, graph editing, preflight, run review, approval, replay/compare, settings import/export, axe checks, responsive layouts, and no console errors.

## Product-level tests

The opt-in real-runner E2E harness requires a freshly built binary:

```bash
export BLUEFIRE_E2E_RUNNER="$(pwd)/runner/target/release/bluefire-runner"
python -m pytest tests_platform/test_execute_e2e.py
```

Windows PowerShell:

```powershell
$env:BLUEFIRE_E2E_RUNNER = (Resolve-Path .\runner\target\release\bluefire-runner.exe)
python -m pytest tests_platform\test_execute_e2e.py
```

The harness creates temporary sandboxes and currently covers the canonical, Linux-oriented, Windows-oriented, and restricted-canary scenario cases. Keep this opt-in because a real runner performs real local effects even though the fixtures are harmless and disposable.

Product tests should prove:

- Simulate never instantiates runner transport;
- Execute requires a compatible profile, explicit scope, and approval;
- AI Off performs no provider call;
- Assist persists every actionable v2 proposal and pauses before mutation;
- Auto can apply a policy-valid Simulate choice for the exact next edge, compatible behavior, bounded primitive parameters, or one retry;
- Execute proposal acceptance never reuses the original approval and instead performs a fresh-workspace full replay behind a fresh exact approval;
- any action choice is already registered and enabled by the exact profile;
- the model cannot select a cross-outcome edge, invent an action/command, or expand graph/profile/scope/tier/policy authority;
- control blocks and counterfactuals remain distinct;
- receipt cleanup reconciles to zero in disposable runs;
- replay lineage and comparison deltas are correct;
- bundle/event tampering is detected;
- UI/CLI/API share the service boundary;
- demo artifacts are sanitized.

## Local storage and migrations

`RunStore` owns immutable-ish per-run JSON bundles and hash-chained events. `ProductStore` owns SQLite product metadata: schema migrations, secret-safe settings, content-addressed scenario versions, typed resources, approval primitives, background-job state, and a run index.

At service startup BlueFire:

1. recovers unfinalized run bundles as interrupted;
2. migrates/opens `bluefire-product.sqlite3` under the runs root unless explicitly configured;
3. marks in-flight product jobs interrupted;
4. idempotently seeds scenarios, actions, profiles, providers, six collector records, research sources, and detection backends;
5. backfills/indexes run summaries.

Migration changes must be additive and transactional where possible. Add tests for a fresh database, restart recovery, idempotent seeding, prior-schema upgrade, and corrupt/invalid data handling. Never persist resolved secret values.

## Package and installed-wheel smoke

Build the frontend first when its source changed, then build Python artifacts:

```bash
cd frontend && pnpm build && cd ..
python -m build
```

Inspect wheel contents: only the `bluefire` package, catalog/data YAML, and built UI assets should ship. Then install the wheel into a fresh temporary virtual environment and smoke:

```bash
bluefire --help
bluefire --runs-dir path/to/temp-runs scenario validate --scenario-id scenario.restricted.persistence-canary.v1
bluefire --runs-dir path/to/temp-runs scenario run --scenario-id scenario.restricted.persistence-canary.v1 --mode simulate --autonomy off
bluefire --runs-dir path/to/temp-runs ui --host 127.0.0.1 --port 8765
```

The runner is a separate release artifact and must be built/tested independently.

Native-wheel CI additionally runs `tools/verify_packaged_runner.py inspect` and then copies the verifier outside the checkout for installed-wheel `smoke`. The smoke report includes a sanitized `disposable_workspace` proof showing the temporary work root is outside the checkout, source runner overrides are absent, sandbox scopes remain inside the disposable root, and cleanup leaves zero retained files. The proof deliberately omits absolute paths.

## Contract-change workflow

When adding or changing a behavior/action:

1. update the versioned contract rather than silently changing semantics;
2. preserve logical/executor separation;
3. update registry and negative tests;
4. update the explicit adapter and simulation;
5. update profiles/scenarios and cleanup paths;
6. verify Rust inventory parity;
7. update API/UI fixtures and public docs;
8. document migration and compatibility.

See [Action SDK](ACTION_SDK.md) and [Behavior authoring](BEHAVIOR_AUTHORING.md).

## Security and privacy before a commit

1. Inspect `git status --short` and the full diff.
2. Stage only explicit reviewed paths; never use `git add .` or `git add -A`.
3. Inspect the complete staged diff.
4. Run secret/privacy scans and `git diff --cached --check`.
5. Ensure no virtual environment, dependency tree, cache, run bundle, SQLite database, log, local sandbox, external research cache, private endpoint, real telemetry, prompt, local absolute path, username, or machine name is staged.
6. Use a concise public commit message.

Do not push, merge, rewrite history, publish packages/releases, or change remotes without explicit authorization.

## Release checklist

- Python, Rust, frontend, browser, security, package, installed-wheel, API, CLI, and opt-in disposable E2E checks pass.
- Version is consistent across Python, Rust, and frontend metadata.
- Eight packaged/check-out scenarios and twenty action descriptors remain in parity.
- Research pins/licenses and optional dependency versions are current and reviewed.
- Generated screenshots use real UI with sanitized seeded data.
- README/docs match shipped behavior and limitations.
- Final tracked tree contains no private residue or runtime artifacts.
