# Contributing to BlueFire Nexus

Thank you for contributing. Security-sensitive reports belong in the private
process described in [SECURITY.md](SECURITY.md), not a public issue. All
participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Local setup

Python 3.10 or newer and a current stable Rust toolchain are required for the
complete verification suite.

~~~bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
~~~

Frontend changes also require pnpm 11.19.0. Optional detection-backend work
uses the pinned pySigma and yara-python versions documented in
[docs/DETECTION_LAB.md](docs/DETECTION_LAB.md).

The default Simulate path needs no Rust runner. Execute development must use an
owned disposable sandbox and the explicit profile, approval, scope, and cleanup
rules documented in [docs/EXECUTION_MODEL.md](docs/EXECUTION_MODEL.md).

## Verification

~~~bash
python -m compileall -q bluefire tests_platform
python -m pytest
python -m ruff check bluefire tests_platform
python -m black --check bluefire tests_platform
python -m mypy bluefire
python -m bandit -r bluefire -ll
python -m pip_audit
pre-commit run --all-files
python -m build --sdist

cargo fmt --manifest-path runner/Cargo.toml -- --check
cargo clippy --manifest-path runner/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path runner/Cargo.toml --all

cd frontend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm test:e2e
~~~

Wheel verification is host-specific because every wheel embeds one matching native runner.
Follow [Package and installed-wheel smoke](docs/DEVELOPMENT.md#package-and-installed-wheel-smoke),
which builds and stages the host runner before invoking the wheel backend.

Tests must use temporary sandbox roots and loopback only. They must not require
credentials, external targets, host security-control changes, elevated
privileges, or persistent host modifications.

## Design rules

- Python owns contracts, planning, policy, evidence, replay, comparison, API,
  and UI. Legacy exact-plan effects remain implemented by the native runner.
- Exact-plan scenario effects require a versioned, registered Rust action with
  a strict schema. A separately reviewed external-engine experiment may instead
  invoke one exact pinned engine through its supported worker interface only
  after its exact runtime candidate and independently effective network,
  process, and container custody have qualified. That path must bind an
  approved disposable environment, immutable scope and budgets, independently
  supervise the worker and its descendants, and import only bounded, hashed
  artifacts. Review alone is not execution qualification, and this path does
  not add a generic host executor.
- Never add a caller-selected command, script, payload, binary, mount, tool
  server, credential, or destination field. Engine installation and admission
  are reviewed separately from experiment execution.
- Simulate output stays synthetic; runner self-report stays executed; only an
  independent collector can claim observed evidence.
- New scenario edges must preserve typed artifact compatibility and explicit
  success, partial, blocked, and failed routing.
- New detection candidates must report their real lifecycle state and known
  limitations.
- Plugins remain declarative until a separately reviewed installation and trust
  mechanism exists.
- AI Off must make no provider call. The legacy exact-plan Assist and Auto paths
  retain their deterministic next-node and reviewed-method limits. An admitted
  objective-level experiment may create a new attempt or continuation from
  applicable saved findings, but only within its versioned capability
  delegation. Model output never grants target ownership, scope, credentials,
  policy, defensive-change authority, executable admission, or spending.
- SQLite product-state migrations and seeding must be idempotent and must never
  persist resolved secret values.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component ownership and
[docs/MIGRATION.md](docs/MIGRATION.md) for translating older concepts. Detailed
workflows live in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md),
[docs/ACTION_SDK.md](docs/ACTION_SDK.md), and
[docs/BEHAVIOR_AUTHORING.md](docs/BEHAVIOR_AUTHORING.md).

## Change quality

Keep commits small and coherent. Add tests for boundary and failure behavior,
avoid generated artifacts, and update public documentation when a shipped
contract changes. Contributions are licensed under the [MIT License](LICENSE).
