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
python -m build

cargo fmt --manifest-path runner/Cargo.toml -- --check
cargo clippy --manifest-path runner/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path runner/Cargo.toml --all
~~~

Tests must use temporary sandbox roots and loopback only. They must not require
credentials, external targets, host security-control changes, elevated
privileges, or persistent host modifications.

## Design rules

- Python owns contracts, planning, policy, evidence, replay, comparison, API,
  and UI. It does not implement behavior effects.
- Real effects require a versioned, registered Rust action with a strict schema.
- Never add a generic command, script, payload, binary, or destination field.
- Simulate output stays synthetic; runner self-report stays executed; only an
  independent collector can claim observed evidence.
- New scenario edges must preserve typed artifact compatibility and explicit
  success, partial, blocked, and failed routing.
- New detection candidates must report their real lifecycle state and known
  limitations.
- Plugins remain declarative until a separately reviewed installation and trust
  mechanism exists.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component ownership and
[docs/MIGRATION.md](docs/MIGRATION.md) for translating older concepts.

## Change quality

Keep commits small and coherent. Add tests for boundary and failure behavior,
avoid generated artifacts, and update public documentation when a shipped
contract changes. Contributions are licensed under the [MIT License](LICENSE).
