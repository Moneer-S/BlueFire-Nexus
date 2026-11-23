# Contributing to BlueFire Nexus

Thank you for contributing. Security-sensitive reports belong in the private
process described in [SECURITY.md](SECURITY.md), not a public issue. All
participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). The rules
for working in this repository are in [AGENTS.md](AGENTS.md).

## Local setup

Python 3.10 or newer is required. A change to the runner also needs the Rust
toolchain that `rust-toolchain.toml` pins.

~~~bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
~~~

To only look at the app, Docker is enough: `docker compose up app` starts it
from your checkout and prints its address. [`compose.yaml`](compose.yaml) says
how.

Frontend changes also require pnpm 11.19.0. Optional detection-backend work
uses the pinned pySigma and yara-python versions documented in
[docs/DETECTION_LAB.md](docs/DETECTION_LAB.md).

The default Simulate path needs no Rust runner. Execute development must use an
owned disposable sandbox and the explicit profile, approval, scope, and cleanup
rules documented in [docs/EXECUTION_MODEL.md](docs/EXECUTION_MODEL.md).

## Verification

The checks are few and meant to finish in a few minutes. The `app` workflow
runs these on a pull request that touches the app:

~~~bash
python -m pytest -n auto      # the service: API, command line, runs, detection, comparison

cd frontend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm test                     # logic and quick component tests
pnpm build                    # bluefire/ui must then be unchanged: commit it when it is not
pnpm test:e2e                 # the screens in a browser
~~~

The browser tests need Chromium's system libraries. Where those are missing,
run them in the image the workflow uses, from the repository's root, after
`pnpm install` and `pnpm build:e2e`:

~~~bash
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/work -w /work/frontend \
  mcr.microsoft.com/playwright:v1.62.1-noble npx playwright test
~~~

A pull request that touches `runner/` also runs the runner's tests, in the
`runner` workflow:

~~~bash
cargo test --manifest-path runner/Cargo.toml --all --locked
~~~

The linters are there to run by hand: `python -m ruff check bluefire tests_platform`,
`python -m black --check bluefire tests_platform`, `python -m mypy bluefire`,
`python -m bandit -r bluefire -ll`, and `cargo fmt` and `cargo clippy` for the
runner.

Before you push, scan the files and every commit of your branch for private
paths. The scan needs nothing installed:

~~~bash
python3 .github/scripts/privacy_scan.py
python3 .github/scripts/privacy_scan.py --commits origin/main..HEAD
~~~

Wheel verification is host-specific because every wheel embeds one matching native runner.
Follow [Package and installed-wheel smoke](docs/DEVELOPMENT.md#package-and-installed-wheel-smoke),
which builds and stages the host runner before invoking the wheel backend.

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
- AI Off must make no provider call; Assist records without applying; Auto may
  apply only a registered compatible alternate selected inside the deterministic
  next-node allowlist. Model output never grants policy or execution authority.
- SQLite product-state migrations and seeding must be idempotent and must never
  persist resolved secret values.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for component ownership and
[docs/MIGRATION.md](docs/MIGRATION.md) for translating older concepts. Detailed
workflows live in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md),
[docs/ACTION_SDK.md](docs/ACTION_SDK.md), and
[docs/BEHAVIOR_AUTHORING.md](docs/BEHAVIOR_AUTHORING.md).

## The lab

`lab/` is the engine that runs real attack tests and records what the sensors
saw. Its own checks run in the `lab package` job on Ubuntu 24.04:

~~~bash
python3 -m venv .venv
.venv/bin/pip install -e "lab[dev]"
.venv/bin/ruff check lab
.venv/bin/ruff format --check lab
.venv/bin/pytest --rootdir lab -c lab/pyproject.toml lab/tests
~~~

Attack tests run only in the `lab` workflow, on GitHub-hosted runners. A pull
request that changes `lab/` runs it. The run page shows the results. When a
previous successful run on `main` has an available artifact, the comparison
shows which answers changed.

- A test is a published Atomic Red Team test, pinned by its GUID in
  [`lab/pinned-tests.yaml`](lab/pinned-tests.yaml), with a check that can show
  it did not take effect. The file's header says which tests belong there and
  how each key works.
- A hardening change goes under `defenses` in the same file, with the command
  that puts it in place, the command that removes it, and why a defender would
  deploy it.
- A detection rule of the lab's own is a Sigma rule in
  [`lab/rules/linux`](lab/rules/linux). It counts only once a run accepts it:
  see [the lab's README](lab/README.md#detection-rules-of-the-labs-own).

## Change quality

Keep commits small and coherent. A test checks behaviour that a user of the app
can observe. Avoid generated artifacts, and update public documentation when a
shipped contract changes. Contributions are licensed under the
[MIT License](LICENSE).
