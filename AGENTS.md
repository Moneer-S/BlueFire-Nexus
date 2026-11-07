# Working in this repository

These notes apply to people and to coding agents. [CONTRIBUTING.md](CONTRIBUTING.md)
has setup and the full verification list.

## Before you push

1. Run `python tools/quick_check.py`. It lints, checks formatting, type-checks
   for Linux, Windows and macOS, and checks frontend types and lint in about two
   minutes. Fix everything it reports.
2. Run the tests for the area you changed, for example
   `python -m pytest tests_platform/test_service.py` or
   `cd frontend && pnpm exec vitest run tests/builder-routes.test.tsx`.
3. Push a batch of related commits, not one commit at a time. Every push to a
   pull request cancels the CI run that was still going.

## How CI runs

Every run covers Linux, macOS and Windows, because agents cannot check macOS or
Windows on their own machines.

- Static checks run first, in about two minutes. The Python, frontend, Rust and
  wheel jobs start only when they pass.
- **Draft pull request:** Python 3.10 on Linux and Python 3.12 on Linux, macOS
  and every Windows partition, plus all four native wheels with their installed
  checks.
- **Ready for review, push to `main`, or a manual run:** both Python versions on
  every platform.
- `tools/ci_plan.py` holds the platform matrices.

## Reading a CI result

Read the end of the **Result digest** job's log. It lists every job that did not
pass, the step that failed, and the failing tests, lint, format or type errors,
or installed-check stage from that job's log (see `tools/ci_digest.py`). Open a
job's own log only when the digest line is not enough.

## When a test times out only in CI

Tests that wait for a real background job use short guards such as
`controller.wait(job_id, timeout=3)`. CI multiplies those guards by
`BLUEFIRE_TEST_WAIT_SCALE` (4) because hosted runners are slow; see
`tests_platform/conftest.py`. If a wait still times out, the job most likely
does not finish at all. Find out why. Do not raise that one timeout, add
another diagnostic wrapper, or retry until green.

Never skip, disable or loosen an assertion to make CI pass.

## Installed-browser checks

`frontend/tests/installed/*.mjs` drive the real installed product and encode
product contracts: for example, every saved route stays visibly drawn, and a
step card's method qualifier keeps its parentheses. When a UI change breaks
one, decide whether the UI or the contract is wrong before editing either.
