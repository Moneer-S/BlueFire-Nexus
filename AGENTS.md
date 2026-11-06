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

- **Draft pull request:** Linux only. Static checks run first, in a few minutes;
  Python tests on Ubuntu, the frontend, Rust and the Linux wheel with its
  installed-browser checks start only when they pass.
- **Ready for review, push to `main`, or a manual run:** every platform. That
  adds Python on macOS, the Windows test partitions and the Windows and macOS
  wheels. Marking a draft ready starts this run.
- `tools/ci_plan.py` holds the platform matrices.

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
