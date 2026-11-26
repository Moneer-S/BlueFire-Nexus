# Working in this repository

These notes apply to everyone who works here.

## What this is

BlueFire Nexus is a range you can watch. A small real network runs, an attacker
works through it, and the app shows each step next to what the defenses saw and
what they did about it.

The app is the product: `bluefire/`, `frontend/` and `runner/`. Build on it.
`lab/` is the engine that runs real attack tests and records what the sensors
saw. New work puts real runs under the app's screens and makes those screens
better. A screen or a feature that is not used yet is left alone, not removed.

## Rules

1. **A result is real or it is labelled.** Real means the test ran in a range,
   a sensor there produced the telemetry, and a rule engine evaluated it.
   Fixtures, mocks and made-up data help development, and they are never
   presented as results. A recorded run judged again by another rule set is a
   result, and it says that the rules ran after the run.
2. **Attacks run only inside a range.** A range is a set of containers that the
   project starts on networks with no route out, or a GitHub-hosted runner
   inside this repository's own workflows. Nothing attacks a developer machine
   itself or anything a range did not create.
3. **Use published tests and tools, pinned.** Attack steps come from maintained
   public projects such as Atomic Red Team, pinned to a commit or version and
   recorded in `THIRD_PARTY_NOTICES.md`. Do not write new attack techniques.
   The path that strings published steps together is ours to write, and so are
   a lab host's planted weaknesses, detection rules, responses, hardening
   changes, parsers and reports. A planted weakness is a weak setting, such as
   a guessable password or a key left readable, or a flaw of a textbook kind in
   the lab's own application: never real software with a known flaw. A
   published tool opens it.
4. **An AI attack harness is a published tool with stricter handling.** It is
   taken as published at a pinned commit, with nothing changed in its code,
   prompts or tools. It runs only inside a sealed range on a GitHub-hosted
   runner, in a job whose only trigger is a manual one, which holds no key or
   secret and whose token reads the repository and nothing else. Its model is a
   general open model that runs inside the same range. It is never fetched to a
   developer machine and never copied into this repository. Nothing is tuned so
   that it gets further: a run that stalls is reported as that.
5. **This repository is public.** Commits, pull requests, issues, comments, CI
   logs and CI artifacts can be read by anyone. Keep out secrets and details of
   any developer machine: user names, host names, local paths, addresses.
   Pictures and recordings that are published come from CI runners.
6. **Write for a stranger.** Commit messages, pull request text and documents
   say what the change does and how it was checked. Plain messages only: no
   trailers or footers, no status notes or to-do lists. Name a branch after the
   change, for example `range/first-range`.
7. **Borrow before you build.** Ranges, sensors, rule sets and engines exist as
   open projects. Our code joins them to the app. Keep each one's licence:
   fetch it at a pinned commit, credit it, and copy it into this repository
   only where its licence allows.
8. **How it looks matters.** A change that makes a screen or the README worse
   to look at is a regression. A first screen or a first paragraph is for
   someone who has just arrived: it says what this is and what happened, in
   plain words. Counts, run numbers and method are one click away.

## Pull requests

- Open a pull request as a draft and keep it a draft while you work.
- Mark it ready once, when it is finished and CI is green. An automated reviewer
  reads the pull request at that moment. Do not switch back and forth between
  draft and ready.
- Treat each review finding as a claim to check. Fix real defects. Where you
  disagree, reply in a sentence or two with the reason.
- One idea per pull request. The description says what the change does, what it
  could break if anything, and how it was checked: the command or run, and its
  outcome.
- Push a batch of related commits, not one commit at a time. Every push to a
  pull request cancels the CI run that was still going.

## Checks

- The scan for private paths and the secret scans run on every pull request.
  Keep them running when other checks change.
- Checks are few and fast. A test checks behaviour that a user of the app can
  observe. Fix or delete a test that still passes when that behaviour breaks,
  or that fails when only the internals change.
- When the same mistake happens twice, make it impossible: by design first, then
  a type, then a lint or CI check whose error names the fix, then a test. Add a
  check only for a mistake that really happened, and show that it fails on that
  mistake.
