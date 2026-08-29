# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A canonical `bluefire` control plane with strict behavior, action, graph,
  evidence, detection, replay, comparison, plugin, and configuration contracts.
- A modular Rust runner with nineteen reviewed endpoint/sandbox actions, a
  versioned action SDK inventory, independent policy enforcement, structured
  partial results, bounded effects, and receipt-based cleanup.
- Bounded cross-platform system/process discovery, recursive sandbox discovery,
  and deterministic ustar archive actions alongside the existing fixture,
  staging, loopback, export, and cleanup pack.
- Eight sanitized scenarios for the canonical sandbox chain, Linux/container and
  Windows-oriented validation, detection regression, bounded AI adaptation, a
  dedicated restricted persistence-detection canary, and representative/deep endpoint labs.
- AI autonomy levels `off`, `assist`, and `auto`; a deterministic offline
  provider; and an OpenAI-compatible Responses provider with strict structured
  output, redaction, bounds, health metadata, retry, and fallback.
- A bounded natural-language objective-to-graph endpoint that returns an unsaved,
  deterministically normalized scenario containing only registered behavior
  contracts and primitive typed parameters.
- A bounded v2 runtime proposal loop for the exact observed next edge,
  compatible behavior substitution, typed primitive parameter changes,
  exact-profile registered action selection, and one bounded retry. Assist
  pauses for durable review; Auto applies only policy-valid Simulate choices;
  every Execute mutation receives fresh review, workspace replay, and approval.
- A migrated SQLite product store for scenario versions, secret-safe settings,
  typed resources, approvals/jobs, restart recovery, and indexed run summaries.
- Filesystem and disposable JSONL fixture collectors with explicit evidence-gap
  records, plus honest readiness descriptors for optional audit/SIEM adapters.
- Pinned public-research provenance for MITRE ATT&CK, Sigma, pySigma, and
  yara-python, including license and relationship metadata.
- pySigma parsing, YARA compilation/bounded fixture exercise, SPL structural
  checks, predicted-versus-observed field drift, and public-baseline deltas.
- A React/TypeScript loopback workspace with scenario graph building, run
  preflight/review, comparison, catalogs, Detection Lab, AI Planner, settings,
  research, runner/profile, and help surfaces.
- Complete operator/developer documentation covering threat model, runner
  deployment/profiles, action/plugin SDKs, behavior authoring, AI, detections,
  evidence, replay/compare, API, development, and responsible use.

### Changed

- The product exposes exactly two run modes: Simulate and Execute. AI autonomy
  remains an independent axis and cannot widen execution authority.
- Real effects now cross a single Python-to-Rust action boundary; Python no
  longer implements behavior effects.
- Scenario and catalog identities are neutral and versioned.
- Execute now requires explicit operator target scope in addition to a
  compatible profile and request-bound approval.
- Evidence graphs reject cross-run parents; observers and collectors enforce
  time/size/count bounds and preserve unavailable evidence as `unknown`.

### Removed

- Superseded Python execution handlers, compatibility modes, identity-specific
  wrappers, stale scenarios, and generated report snapshots.
