# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A canonical `bluefire` control plane with strict behavior, action, graph,
  evidence, detection, replay, comparison, plugin, and configuration contracts.
- A modular Rust runner with eight reviewed sandbox actions, independent policy
  enforcement, structured results, bounded effects, and receipt-based cleanup.
- A loopback-only experiment console for graph editing, preflight, run review,
  replay, and comparison.

### Changed

- The product exposes exactly two run modes: Simulate and Execute. AI planning
  remains an independent option.
- Real effects now cross a single Python-to-Rust action boundary; Python no
  longer implements behavior effects.
- Scenario and catalog identities are neutral and versioned.

### Removed

- Superseded Python execution handlers, compatibility modes, identity-specific
  wrappers, stale scenarios, and generated report snapshots.
