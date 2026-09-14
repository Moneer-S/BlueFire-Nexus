# Plugin manifest SDK

BlueFire 0.1.x supports **declarative plugin manifests only**. Parsing a manifest does not install a package, import Python, load a dynamic library, discover an entry point, or make an action executable.

This narrow boundary lets the product inventory proposed third-party content without treating metadata as trusted code. The local API can save, activate, deactivate, and inventory these manifests, but activation registers metadata only: `executable_loading` and `dynamic_actions` always remain `false`.

## Manifest schema

```yaml
schema_version: bluefire.plugin.v1
id: plugin.example.catalog.v1
name: Example reviewed catalog extension
version: 1.0.0
enabled: false
trust: reviewed
integrity:
  algorithm: sha256
  digest: 0000000000000000000000000000000000000000000000000000000000000000
license: MIT
provenance:
  source: Example project
  reference: https://example.invalid/release/v1.0.0
  license: MIT
  derived: false
  notes: Replace with a real public source and reviewed digest.
permissions: [catalog.read]
capabilities: [sandbox.discovery]
behavior_ids: [example.discovery.v1]
action_ids: []
```

Use a real lowercase SHA-256 digest; the zeros above are a shape example, not a valid reviewed artifact identity.

## Fields

| Field | Rule |
|---|---|
| `schema_version` | Exactly `bluefire.plugin.v1` |
| `id` | Lowercase stable ID ending in `.vN` |
| `name` | Human-readable non-empty name |
| `version` | Semantic version |
| `enabled` | Declarative intent only; does not load code |
| `trust` | `untrusted`, `reviewed`, or `trusted` |
| `integrity` | `sha256` plus 64 lowercase hex characters |
| `license` | Reviewed license identifier/text |
| `provenance` | Source, reference, license, derivation, notes |
| `permissions` | Namespaced declared permissions |
| `capabilities` | Namespaced declared capabilities |
| `behavior_ids` | Stable behavior IDs the package claims to contribute |
| `action_ids` | Stable action IDs the package claims to contribute |

Unknown fields—including `python_entry_point`—are rejected. The loader validates the integrity field's shape but does not fetch bytes, recompute the digest, or prove publisher identity.

## Local manifest lifecycle

Save a manifest at `POST /api/v1/resources/plugins/{manifest_id}`. The JSON body must contain exactly one `document` member whose value is the full strict manifest shown above; its `id` must match the route. A caller-supplied `status` is rejected. BlueFire derives `disabled`, `review_required`, or `ready` from the validated manifest and preserves `inactive` until a later explicit activation.

Activate or deactivate with an exact empty object:

```text
POST /api/v1/resources/plugins/{manifest_id}/activate
POST /api/v1/resources/plugins/{manifest_id}/deactivate
{}
```

Activation requires `enabled: true`, `trust: reviewed` or `trusted`, strict provenance, and a non-placeholder SHA-256 integrity identity. These checks establish local review metadata only; BlueFire does not fetch or hash plugin bytes. Active state persists across restart. Deactivation persists `inactive` state.

`GET /api/v1/resources/plugins` returns the saved resources plus a sanitized inventory and health summary. Every lifecycle response explicitly reports metadata-only registration, with executable loading, dynamic actions, and Python entry points disabled.

## Trust meanings

- `untrusted`: discovered metadata has not completed review.
- `reviewed`: source, scope, license, provenance, and integrity have been reviewed for a specific version.
- `trusted`: local policy has elevated the reviewed package for a defined deployment.

These are policy labels, not cryptographic attestations. A digest proves equality to expected bytes only after a separate installer verifies it; it does not identify the publisher.

## Current inventory command

```bash
bluefire plugins inventory
```

The CLI command reports its static declarative trust boundary. The managed API inventory additionally reports locally saved manifest metadata. Neither inventory discovers packages or claims that plugin code is installed.

## Integrating reviewed third-party content

Declarative plugins remain metadata-only. Executable action-provider packages use a separate signed contract described in [Action SDK](ACTION_SDK.md); making that path available does not make a plugin manifest executable.

For material such as a selected Atomic Red Team test, do not blindly execute an upstream script. The safe integration path is:

1. pin a tag/commit and retrieval date outside the repository;
2. review the upstream license and every executable statement;
3. identify the neutral behavior, prerequisites, parameters, observables, tier, and cleanup;
4. transcribe only the needed semantics or fixture under the permitted license with attribution;
5. implement a narrow compiled Rust action, reuse an existing registered action, or package the reviewed semantics as a signed, content-addressed no-host-import WASM provider with fixed ABI exports and declared limits;
6. add an explicit logical binding—never pass the upstream command/script through;
7. require explicit plugin/action enablement in a runner profile;
8. add structural and disposable dynamic tests appropriate to the risk;
9. preserve imported/adapted/inspired/comparative provenance.

## What is not shipped

- automatic plugin/package discovery, dependency fetching, or installation;
- executable authority from declarative plugin metadata;
- a general-purpose third-party script, native-library, host-import, or command runtime;
- Python entry points;
- remote marketplace or update service;
- automatic Atomic Red Team or public-rule execution.

An executable extension must be either reviewed first-party compiled source or an explicitly trusted and activated signed provider package that satisfies the bounded runtime contract in [Action SDK](ACTION_SDK.md). Arbitrary executable plugins remain unsupported.
