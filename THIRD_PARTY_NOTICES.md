# Third-party notices and source intake

BlueFire Nexus records third-party source provenance before any public content is imported, adapted, or integrated through an external adapter. A source record is not proof that remote bytes were fetched, vendored, redistributed, or executed.

Current built-in records are stored in `bluefire/data/research_sources.yaml` and exposed through Research Sources:

| Source | Classification | Content handling | Notice |
|---|---|---|---|
| MITRE ATT&CK Enterprise STIX data | `metadata_import` | External reference only; selected behavior metadata carries attribution | ATT&CK and MITRE marks are used for attribution and do not imply endorsement. |
| Sigma specification | `reference_only` | Metadata only | Used as a format/semantics reference. |
| pySigma | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded parser-validation integration when available. |
| pySigma SQLite backend | `external_adapter` | Separately installed optional package; no source vendored | LGPL-3.0-only converter pinned for reviewed adapter integration. Package presence is not evidence that conversion or query execution occurred. |
| yara-python | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded compiler integration when available. |
| Atomic Red Team | `reference_only` | Metadata only | Used as a comparative behavior/test-structure reference; external tests are not copied or executed. |

Before any `compatible_code_adaptation`, perform file-level license review, preserve attribution and notices, isolate copied code paths, and record modifications in the source metadata.

The optional detection extra pins `pysigma-backend-sqlite==1.2.2`. SigmaHQ's tag `v1.2.2`
resolves to commit `cfc0a2dd75470f73e2e375c3e58aecc21a33fbc6`. PyPI's Trusted Publishing
attestation records wheel SHA-256
`db553c8af13aa4290a5769f4e3754ecd8970a33254b8d00a65df48039cdc0e76` and source-distribution
SHA-256 `3970518045192d5aeb93f444221dce4661388e7b5b1aab289568930dacbfd247`.
<!-- pragma: allowlist secret -- public source and package digests -->
These public identities document intake; they do not prove which artifact an installer resolved,
that the package was imported, or that BlueFire executed a generated query. The unmodified package
is LGPL-3.0-only. Redistributors remain responsible for preserving its license materials and any
corresponding-source rights required by that license.

## Runtime and build components added for executable providers

| Component | Use | License and notice |
|---|---|---|
| PyNaCl `>=1.5,<2` | Maintained Ed25519 public-key validation for signed action packages | Apache-2.0. PyNaCl wheels may include libsodium, which is ISC licensed; the bundled notice identifies Frank Denis as copyright holder. |
| wasmi `=1.1.0` | No-WASI WebAssembly interpreter compiled into the native runner | Dual licensed MIT or Apache-2.0. BlueFire enables only `std` and `extra-checks`; it does not enable WASI. |
| wat `=1.239.0` | Development-only compilation of provider test fixtures | Apache-2.0 with LLVM exception, Apache-2.0, or MIT. It is not a production runner dependency. |

These packages are obtained from their normal Python or Rust package registries; their source is not copied into this repository. Redistributors must preserve the license texts shipped with the resolved packages and any compiled native-runner distribution.
