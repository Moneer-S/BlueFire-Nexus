# Third-party notices and source intake

BlueFire Nexus records third-party source provenance before any public content is imported, adapted, or integrated through an external adapter. A source record is not proof that remote bytes were fetched, vendored, redistributed, or executed.

Current built-in records are stored in `bluefire/data/research_sources.yaml` and exposed through Research Sources:

| Source | Classification | Content handling | Notice |
|---|---|---|---|
| MITRE ATT&CK® Enterprise T1082 STIX metadata | `metadata_import` | One exact declarative record and its complete pinned license are vendored; only an allowlisted neutral projection may enter generated runtime records | The custom `LicenseRef-MITRE-ATTACK-2026`, required notice, and trademark restrictions apply; use does not imply MITRE endorsement. |
| Sigma specification | `reference_only` | Metadata only | Used as a format/semantics reference. |
| pySigma | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded parser-validation integration when available. |
| pySigma SQLite backend | `external_adapter` | Separately installed optional package; no source vendored | LGPL-3.0-only converter pinned for reviewed adapter integration. Package presence is not evidence that conversion or query execution occurred. |
| yara-python | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded compiler integration when available. |
| Atomic Red Team | `reference_only` | Metadata only | Used as a comparative behavior/test-structure reference; external tests are not copied or executed. |

Before any `compatible_code_adaptation`, perform file-level license review, preserve attribution and notices, isolate copied code paths, and record modifications in the source metadata.

## MITRE ATT&CK® Enterprise T1082 metadata

BlueFire vendors one reviewed declarative STIX 2.0 bundle for T1082, System Information
Discovery, from `mitre/cti` release `ATT&CK-v19.2`. The signed annotated tag points to
commit `8543c5b05bd9bbcace9fc37f30bba96b675b6f33`; the exact source is
`bluefire/data/mitre_attack_t1082_v19_2.json` (6,617 bytes, SHA-256
`dd2e50ceef844302a690a1debac8336864e93ebd19da526eefac3072f5ee9a02`, Git blob
`456248b9947555603bfe2981ae8d931cb2ba88a7`). No other ATT&CK object or corpus is
vendored.

This metadata is distributed under the custom `LicenseRef-MITRE-ATTACK-2026`, not an
SPDX-listed permissive software license. The complete pinned license is shipped unchanged at
`bluefire/data/mitre_attack_v19_2_LICENSE.txt` (2,311 bytes, SHA-256
`4de9222b0d5bc69b758f9cf0afdaea48fdcbfe7d33c7481973a6aa07d6cbea9d`, Git blob
`ecac4fdc83b412256b233fc25d5f3502f2eaa07a`). Its required copyright designation is:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

BlueFire deterministically projects only the technique identity, name, version, active status,
timestamps, and primary MITRE reference. Descriptions, citations, procedures, command examples,
and unrelated references are discarded. The projection and any signed package are
content-addressed in acceptance/runtime state and are not checked in as pre-generated artifacts.
Source intake executes no upstream code, install scripts, payloads, binaries, containers, or test
harnesses. The resulting action invokes BlueFire's independently implemented and compiled
`endpoint.discovery.windows-version.v1` operation. That Windows-only operation uses BlueFire's
fixed compiled `RtlGetVersion` boundary and returns only major, minor, and build fields; the
imported metadata supplies no executable content. ATT&CK is not used in a BlueFire product or logo name, and no MITRE affiliation,
sponsorship, or endorsement is implied.

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

## Release dependency rights inventory

The release rights review dated 2026-08-30 is recorded in
`bluefire/data/release_rights_policy.json`. The offline verifier in
`bluefire/release_rights_audit.py` compares that reviewed record with the Python manifests and
locked wheel inventory, the production closure of `frontend/pnpm-lock.yaml`, the complete
`runner/Cargo.lock`, and every bundled or generated asset. An added, removed, or changed
dependency or asset is not silently accepted: it requires an updated classification. A nonempty
`unresolved_items` list fails the review.

The base Python artifact declares PyYAML (MIT), cryptography (Apache-2.0 or BSD-3-Clause), and
PyNaCl (Apache-2.0). Its locked Linux release set additionally contains cffi (MIT-0) and pycparser
(BSD-3-Clause). The exact five wheel versions and SHA-256 values are part of the committed
inventory. PyNaCl wheels can incorporate libsodium (ISC); that nested notice must be retained
from the resolved wheel.

The packaged web application has 69 packages in its production lock closure: 58 MIT packages;
the ISC-licensed D3 modules `d3-color`, `d3-dispatch`, `d3-drag`, `d3-interpolate`,
`d3-selection`, `d3-timer`, `d3-transition`, and `d3-zoom`; ISC-licensed `lucide-react`;
BSD-3-Clause `d3-ease`; and 0BSD `tslib`. The exact name/version inventory is in the policy.
The remaining entries in the 391-package pnpm lock are build, test, platform, or development
entries and are not represented as shipped browser code by this review.

The native runner review classifies all 48 external crates in `Cargo.lock`; the conservative
release graph contains 42 of them. Observed terms are MIT, Apache-2.0, BSD-3-Clause, Zlib,
Unlicense, Unicode-3.0, and the LLVM exception, alone or in the expressions recorded in the
policy. `wat` and its exclusive closure are test-only. The native runner is statically generated
from the reviewed Rust graph, so binary redistributors must carry the upstream notices and
license choices applicable to that build.

The `detections` Python extra is environment-dependent and is not embedded in the base wheel.
Its direct packages are pySigma 1.5.0 (LGPL-2.1-only), pySigma SQLite backend 1.2.2
(LGPL-3.0-only), and yara-python 4.5.4 (Apache-2.0). A distributor who bundles that optional
environment must perform a fresh transitive inventory and satisfy the corresponding LGPL and
other upstream obligations; this base-release review does not authorize such a bundle.

## Release license decision

BlueFire Nexus remains MIT licensed. The repository does not contain contributor assignments,
a complete copyright ownership record, or equivalent evidence that would authorize relicensing
all project-authored history as AGPL-3.0-only with separate commercial licensing. Therefore this
review does not perform or recommend that relicense. It preserves the existing MIT license and
history, while continuing to apply the separate MITRE terms to the pinned declarative metadata.
