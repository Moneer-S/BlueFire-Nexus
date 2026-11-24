# Third-party notices and source intake

## Inter web font

The packaged interface includes `InterVariable.woff2` from Inter 4.1, released by
the Inter Project at `https://github.com/rsms/inter/releases/tag/v4.1`. The font is
licensed under the SIL Open Font License 1.1; the complete license is included as
`bluefire/ui/fonts/OFL.txt` in packaged distributions. The upstream WOFF2 file has
SHA-256 `693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3`.
Inter is a trademark of Rasmus Andersson. BlueFire does not imply endorsement.

The single replay page, `bluefire/ui/replay.html`, is meant to be passed around and opened on
its own, so it embeds `InterVariable.woff2` and the React, react-dom and scheduler scripts
(`react@19.2.8`, `react-dom@19.2.8`, `scheduler@0.27.0`; MIT License, Copyright (c) Meta
Platforms, Inc. and affiliates) in the one file, and carries their notices, with the MIT
permission text, the Inter copyright line and the whole SIL Open Font License, in a comment in
its head. The build puts the page together with
`vite-plugin-singlefile@2.3.4` (MIT License), a development dependency whose code is not in the
page.

BlueFire Nexus records third-party source provenance before any public content is imported, adapted, or integrated through an external adapter. A source record is not proof that remote bytes were fetched, vendored, redistributed, or executed.

Current built-in records are stored in `bluefire/data/research_sources.yaml` and exposed through Research Sources:

| Source | Classification | Content handling | Notice |
|---|---|---|---|
| MITRE ATT&CK® Enterprise T1082 STIX metadata | `metadata_import` | One exact declarative record and its complete pinned license are vendored; only an allowlisted neutral projection may enter generated runtime records | The custom `LicenseRef-MITRE-ATTACK-2026`, required notice, and trademark restrictions apply; use does not imply MITRE endorsement. |
| Sigma specification | `reference_only` | Metadata only | Used as a format/semantics reference. |
| pySigma | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded parser-validation integration when available. |
| pySigma SQLite backend | `external_adapter` | Separately installed optional package; no source vendored | LGPL-3.0-only converter pinned for reviewed adapter integration. Package presence is not evidence that conversion or query execution occurred. |
| yara-python | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded compiler integration when available. |
| Atomic Red Team general snapshot | `reference_only` | Metadata only | Historical comparative behavior/test-structure reference; this record does not import the corpus. |
| Atomic Red Team single-file gzip test | `compatible_code_adaptation` | One reviewed method adapted into the fixed Linux gzip adapter | MIT, Copyright (c) 2018 Red Canary, Inc.; complete license preserved at `bluefire/data/atomic_red_team_LICENSE.txt`. |
| Atomic Red Team chmod test | `compatible_code_adaptation` | Reviewed permission-change procedure adapted into a fixed Linux GNU chmod adapter | MIT, Copyright (c) 2018 Red Canary, Inc.; the same complete Atomic license is preserved. |

Before any `compatible_code_adaptation`, perform file-level license review, preserve attribution and notices, isolate copied code paths, and record modifications in the source metadata.

## Atomic gzip collection adapter

The fixed adapter in `runner/src/atomic_gzip.rs` adapts Atomic Red Team T1560.001
test `cde3c2af-3485-49eb-9c1f-0ed60e9cc0af`, reviewed at commit
`388942adbd9641f4dfdcf079d7efe9a75ec0ac43`. The containing YAML is 20,402 bytes,
SHA-256 `681f0727810cc1fa1d2032f818d0cdb5b02dd058ed85416658ee26437773e681`.
Its complete MIT license (Copyright (c) 2018 Red Canary, Inc.) is preserved at
`bluefire/data/atomic_red_team_LICENSE.txt`, 1,078 bytes, SHA-256
`65af6027045d23175366eab50e460ab3ee7790e591cb84cc32c78ac63a4c90e1`.
See `docs/ATOMIC_GZIP.md` for the exact source and modifications: fixed stdin/stdout
gzip invocation replaces the shell, fallback input and caller paths, while
BlueFire owns bounded publication and cleanup. The complete Atomic framework is
not imported. Existing native record/USTAR code remains BlueFire authored.

GNU gzip is an external operating-system dependency licensed GPL-3.0-or-later;
its source and binary are not bundled into BlueFire's wheel. BlueFire's MIT
license does not replace the system utility's terms. The adapter records the
actual selected tool digest, and fails closed if the required utility is missing
or fails its integrity checks. Attribution does not imply endorsement.

## Atomic permission adapter

`runner/src/atomic_chmod.rs` adapts Atomic Red Team T1222.002 test
`34ca1464-de9d-40c6-8c77-690adf36a135` at commit
`6132b92779873cb0d05bef07ba0a480d47eb1cc8`. The reviewed YAML digest is
`76ea316186fe0c7f1d7bdaa9b29c92684eb7f63e28ba14834f50b9bd4fcc2049`.
The preserved Atomic MIT license has the same digest listed above.
The adapter replaces the upstream shell and arbitrary target path with a
reviewed finite numeric mode and one held receipt-owned file descriptor;
it adds protected executable inspection, bounded supervision and cleanup.
See [the method documentation](docs/ATOMIC_CHMOD.md) for scope and limitations.

GNU chmod belongs to [GNU Coreutils](https://github.com/coreutils/coreutils),
licensed GPL-3.0-or-later. It is an optional separately installed system tool;
its source and executable are neither bundled nor redistributed by BlueFire.
BlueFire's MIT license does not replace the utility's terms. No Atomic framework
or general command execution interface is imported.

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

## Runtime and build components for executable providers and POSIX secret protection

| Component | Use | License and notice |
|---|---|---|
| PyNaCl `>=1.5,<2` | Maintained Ed25519 public-key validation for signed action packages and XChaCha20-Poly1305 protection for owner-private POSIX runner-enrollment secrets | Apache-2.0. PyNaCl wheels may include libsodium, which is ISC licensed; the bundled notice identifies Frank Denis as copyright holder. |
| wasmi `=1.1.0` | No-WASI WebAssembly interpreter compiled into the native runner | Dual licensed MIT or Apache-2.0. BlueFire enables only `std` and `extra-checks`; it does not enable WASI. |
| wat `=1.239.0` | Development-only compilation of provider test fixtures | Apache-2.0 with LLVM exception, Apache-2.0, or MIT. It is not a production runner dependency. |
| linux-raw-sys `=0.12.1` | Linux-only generated `statx` ABI in the native cgroup reader; only `general` and `no_std` features | Apache-2.0 with LLVM exception, Apache-2.0, or MIT; BlueFire uses the MIT option. The complete notice is below. |

These packages are obtained from their normal Python or Rust package registries; their source is not copied into this repository. Redistributors must preserve the license texts shipped with the resolved packages and any compiled native-runner distribution.

## Release dependency rights inventory

The release rights inventory, updated for the Linux ABI dependency on 2026-10-01, is recorded in
`bluefire/data/release_rights_policy.json`. The offline verifier in
`bluefire/release_rights_audit.py` compares that reviewed record with the Python manifests and
locked wheel inventory, the production closure of `frontend/pnpm-lock.yaml`, the complete
`runner/Cargo.lock`, and every bundled or generated asset. An added, removed, or changed
dependency or asset is not silently accepted: it requires an updated classification. A nonempty
`unresolved_items` list fails the review.

The base Python artifact declares PyYAML (MIT), cryptography (Apache-2.0 or BSD-3-Clause), and
PyNaCl (Apache-2.0), plus Tomli 2.4.1 (MIT) on Python 3.10. Python 3.11 and newer use the
standard-library TOML parser; unsupported TOML syntax fails the audit. The separate
`bluefire/data/python_runtime_backports.json` pins the reviewed, dependency-free Tomli wheel.
Its locked Python 3.12 Linux release set additionally contains cffi (MIT-0) and pycparser
(BSD-3-Clause). The exact five wheel versions and SHA-256 values are part of the committed
inventory. PyNaCl wheels can incorporate libsodium (ISC); that nested notice must be retained
from the resolved wheel.

### Tomli 2.4.1 notice

MIT License

Copyright (c) 2021 Taneli Hukkinen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

The packaged web application has 71 packages in its production lock closure: 60 MIT packages,
including `@dagrejs/dagre@3.1.1` and its transitive dependency `@dagrejs/graphlib@4.0.5`;
the ISC-licensed D3 modules `d3-color`, `d3-dispatch`, `d3-drag`, `d3-interpolate`,
`d3-selection`, `d3-timer`, `d3-transition`, and `d3-zoom`; ISC-licensed `lucide-react`;
BSD-3-Clause `d3-ease`; and 0BSD `tslib`. The exact name/version inventory is in the policy.
The remaining entries in the 395-package pnpm lock are build, test, platform, or development
entries and are not represented as shipped browser code by this review.

The native runner review classifies all 49 external crates in `Cargo.lock`; the conservative
release graph contains 43 of them, including target-specific production dependencies. Observed terms are MIT, Apache-2.0, BSD-3-Clause, Zlib,
Unlicense, Unicode-3.0, and the LLVM exception, alone or in the expressions recorded in the
policy. `wat` and its exclusive closure are test-only. The native runner is statically generated
from the reviewed Rust graph, so binary redistributors must carry the upstream notices and
license choices applicable to that build.

The `detections` Python extra is environment-dependent and is not embedded in the base wheel.
Its direct packages are pySigma 1.5.0 (LGPL-2.1-only), pySigma SQLite backend 1.2.2
(LGPL-3.0-only), and yara-python 4.5.4 (Apache-2.0). A distributor who bundles that optional
environment must perform a fresh transitive inventory and satisfy the corresponding LGPL and
other upstream obligations; this base-release review does not authorize such a bundle.

## linux-raw-sys 0.12.1 notice

The exact [published source archive](https://static.crates.io/crates/linux-raw-sys/linux-raw-sys-0.12.1.crate)
has SHA-256 `32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53`.
Its package license expression is `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.
The generated bindings are compiled into the Linux runner; upstream source is not
vendored here. The upstream COPYRIGHT file states that copyrights are retained by
the project's contributors. BlueFire selects the MIT option and preserves the
complete upstream LICENSE-MIT text:

> Permission is hereby granted, free of charge, to any
> person obtaining a copy of this software and associated
> documentation files (the "Software"), to deal in the
> Software without restriction, including without
> limitation the rights to use, copy, modify, merge,
> publish, distribute, sublicense, and/or sell copies of
> the Software, and to permit persons to whom the Software
> is furnished to do so, subject to the following
> conditions:
>
> The above copyright notice and this permission notice
> shall be included in all copies or substantial portions
> of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
> ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
> TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
> PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
> SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
> CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
> OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
> IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
> DEALINGS IN THE SOFTWARE.

## Recordings shipped with the app

`bluefire/data/recordings/lab-linux-host.json` (1,135,924 bytes, SHA-256
`d8056aa091bd8ab74bd604d540053d4eb0674741b32ebe76cc7c0cb009dc3595`) is the
recording that this repository's lab workflow wrote on a GitHub-hosted runner in
the run https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45227119895
(artifact `lab-run`), unchanged. It is data, not code: nothing in it is run.

The pair of runs shipped with the app comes from the artifact `lab-pair` of the run
https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45365902367, unchanged:
`bluefire/data/recordings/lab-pair-history-watch-before.json` (its
`before/recording.json`, 1,147,271 bytes, SHA-256
`24a4f0138307091f61330615df74653480107fdb1861b109d24a794cdd652960`),
`bluefire/data/recordings/lab-pair-history-watch-after.json` (its
`after/recording.json`, 1,172,517 bytes, SHA-256
`a4d802c2658780cea95d8a82dec4ba5b51e1fcedea9ee78f5d379930ff129d5e`) and
`bluefire/data/recordings/deltas/lab-pair-history-watch.json` (its `delta.json`,
51,591 bytes, SHA-256
`4470d56391eafa38a005ef003b36526a1afeba989251545725b343de9fc62646`). They are data
too, and what follows holds for them as it does for the example: the same tests at the
same commit, and the same published rules, all of them in the table below.

The run evaluated with two rule sets shipped with the app comes from the artifact
`lab-rules-twice` of the run
https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682, unchanged:
`bluefire/data/recordings/lab-rule-history-truncated-base.json` (its
`before/recording.json`, 1,196,140 bytes, SHA-256
`3be33c4987e190a1329bd74d70984707a4d8473a39b4d827dd1a54c170587118`),
`bluefire/data/recordings/lab-rule-history-truncated-head.json` (its
`after/recording.json`, 1,201,217 bytes, SHA-256
`4802adcbec733a0e96048aa7463dea0d07b401d24c7e4768cc021c15c9e5f828`) and
`bluefire/data/recordings/deltas/lab-rule-history-truncated.json` (its `delta.json`,
59,666 bytes, SHA-256
`51ad6e80f43f6e84f7551878db0903b4856804543fc83beb459ca058ddfd2ddc`). They are data
too, and what follows holds for them as it does for the example: the same tests at the
same commit, and the same published rules, all of them in the table below. These two
recordings also hold the text of the rules written in this repository (`lab/rules/`),
which are this repository's own work under its license.

- It quotes the commands and the printed output of published Atomic Red Team tests
  at commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`, and their names and GUIDs.
  Atomic Red Team is MIT, Copyright (c) 2018 Red Canary, Inc.; the complete license
  is preserved at `bluefire/data/atomic_red_team_LICENSE.txt`.
- It names the published SigmaHQ rules that matched, by title, id and level, at
  commit `552f3fee420ef232a8e5790c4fae591847e32347` (release `r2026-07-01`). The
  rules are under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License);
  no rule text is copied. The recording does not carry each rule's author, so they
  are listed here, as each rule's `author` field gives them at that commit:

| Rule | Id | Author |
|---|---|---|
| ASLR Disabled Via Sysctl or Direct Syscall - Linux | `e497a24e-9345-4a62-9803-b06d7d7cb132` | Milad Cheraghi |
| Bash Interactive Shell | `6104e693-a7d6-4891-86cb-49a258523559` | @d4ns4n_ |
| Binary Padding - Linux | `c52a914f-3d8b-4b2a-bb75-b3991e75f8ba` | Igor Fits, oscd.community |
| Chmod Targeting Sensitive Directories | `6419afd1-3742-47a5-a7e6-b50386cd15f8` | Christopher Peacock @SecurePeacock, SCYTHE @scythe_io |
| Creation Of An User Account | `759d0d51-bc99-4b5e-9add-8f5b2c8e7512` | Marie Euler, Pawel Mazur |
| Crontab Enumeration | `403ed92c-b7ec-4edd-9947-5b535ee12d46` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| Data Compressed | `a3b5e3e9-1b49-4119-8b8e-0344a01f21ee` | Timur Zinniatullin, oscd.community |
| Decode Base64 Encoded Text | `e2072cab-8c9a-459b-b63c-40ae79e27031` | Daniil Yugoslavskiy, oscd.community |
| Disable Or Stop Services | `de25eeb8-3655-4643-ac3a-b662d3f26b6b` | Nasreddine Bencherchali (Nextron Systems) |
| Execution Of Script Located In Potentially Suspicious Directory | `30bcce26-51c5-49f2-99c8-7b59e3af36c7` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| File and Directory Discovery - Linux | `d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72` | Daniil Yugoslavskiy, oscd.community, CheraghiMilad |
| File Deletion | `30aed7b6-d2c1-4eaf-9382-b6bc43e50c57` | Ömer Günal, oscd.community |
| File or Folder Permissions Change | `74c01ace-0152-4094-8ae2-6fd776dd43e5` | Jakob Weinzettl, oscd.community |
| File Time Attribute Change - Linux | `b3cec4e7-6901-4b0d-a02d-8ab2d8eb818b` | Igor Fits, oscd.community |
| Hidden Files and Directories | `d08722cd-3d09-449a-80b4-83ea2d9d4616` | Pawel Mazur |
| History File Deletion | `1182f3b3-e716-4efa-99ab-d2685d04360f` | Florian Roth (Nextron Systems) |
| Linux Base64 Encoded Pipe to Shell | `ba592c6d-6888-43c3-b8c6-689b8fe47337` | pH-T (Nextron Systems) |
| Linux Base64 Encoded Shebang In CLI | `fe2f9663-41cb-47e2-b954-8a228f3b9dff` | Nasreddine Bencherchali (Nextron Systems) |
| Linux Logs Clearing Attempts | `80915f59-9b56-4616-9de0-fd0dea6c12fe` | Ömer Günal, oscd.community |
| Linux Setuid Capability Set on a Binary via Setcap Utility | `ed447910-bc30-4575-a598-3a2e49516a7a` | Luc Génaux |
| Linux Shell Pipe to Shell | `880973f3-9708-491c-a77b-2a35a1921158` | Florian Roth (Nextron Systems) |
| Local Groups Discovery - Linux | `676381a6-15ca-4d73-a9c8-6a22e970b90d` | Ömer Günal, Alejandro Ortuno, oscd.community |
| Local System Accounts Discovery - Linux | `b45e3d6f-42c6-47d8-a478-df6bd6cf534c` | Alejandro Ortuno, oscd.community, CheraghiMilad |
| Masquerading as Linux Crond Process | `9d4548fa-bba0-4e88-bd66-5d5bf516cda0` | Timur Zinniatullin, oscd.community |
| New Cron File Created | `6c4e2f43-d94d-4ead-b64d-97e53fa2bd05` | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| Nohup Execution | `e4ffe466-6ff8-48d4-94bd-e32d1a6061e2` | Christopher Peacock @SecurePeacock, SCYTHE @scythe_io |
| Potential Suspicious Change To Sensitive/Critical Files | `86157017-c2b1-4d4a-8c33-93b8e67e4af4` | @d4ns4n_ (Wuerth-Phoenix) |
| Potentially Suspicious Execution From Tmp Folder | `312b42b1-bded-4441-8b58-163a3af58775` | Joseliyo Sanchez, @Joseliyo_Jstnk |
| Print History File Contents | `d7821ff1-4527-4e33-9f84-d0d57fa2fb66` | Florian Roth (Nextron Systems) |
| Program Executions in Suspicious Folders | `a39d7fa7-3fbd-4dc2-97e1-d87f546b1bbc` | Florian Roth (Nextron Systems) |
| Scheduled Cron Task/Job - Linux | `6b14bac8-3e3a-4324-8109-42f0546a347f` | Alejandro Ortuno, oscd.community |
| Security Software Discovery - Linux | `c9d8b7fd-78e4-44fe-88f6-599135d46d60` | Daniil Yugoslavskiy, oscd.community |
| Service Reload or Start - Linux | `2625cc59-0634-40d0-821e-cb67382a3dd7` | Jakob Weinzettl, oscd.community, CheraghiMilad |
| Split A File Into Pieces - Linux | `2dad0cba-c62a-4a4f-949f-5f6ecd619769` | Igor Fits, oscd.community |
| Suspicious Commands Linux | `1543ae20-cbdf-4ec1-8d12-7664d667a825` | Florian Roth (Nextron Systems) |
| Suspicious History File Operations - Linux | `eae8ce9f-bde9-47a6-8e79-f20d18419910` | Mikhail Larin, oscd.community |
| Suspicious Invocation of Shell via AWK - Linux | `8c1a5675-cb85-452f-a298-b01b22a51856` | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| System Information Discovery | `42df45e7-e6e9-43b5-8f26-bec5b39cc239` | Ömer Günal, oscd.community |
| System Information Discovery - Auditd | `f34047d9-20d3-4e8b-8672-0a35cc50dc71` | Pawel Mazur |
| System Network Discovery - Linux | `e7bd1cfa-b446-4c88-8afb-403bcd79e3fa` | Ömer Günal and remotephone, oscd.community |
| System Owner or User Discovery - Linux | `9a0d8ca0-2385-4020-b6c6-cb6153ca56f3` | Timur Zinniatullin, oscd.community |
| Unix Shell Configuration Modification | `a94cdd87-6c54-4678-a6cc-2814ffe5a13d` | Peter Matkovski, IAI |
| Use Of Hidden Paths Or Files | `9e1bef8d-0fff-46f6-8465-9aa54e128c1e` | David Burkett, @signalblur |
| User Has Been Deleted Via Userdel | `08f26069-6f80-474b-8d1f-d971c6fedea0` | Tuan Le (NCSGroup) |

The recordings also name the tools of their runs (Invoke-AtomicRedTeam, Sysmon for
Linux, auditd, Zircolite) with their versions, and hold what Sysmon for Linux and
auditd recorded on the runner. Those tools ran in CI only; none of them is shipped.
The home folders they name belong to the runner's lab accounts: `bluefire-lab`, which
the lab creates, and `art`, which Atomic Red Team's own tests create.

## Release license decision

BlueFire Nexus remains MIT licensed. The repository does not contain contributor assignments,
a complete copyright ownership record, or equivalent evidence that would authorize relicensing
all project-authored history as AGPL-3.0-only with separate commercial licensing. Therefore this
review does not perform or recommend that relicense. It preserves the existing MIT license and
history, while continuing to apply the separate MITRE terms to the pinned declarative metadata.

## Lab: tools and content fetched at run time

The lab (`lab/`, `.github/workflows/lab.yml`) copies none of the following into this repository.
Each is fetched at the pinned version during a CI job and runs as a separate program on the
hosted runner. The pins are the `env` values at the top of the workflow, except for Tetragon,
which only the sensor spike tried (runs 43802339233 and 43803220104), whose version is the one
those runs installed.

| Project | Pin | Licence | Use |
|---|---|---|---|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | commit `a0e3f9bc` | MIT, Copyright (c) 2018 Red Canary, Inc. | Published attack test definitions |
| [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) | commit `8af478bb` | MIT | Executor for the test definitions |
| [powershell-yaml](https://github.com/cloudbase/powershell-yaml) | 0.4.12 | Apache-2.0 | Dependency of the executor |
| [Sysmon for Linux](https://github.com/microsoft/SysmonForLinux) | 1.6.0 | MIT, with GPL-2.0 for its eBPF programs | Sensor on the lab target |
| [SysinternalsEBPF](https://github.com/microsoft/SysinternalsEBPF) | 2.3.0 | LGPL-2.1 | Library the sensor depends on |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | release `r2026-07-01`, commit `552f3fee` | [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) | Detection rules. Output that names a matched rule keeps the rule's author |
| [Zircolite](https://github.com/wagga40/Zircolite) | 4.7.1 | LGPL-3.0-or-later | Rule engine, run as a separate program |
| [Linux audit daemon](https://github.com/linux-audit/audit-userspace) | Ubuntu 24.04 package `auditd` `1:3.1.2-2.1ubuntu0.1` | GPL-2.0 | Second sensor on the lab target, with the rules in `lab/sensors/audit.rules` |
| [Tetragon](https://github.com/cilium/tetragon) | 1.8.0 | Apache-2.0 | Sensor tried in the spike |

Each `lab-run` artifact includes the SigmaHQ rules used and their license.

The ranges (`lab/range/`, `.github/workflows/range-one.yml`) pull the following images and
packages at the pins their spec files give, when a range is built or runs. None of them is copied
into this repository. The nginx image runs unchanged; the others are the base of images the lab
builds from a spec (`bluefire-lab range render`), which add the lab's configuration files.

| Project | Pin | Licence | Use |
|---|---|---|---|
| [nginx official image](https://github.com/nginx/docker-nginx) | `nginx:1.28.0-bookworm@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609` | nginx: BSD-2-Clause; the image's Debian packages under their own licences | The bare hosts of `lab/range/seal-check.yaml`: a listener for the seal's probes |
| [Ubuntu official image](https://hub.docker.com/_/ubuntu) | `ubuntu:noble-20261110.1@sha256:882e1e56091c9ffbc70c026ff5935fe85d3c91ad155917865ba2ffa23ede1560`, with packages from the [Ubuntu snapshot archive](https://snapshot.ubuntu.com/) at `20261120T000000Z` | Each package under its own licence, listed in its `/usr/share/doc/<package>/copyright` | The base of the hosts the lab builds, the hosts of `lab/range/range-one.yaml`. Every package they install comes from that snapshot (except the certificate store, see `lab/README.md`): among them nginx, PHP 8.3 with php-fpm and php-mysql, MariaDB, git, make, OpenSSH, sudo, cron, curl, wget, sshpass, Python 3, rsyslog and OpenSSL, which makes the stand-in internet's certificate at build time |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`, every file checked against the SHA-256 in `lab/range/range-one.lock` | MIT, Copyright (c) 2018 Red Canary, Inc. | Fetched when range one's images are built, and copied into them as data: the `src` folder of T1110.004 (its password lists) on `attacker`, and T1105's `atomic.sh` on `inet`, which serves it. The technique YAMLs of the path are fetched and checked too, and are written to the build folder only. No build step runs any of them. The project's `LICENSE.txt` is fetched and locked with them, and goes with every copy: `build/atomics/LICENSE.txt` in the build folder, and `/opt/atomics/LICENSE.txt` on `attacker` and `inet`. The build folder is part of a run's folder, which the `range-one` CI job uploads as the artifact `range-one-run`, so that artifact holds these files with their licence. The images are built on the machine or runner that runs the range and are not pushed to a registry; in CI their layers are kept in the repository's GitHub Actions cache |
| [Wazuh manager image](https://github.com/wazuh/wazuh-docker) | `wazuh/wazuh-manager:4.14.10@sha256:eabfa7ee4e63acb51c2130fa0583e30f843d030b091cf45a4fbd93d78fa21517` | Wazuh: GPL-2.0; the image's Amazon Linux 2023 packages under their own licences | The range's Wazuh manager, with the lab's edits of its stock `ossec.conf`, the lab's snoopy decoder, Filebeat kept from starting and its API on loopback only |
| [Wazuh agent](https://github.com/wazuh/wazuh) | package `wazuh-agent_4.14.10-1_amd64.deb` from `packages.wazuh.com`, SHA-512 `5ee41846e81b2f5f5017bb0f968ac039443f09a400e5feb8121a4e52db6bb8d1c91683667b03a657a0236c858bd1f159026b493ace504ec8f92e491e6c8ae04d` | GPL-2.0 | The agent inside each watched host, with the lab's edits of its stock `ossec.conf` |
| [snoopy](https://github.com/a2o/snoopy) | Ubuntu noble package `snoopy` `2.5.1-1`, from the snapshot above | GPL-2.0 | Writes every program start on a watched host to syslog |

The tests in `lab/tests/fixtures/range/wazuh/` hold short excerpts of the stock `ossec.conf` files
that the pinned agent package and manager image install (Wazuh, GPL-2.0), as test data for the
lab's edits of them, and lines and events trimmed from one run of a range with one agent host.
The small range in `lab/tests/fixtures/range/small/` stands in for published files with contents
of its own, at a stand-in commit; it copies nothing from Atomic Red Team.

`lab/tests/fixtures/range/ecs/ecs-8.17.0-fields.yml` is taken from the
[Elastic Common Schema](https://github.com/elastic/ecs) (Apache-2.0, Copyright Elasticsearch B.V.),
tag `v8.17.0`, commit `e3103a213a4e84cbcd3ef36da7001483ddc60230`, file `generated/ecs/ecs_flat.yml`
(SHA-256 `4c72bf4d0fa7b79a101ac86c5d175092557a8ed318c29db817bd85186db207f0`): the name and type of
each of its 1692 fields, the allowed values of `event.kind`, `event.category`, `event.type` and
`event.outcome`, and the event types ECS expects with each category, and nothing else. A test checks
every field the lab's ECS mapper (`lab/bluefire_lab/range/ecs.py`) can write against it. The mapper
itself is the lab's own: no maintained mapping of Wazuh 4.x output to ECS was found to follow (Wazuh's
own Filebeat module keeps Wazuh's field names, and the Wazuh Common Schema of Wazuh 5 describes the
output of Wazuh 5's engine), so it copies none.
The lines in `lab/tests/fixtures/range/ecs/` are trimmed from one run of range one, with each
hash and key fingerprint replaced by a stand-in.
The workflow's image build uses [docker/setup-buildx-action](https://github.com/docker/setup-buildx-action)
and [docker/bake-action](https://github.com/docker/bake-action) (Apache-2.0), pinned to a commit,
and runs [BuildKit](https://github.com/moby/buildkit) (Apache-2.0) from the image
`moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe`.

The lab's Python package depends on [PyYAML](https://github.com/yaml/pyyaml) (MIT), installed
from PyPI. Its tests and lint use [pytest](https://github.com/pytest-dev/pytest) (MIT) and
[Ruff](https://github.com/astral-sh/ruff) (MIT), installed the same way in CI.

The checks in `.github/workflows/checks.yml` run [gitleaks](https://github.com/gitleaks/gitleaks)
(MIT), a release binary pinned by digest, and [detect-secrets](https://github.com/Yelp/detect-secrets)
(Apache-2.0) from PyPI.

## App checks and the one-command start: what they fetch

None of the following is copied into this repository.

| Project | Pin | Licence | Use |
|---|---|---|---|
| [Playwright image](https://mcr.microsoft.com/en-us/artifact/mar/playwright) | `mcr.microsoft.com/playwright:v1.62.1-noble` | Apache-2.0 for Playwright; the image's Ubuntu packages and browser keep their own licences | Container of the browser tests in `.github/workflows/app.yml` and in `CONTRIBUTING.md` |
| [gzip](https://www.gnu.org/software/gzip/) as Ubuntu packages it | `gzip_1.12-1ubuntu3.2_amd64.deb`, pinned by digest | GPL-3.0-or-later | The exact gzip build the runner's collection tests expect, in `.github/workflows/runner.yml` |
| [Python image](https://hub.docker.com/_/python) | `python:3.12-slim` | PSF-2.0 for Python; the image's Debian packages keep their own licences | Base of `docker/app.Dockerfile`, which `docker compose up app` builds |
| [sharp](https://github.com/lovell/sharp) with its prebuilt [libvips](https://github.com/libvips/libvips) | `sharp@0.34.5` in `frontend/pnpm-lock.yaml` (with `@img/sharp-libvips-*@1.2.4`) | Apache-2.0 for sharp; LGPL-3.0-or-later for libvips and the libraries built into it | A development dependency of the interface: `frontend/tests/pictures/loop.ts` writes the loop of the live view as an animated GIF with it, in the job that takes the pictures. Nothing of it is in the app or its pages |

The app's own Python and JavaScript dependencies are named in `pyproject.toml` and
`frontend/package.json`, and the release dependency inventory above covers what a wheel carries.
