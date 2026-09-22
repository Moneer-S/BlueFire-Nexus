# Atomic gzip collection

The **Atomic gzip collection comparison** example tests whether a detector can
identify retained synthetic values after compression while avoiding redacted
benign activity. It keeps the existing native record and whole-file collection
methods available as compatible alternatives.

Choose the example in Builder, inspect its five steps, and select an owned Linux
environment. It creates eight synthetic records, optionally redacts their values,
selects the exact transformed file, collects it, and cleans up receipt-owned files.
The gzip method requires an already-installed, protected GNU gzip build listed in
[Reviewed native tool builds](REVIEWED_NATIVE_BUILDS.md). In Settings, open the
inactive Execute profile, choose **Configure methods**, select Linux and the gzip
collection method, and save the draft. Then choose **Set up GNU gzip**. Inspect the exact
package version and installation location, review the result, then save its
binding. Inspection does not run gzip or activate the profile. An unavailable or
untrusted tool stops that method; BlueFire does not install it.

New default profiles leave optional external tools unselected so native methods
can run before tool setup. Existing saved profiles keep their selections: if an
older profile enables unbound gzip, deactivate it and either finish this setup or
unselect gzip in **Configure methods**. Saving that draft does not approve a run.

In Run review, leave **Collection contents** enabled. This normal control selects
the semantic observer; BlueFire derives the exact collection paths and schedule.
The displayed gzip path is `staged/collection/bundle.jsonl.gz`, or
`staged/variation/bundle.jsonl.gz` for alternate staging. Native methods display
`bundle.jsonl` or `bundle.tar`. Review the actual prepared settings and fresh
approval through normal controls before execution.

The observer independently opens and hashes the produced file, decodes one bounded
gzip member, and records counts of retained, redacted and empty synthetic values.
It validates the compressed stream's checksum and length and rejects concatenated
members, trailing data, truncation and excessive expansion. It does not extract
files or retain record values. Run a detector against those observations, repeat
with **Redact values** enabled for benign activity, revise the detector, and compare
its actual evaluations and replay. Command completion is not a detector hit.

## Reviewed source and modifications

This method adapts Atomic Red Team's
[T1560.001 single-file gzip test](https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1560.001/T1560.001.yaml#L190),
test GUID `cde3c2af-3485-49eb-9c1f-0ed60e9cc0af`, at commit
`388942adbd9641f4dfdcf079d7efe9a75ec0ac43`. The reviewed YAML is 20,402 bytes,
SHA-256 `681f0727810cc1fa1d2032f818d0cdb5b02dd058ed85416658ee26437773e681`.
The complete upstream MIT license is preserved in
`bluefire/data/atomic_red_team_LICENSE.txt`, with Red Canary's copyright notice.
This is a constrained adaptation, not execution of the complete Atomic framework.

The upstream method compresses a selected file with `gzip -k`, creates fallback
sample content when absent, and removes its compressed output during cleanup.
BlueFire instead supplies its previously generated, digest-verified JSONL over
stdin to one fixed system gzip process with `-n -c`. These documented gzip options
preserve the original input and omit embedded filename/timestamp. The adapter
replaces the shell, caller paths, fallback content and shell cleanup with typed
bindings, bounded process handling, receipt-bound output publication and normal
verified cleanup. The native JSONL and USTAR implementations are not relabeled as
upstream work.

The Linux adapter accepts only a setup-bound executable whose version, architecture,
size and digest match a reviewed GNU gzip package. The default location is
`/usr/bin/gzip`; a protected nondefault location may contain the same reviewed bytes.
The runner holds and rechecks the protected ELF and its parent directories, then
executes through its open descriptor. Runtime parameters cannot select a tool path
or argument list. It clears the environment, sets only `LC_ALL=C`, uses the approved
workspace as its working directory and supplies no filename arguments. Its result
records the executable identity, fixed arguments, source test, adapter version,
contract and installation digests, package version and successful exit status.
Input and compressed output are each limited to 1 MiB, diagnostics to 8 KiB, and
the entire method to five seconds or the shorter approved deadline. The adapter
kills and reaps timed-out children, arms a parent-death signal and prevents gaining
new privileges. There are no network effects, arbitrary command controls,
dependency installers, elevation, or personal-file inputs.

Adapter version **1.1.0** requires this installation binding. A previous unbound
profile or exact-plan approval does not acquire it automatically. Reopen the saved
experiment with the current runner, finish setup and review a fresh approval.
Historical version 1.0.0 output remains readable with its original identity fields;
it is not upgraded into proof of a bound installation. The graph, collection
objective, input digest, independent observer and receipt-based cleanup remain the
same. Native JSONL and USTAR methods do not require an external tool installation.

GNU gzip remains an external system dependency under GPL-3.0-or-later; it is not
copied into BlueFire's source or wheel. Atomic Red Team's adapted test is MIT.
BlueFire preserves its existing MIT license and the distinct upstream notices.
Use of these project names describes provenance and does not imply endorsement.

## Runner implementation

`runner/src/actions/atomic_gzip_action.rs` owns the registered method's descriptor,
typed parameters, input binding and receipt-backed artifact publication. The
registry in `runner/src/actions.rs` composes it with the other reviewed actions.
`runner/src/atomic_gzip.rs` owns the fixed system-process boundary described above.
The shared installation inspector and closed reviewed-build registry establish
dependency readiness. The adapter repeats the binding and executable checks before
effects; the shared inspector cannot register arbitrary native code. The immutable
Python contract is in `bluefire/tool_adapters/gzip.py`. Simulation remains a labeled
synthetic result and does not inspect or execute an external utility.
