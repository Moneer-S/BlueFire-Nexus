# Atomic gzip collection

The **Atomic gzip collection comparison** example tests whether a detector can
identify retained synthetic values after compression while avoiding redacted
benign activity. It keeps the existing native record and whole-file collection
methods available as compatible alternatives.

Choose the example in Builder, inspect its five steps, and select an owned Linux
environment. It creates eight synthetic records, optionally redacts their values,
selects the exact transformed file, collects it, and cleans up receipt-owned files.
The gzip method requires an already-installed, protected system gzip executable.
An unavailable or untrusted tool stops that method; BlueFire does not install it.

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

The Linux adapter accepts only the protected `/usr/bin/gzip` or `/bin/gzip` ELF,
opens and hashes it before execution through its pinned descriptor, clears its
environment and uses no filename arguments. Its result records the selected
executable, digest, fixed arguments and source-test identity. It bounds input,
stdout, stderr and elapsed time, kills and reaps timed-out children, and arms a
parent-death signal. There are no network effects, arbitrary command controls,
dependency installers, elevation, or personal-file inputs.

GNU gzip remains an external system dependency under GPL-3.0-or-later; it is not
copied into BlueFire's source or wheel. Atomic Red Team's adapted test is MIT.
BlueFire preserves its existing MIT license and the distinct upstream notices.
Use of these project names describes provenance and does not imply endorsement.
