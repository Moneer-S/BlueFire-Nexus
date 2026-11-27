# Retained range runs

A retained range run is real raw sensor data made by the hosted range
workflow, small enough to keep in the repository and judge again after the
rules change. It is not a recording or a score. Those are derived from it.
No retained run is committed yet; this document defines the required shape
for a future fixture made by a separate hosted CI run.

Only the hosted workflow adds a run below this folder. Files produced on a
developer machine are never retained. A candidate is committed only after the
repository's unchanged privacy and secret scans pass on its exact bytes.

The hosted, manually dispatched fixture workflow exports a completed run with:

```bash
bluefire-lab range retain "$RUN" \
  --spec lab/range/<fixture-spec>.yaml \
  --out "$RUNNER_TEMP/retained-artifact/lab/retained/<run>"
```

`range retain` runs only when the standard Actions context says this is a
GitHub-hosted `workflow_dispatch` job. It takes no provenance flags: the
repository, tracked workflow, run, attempt, job, head commit and run URL come
from that context. The workflow and spec on disk must exactly equal their
blobs at that commit, the source manifest must hold that exact spec and URL,
and the source run must be sealed with exit 0 and complete teardown. The
artifact is named `<range>-run-<attempt>`; each `artifact_path` is derived from
the output folder's path below `$RUNNER_TEMP/retained-artifact`, which is the
root the workflow uploads.

The exporter binds packet capture to the engine's exact filter and the tracked
spec's capture hosts. It requires one distinct ready interface, PCAP and counter
record for every declared network, then recomputes the exact packet file
closure, classic-PCAP facts, digests, ready tokens and tcpdump counters. It
refuses any kernel drop and limits the PCAP identity bytes to 8 MiB and the
whole candidate to 16 MiB. It selects the two live Wazuh JSON streams only
after their bytes exactly match the chronological, decompressed daily files
collected from the manager. It also selects the manager startup record, every
file of every completed path step, every declared PCAP and its counter record,
plus only the manifest context needed to score and record them later. Raw bytes
are streamed unchanged. The known `.log` inputs are stored as `.txt` and mapped
back to their canonical names; this is a name change only. Generated ECS,
scores, recordings, replay pages, rule-engine work and Docker event documents
are not retained.

Every selected source and tracked input must be a regular single-link file.
The exporter hashes it before use, verifies size and hash while streaming the
copy, verifies the copy, and rechecks all sources before publication. It writes
a private sibling candidate, runs the actual retained-run verifier over its
exact closure, then atomically publishes a new output folder without replacing
any final path that appeared in the meantime. This final-name guarantee assumes
the GitHub workflow keeps its private `$RUNNER_TEMP/retained-artifact` parent
stable while the command runs. The exporter never
truncates, redacts, encodes or synthesizes telemetry. The unchanged repository
privacy and secret scans remain the final publication gate.

Each run has this shape:

```text
<run>/
  provenance.json
  files/
    ...
```

`provenance.json` has schema `bluefire.range-run/1`. It names the repository,
workflow, job, Actions run and attempt, the first 12 characters of the head
commit, and the artifact. Its run section names the range run id, pinned run
spec, result and exit code. Its sorted `files` list gives every retained
file's:

- `artifact_path`: where the hosted artifact supplied it;
- `stored_path`: its path in the retained folder, below `files/`;
- `run_path`: the canonical path restored in a disposable run folder;
- `role` and byte count.

`provenance.json` declares an Actions run and artifact. The verifier validates
the declared values' shape and internal consistency; it does not contact
GitHub, establish that the run, job, head or artifact exists, or prove that the
artifact supplied these bytes. Authenticity is established separately by the
future fixture's hosted CI run and artifact link. The repository commit then
binds the checked-in bytes. The small provenance file does not duplicate
artifact or file digests: those secret-like opaque values are unrelated to
rejudgment and fail the repository's secret gate. The verifier can
independently prove only the committed file closure, byte counts, copy
equality, and that the source stayed unchanged while it was used. After the
hosted artifact expires, neither it nor the repository alone can independently
prove that a retained file equals the former artifact.

The exporter derives this declaration from the hosted job and checks it
against the generated run locally. This still does not authenticate GitHub to
a later clone. The public Actions run and artifact link establish that external
fact for a fixture while the artifact exists; the repository commit thereafter
binds the reviewed bytes and preserves the verifier's more limited proof.

The stored and materialized sensor bytes are identical. Path remapping lets a
hosted workflow retain a regular text file under a permitted name, such as
`.txt`, and restore the canonical name the scorer reads. It does not redact,
decode, or otherwise transform raw telemetry.

The file list is an exact closure. Missing, extra, symbolically or hard linked,
duplicated, unsafe, or changed files are refused. A packet-capable retained
run keeps:

- a minimal hosted context manifest with only the real fields scoring and
  recording need;
- the pinned spec the run used;
- the manager's complete raw archive and alerts;
- the manager startup record and any raw step output the recording consumes;
- every packet capture plus its capture metadata and drop counters.

The context manifest carries the exact first and last Docker event times that
the hosted workflow selected for the recording clock. It omits unrelated
container ids and the full Docker and seal documents; the Actions run retains
those. Generated ECS, scores, recordings, replay pages, evaluator work, and
duplicate live output are omitted. Capture size is bounded during the hosted
run; sensor data is not truncated afterward.

After installing the lab from a fresh clone, judge a retained run into a new
ignored folder:

```bash
bluefire-lab range rejudge lab/retained/<run> \
  --defenses lab/range/<defense-spec>.yaml \
  --engine <path-to-the-pinned-rule-engine> \
  --template bluefire/ui/replay.html \
  --out .bluefire-runs/rejudged/<run>
```

The command validates the exact source closure and declared provenance, copies
the declared bytes to their canonical paths, verifies each copy, restores the
pinned spec into the copied context, fetches only the judging spec's locked
public rules, scores the copy, and writes `recording.json` and `replay.html`.
Any copied `recording.json` is discarded before scoring, and publication
requires the scorer to create a fresh one. The command validates the retained
source again before the output folder becomes visible. A failure removes only
the command's private partial folder. The retained source is never changed.

Open the generated replay page directly, or import its `recording.json` on the
app's Runs screen. A later evaluation keeps the original run identity and
source; its judging spec and rule locks are recorded as evaluation metadata.
