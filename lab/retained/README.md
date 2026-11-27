# Retained range runs

A retained range run is real raw sensor data made by the hosted range
workflow, small enough to keep in the repository and judge again after the
rules change. It is not a recording or a score. Those are derived from it.

Only the hosted workflow adds a run below this folder. Files produced on a
developer machine are never retained. A candidate is committed only after the
repository's unchanged privacy and secret scans pass on its exact bytes.

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

The Actions run and artifact are the public provenance of the retained bytes.
The repository commit binds the checked-in bytes. The small provenance file
does not duplicate artifact or file digests: those secret-like opaque values
are unrelated to rejudgment and fail the repository's secret gate. This means
the verifier can independently prove the committed file closure, byte counts,
copy equality, and that the source stayed unchanged while it was used. After
the hosted artifact expires, it cannot independently prove that a retained
file equals the former artifact; that relationship is the hosted workflow's
attestation, reached through the recorded run URL.

The stored and materialized sensor bytes are identical. Path remapping lets a
hosted workflow retain a regular text file under a permitted name, such as
`.txt`, and restore the canonical name the scorer reads. It does not redact,
decode, or otherwise transform raw telemetry.

The file list is an exact closure. Missing, extra, linked, duplicated, unsafe,
or changed files are refused. A packet-capable retained run keeps:

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

The command verifies the source, copies the declared bytes to their canonical
paths, verifies each copy, restores the pinned spec into the copied context,
fetches only the judging spec's locked public rules, scores the copy, and
writes `recording.json` and `replay.html`. It verifies the retained source
again before the output folder becomes visible. A failure removes only the
command's private partial folder. The retained source is never changed.

Open the generated replay page directly, or import its `recording.json` on the
app's Runs screen. A later evaluation keeps the original run identity and
source; its judging spec and rule locks are recorded as evaluation metadata.
