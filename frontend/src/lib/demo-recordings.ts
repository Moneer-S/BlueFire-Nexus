// The demo build's recordings: the one real example that ships with BlueFire,
// read from the same file the service ships, and labelled the way the service
// labels it. Only the demo build loads this module, as a file of its own, so
// the installed interface does not carry the recording.

import shippedText from "../../../bluefire/data/recordings/lab-linux-host.json?raw";
import { readRecording } from "../live/recording";
import type { Recording } from "../live/recording";
import type { RecordingSummary } from "./api";

/** The service's note for a shipped recording (`SHIPPED_NOTE` in bluefire/recordings.py). */
const SHIPPED_NOTE = "Shipped with BlueFire. This repository's lab workflow recorded it in the CI run at {run_url}. BlueFire checked that it follows the recording format and that its parts agree with each other.";

/** The list entry the service gives a recording: the same keys, in the same order. */
function summarize(recording: Recording, origin: RecordingSummary["origin"]): RecordingSummary {
  const source: RecordingSummary["source"] = { engine: recording.source.engine, environment: recording.source.environment, started: recording.source.started };
  if (recording.source.finished !== undefined) source.finished = recording.source.finished;
  if (recording.source.run_url !== undefined) source.run_url = recording.source.run_url;
  if (recording.source.commit !== undefined) source.commit = recording.source.commit;
  return {
    id: recording.id,
    title: recording.title,
    kind: recording.kind,
    source,
    score: { ...recording.score },
    counts: { steps: recording.steps.length, events: recording.events.length, alerts: recording.alerts.length },
    origin,
    running: recording.source.finished === undefined,
  };
}

let shipped: { summary: RecordingSummary; recording: Recording } | undefined;

export async function shippedRecording(): Promise<{ summary: RecordingSummary; recording: Recording }> {
  if (!shipped) {
    const recording = readRecording(JSON.parse(shippedText));
    const runUrl = recording.source.run_url;
    // The service refuses to ship a recording that does not name its finished CI run.
    if (runUrl === undefined || recording.source.finished === undefined) throw new Error("The shipped recording does not name its finished CI run.");
    shipped = { recording, summary: summarize(recording, { kind: "shipped", run_url: runUrl, note: SHIPPED_NOTE.replace("{run_url}", runUrl) }) };
  }
  return shipped;
}
