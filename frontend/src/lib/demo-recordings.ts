// The demo build's recordings: the real ones that ship with BlueFire, read from
// the same files the service ships, and labelled the way the service labels
// them. Only the demo build loads this module, and each recording is a file of
// its own that is loaded only when it is asked for, so the installed interface
// carries none of them.

import { readRecording } from "../live/recording";
import type { Recording } from "../live/recording";
import type { RecordingSummary } from "./api";

/** The service's note for a shipped recording (`SHIPPED_NOTE` in bluefire/recordings.py). */
const SHIPPED_NOTE = "Shipped with BlueFire. This repository's lab workflow recorded it in the CI run at {run_url}. BlueFire checked that it follows the recording format and that its parts agree with each other.";

/** The files under bluefire/data/recordings/, each loaded on demand. */
const FILES: readonly (() => Promise<{ default: string }>)[] = [
  () => import("../../../bluefire/data/recordings/lab-linux-host.json?raw"),
  () => import("../../../bluefire/data/recordings/lab-pair-history-watch-before.json?raw"),
  () => import("../../../bluefire/data/recordings/lab-pair-history-watch-after.json?raw"),
];

export type ShippedRecording = { summary: RecordingSummary; recording: Recording };

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

function shipped(text: string): ShippedRecording {
  const recording = readRecording(JSON.parse(text));
  const runUrl = recording.source.run_url;
  // The service refuses to ship a recording that does not name its finished CI run.
  if (runUrl === undefined || recording.source.finished === undefined) throw new Error("A shipped recording does not name its finished CI run.");
  return { recording, summary: summarize(recording, { kind: "shipped", run_url: runUrl, note: SHIPPED_NOTE.replace("{run_url}", runUrl) }) };
}

let all: Promise<ShippedRecording[]> | undefined;

/** Every shipped recording, in the order of their file names, as the service lists them. */
export function shippedRecordings(): Promise<ShippedRecording[]> {
  if (!all) all = Promise.all(FILES.map(async (load) => shipped((await load()).default)));
  return all;
}

/** One shipped recording by its id, or undefined. */
export async function shippedRecording(id: string): Promise<ShippedRecording | undefined> {
  return (await shippedRecordings()).find((item) => item.recording.id === id);
}
