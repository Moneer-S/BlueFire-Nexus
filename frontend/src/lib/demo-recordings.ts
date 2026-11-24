// The demo build's recordings: the real ones that ship with BlueFire, read from
// the same files the service ships, and labelled the way the service labels
// them. Only the demo build loads this module. It lists them from the entries
// the build works out of their files, as the service's list route gives them,
// and each recording is a file of its own that is loaded only when it is
// opened, so listing them loads none and the installed interface carries none.

import entries from "virtual:shipped-recording-summaries";
import { readRecording } from "../live/recording";
import type { Recording } from "../live/recording";
import { isRecordingSummary, type RecordingSummary } from "./api";

export type ShippedRecording = { summary: RecordingSummary; recording: Recording };

/** The files under bluefire/data/recordings/, each loaded on demand, by file name. */
const FILES = new Map(Object.entries(import.meta.glob<string>("../../../bluefire/data/recordings/*.json", { query: "?raw", import: "default" }))
  .map(([path, load]) => [path.slice(path.lastIndexOf("/") + 1), load]));

/** Every shipped recording's list entry, in the order of their file names, as the service lists them. */
export function shippedSummaries(): RecordingSummary[] {
  return entries.map(({ file, summary }) => {
    if (!isRecordingSummary(summary)) throw new Error(`The build's list entry of ${file} cannot be read.`);
    return summary;
  });
}

const opened = new Map<string, Promise<ShippedRecording>>();

async function open(file: string, summary: RecordingSummary): Promise<ShippedRecording> {
  const load = FILES.get(file);
  if (!load) throw new Error(`The shipped recording ${file} is not in the build.`);
  const recording = readRecording(JSON.parse(await load()));
  if (recording.id !== summary.id) throw new Error(`The shipped recording ${file} is not the one its list entry names.`);
  return { summary, recording };
}

/** One shipped recording by its id, loaded whole the first time it is asked for, or undefined. */
export async function shippedRecording(id: string): Promise<ShippedRecording | undefined> {
  const summaries = shippedSummaries();
  const index = summaries.findIndex((summary) => summary.id === id);
  const file = entries[index]?.file;
  const summary = summaries[index];
  if (file === undefined || !summary) return undefined;
  let found = opened.get(id);
  if (!found) {
    found = open(file, summary);
    opened.set(id, found);
  }
  return found;
}
