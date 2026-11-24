// The demo build's recordings: the real ones that ship with BlueFire, read from
// the same files the service ships, and labelled the way the service labels
// them. Only the demo build loads this module. It lists them from the entries
// the build works out of their files, as the service's list route gives them,
// and each recording is a file of its own that is loaded only when it is
// opened, so listing them loads none and the installed interface carries none.
// As the service does, it lists the first file of each id; a later file of the
// same id is another evaluation of that run, opened by its SHA-256.

import entries from "virtual:shipped-recording-summaries";
import { readRecording } from "../live/recording";
import type { Recording } from "../live/recording";
import { isRecordingSummary, type RecordingSummary } from "./api";

export type ShippedRecording = { summary: RecordingSummary; recording: Recording };

/** The files under bluefire/data/recordings/, each loaded on demand, by file name. */
const FILES = new Map(Object.entries(import.meta.glob<string>("../../../bluefire/data/recordings/*.json", { query: "?raw", import: "default" }))
  .map(([path, load]) => [path.slice(path.lastIndexOf("/") + 1), load]));

/** Every shipped file with its list entry, in the order of their file names. */
function shippedFiles(): { file: string; sha256: string; summary: RecordingSummary }[] {
  return entries.map(({ file, sha256, summary }) => {
    if (!isRecordingSummary(summary)) throw new Error(`The build's list entry of ${file} cannot be read.`);
    return { file, sha256, summary };
  });
}

/** Every shipped recording's list entry, the first file of each id, as the service lists them. */
export function shippedSummaries(): RecordingSummary[] {
  const firsts = new Map<string, RecordingSummary>();
  for (const { summary } of shippedFiles()) if (!firsts.has(summary.id)) firsts.set(summary.id, summary);
  return [...firsts.values()];
}

const opened = new Map<string, Promise<ShippedRecording>>();

async function open(file: string, summary: RecordingSummary): Promise<ShippedRecording> {
  const load = FILES.get(file);
  if (!load) throw new Error(`The shipped recording ${file} is not in the build.`);
  const recording = readRecording(JSON.parse(await load()));
  if (recording.id !== summary.id) throw new Error(`The shipped recording ${file} is not the one its list entry names.`);
  return { summary, recording };
}

function loaded(file: string, summary: RecordingSummary): Promise<ShippedRecording> {
  let found = opened.get(file);
  if (!found) {
    found = open(file, summary);
    opened.set(file, found);
  }
  return found;
}

/** One shipped recording by its id, its first file, loaded whole the first time it is asked for, or undefined. */
export async function shippedRecording(id: string): Promise<ShippedRecording | undefined> {
  const first = shippedFiles().find(({ summary }) => summary.id === id);
  return first ? loaded(first.file, first.summary) : undefined;
}

/** One shipped file of a recording by its id and SHA-256, loaded whole the first time it is asked for, or undefined. */
export async function shippedFile(id: string, sha256: string): Promise<ShippedRecording | undefined> {
  const found = shippedFiles().find((entry) => entry.summary.id === id && entry.sha256 === sha256);
  return found ? loaded(found.file, found.summary) : undefined;
}

/** The list entry of one shipped file, by its id and SHA-256, without loading it. */
export function shippedFileSummary(id: string, sha256: string): RecordingSummary | undefined {
  return shippedFiles().find((entry) => entry.summary.id === id && entry.sha256 === sha256)?.summary;
}
