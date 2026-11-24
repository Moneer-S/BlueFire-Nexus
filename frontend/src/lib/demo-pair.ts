// The demo build's pair of runs: the real one that ships with BlueFire, the
// delta under bluefire/data/recordings/deltas/ with its two recordings, read
// from the same files the service ships and labelled the way the service labels
// it. Only the demo build loads this module, as a file of its own.

import deltaText from "../../../bluefire/data/recordings/deltas/lab-pair-history-watch.json?raw";
import { readDelta, type Delta, type DeltaEntry } from "./api";
import { shippedSummaries } from "./demo-recordings";

/** The service's note for a pair of two runs side by side in one CI run (`SHIPPED_PAIR_NOTE` in bluefire/recording_deltas.py). */
const SHIPPED_PAIR_NOTE = "Shipped with BlueFire, with both of its recordings. This repository's lab workflow made the two runs side by side, and this comparison of them, in the CI run at {run_url}. BlueFire checked that the comparison follows the delta format and names both recordings by the SHA-256 of their files, with every step it lists. It did not make the comparison: bluefire-lab compare did.";

/**
 * JSON with sorted keys and no spaces, as the service writes it to name a
 * delta (`canonical_json_bytes` in bluefire/util.py). A delta holds texts,
 * whole numbers, booleans and nulls, which both write alike.
 */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** A delta's id as the service gives it: the first 16 hex digits of the SHA-256 of its canonical JSON. */
async function deltaId(delta: Delta): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(delta)));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

async function load(): Promise<DeltaEntry> {
  const delta = readDelta(JSON.parse(deltaText));
  // The list entries of its two recordings: neither recording is loaded until a step's detail asks for it.
  const summaries = shippedSummaries();
  const before = summaries.find((summary) => summary.id === delta.before.id);
  const after = summaries.find((summary) => summary.id === delta.after.id);
  if (!before || !after) throw new Error("The shipped pair names a recording that is not shipped.");
  const runUrl = before.source.run_url;
  // The shipped pair is two runs side by side in one CI run, which the service names.
  if (delta.runners !== 2 || runUrl === undefined || runUrl !== after.source.run_url) throw new Error("The shipped pair is not two runs side by side in one CI run.");
  return {
    delta,
    summary: {
      id: await deltaId(delta),
      claim: delta.claim,
      declared_change: delta.declared_change,
      runners: delta.runners ?? null,
      comparable: delta.comparable,
      limit: delta.limit ?? null,
      refused_because: delta.refused_because,
      counts: delta.counts,
      before: delta.before,
      after: delta.after,
      recordings: { before, after },
      origin: { kind: "shipped", run_url: runUrl, note: SHIPPED_PAIR_NOTE.replace("{run_url}", runUrl) },
    },
  };
}

let pair: Promise<DeltaEntry> | undefined;

/** The shipped pair with its list entry, loaded once when it is first asked for. */
export function shippedPair(): Promise<DeltaEntry> {
  if (!pair) pair = load();
  return pair;
}
