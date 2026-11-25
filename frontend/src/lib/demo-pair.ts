// The demo build's pairs of runs: the real ones that ship with BlueFire, the
// deltas under bluefire/data/recordings/deltas/ with their recordings, read
// from the same files the service ships and labelled the way the service labels
// them. Only the demo build loads this module, as a file of its own.

import { readDelta, type Delta, type DeltaEntry, type DeltaSummary } from "./api";
import { shippedFileSummary } from "./demo-recordings";

/** The service's notes for a shipped pair (`SHIPPED_PAIR_NOTE` and `SHIPPED_ONE_RUN_NOTE` in bluefire/recording_deltas.py). */
const SHIPPED_PAIR_NOTE = "Shipped with BlueFire, with both of its recordings. This repository's lab workflow made the two runs side by side, and this comparison of them, in the CI run at {run_url}. BlueFire checked that the comparison follows the delta format and names both recordings by the SHA-256 of their files, with every step it lists. It did not make the comparison: bluefire-lab compare did.";
const SHIPPED_ONE_RUN_NOTE = "Shipped with BlueFire, with both of its recordings. This repository's lab workflow ran the list once, evaluated its telemetry with two sets of the lab's rules, and compared the two, in the CI run at {run_url}. BlueFire checked that the comparison follows the delta format, names both recordings by the SHA-256 of their files with every step it lists, and that the two are one run. It did not make the comparison: bluefire-lab compare did.";
/** The service lists at most this many of the steps a pair moved (`moved` in bluefire/recording_deltas.py). */
const MOVED_LISTED = 20;

/** The shipped deltas, each loaded on demand, in the order of their file names, as the service lists them. */
const DELTAS = Object.entries(import.meta.glob<string>("../../../bluefire/data/recordings/deltas/*.json", { query: "?raw", import: "default" }))
  .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

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

/** Where a shipped pair comes from, as the service says it: the one CI run that made both recordings and compared them. */
function origin(delta: Delta, runUrl: string): DeltaSummary["origin"] {
  if (delta.one_run === true) return { kind: "shipped", run_url: runUrl, note: SHIPPED_ONE_RUN_NOTE.replace("{run_url}", runUrl) };
  if (delta.runners === 2) return { kind: "shipped", run_url: runUrl, note: SHIPPED_PAIR_NOTE.replace("{run_url}", runUrl) };
  throw new Error("A shipped pair is two runs side by side in one CI run, or one run evaluated twice.");
}

async function load(file: string, text: string): Promise<DeltaEntry> {
  const delta = readDelta(JSON.parse(text));
  // The list entries of its two recordings, by the very files it names: neither is loaded until a step's detail asks for it.
  const before = shippedFileSummary(delta.before.id, delta.before.sha256);
  const after = shippedFileSummary(delta.after.id, delta.after.sha256);
  if (!before || !after) throw new Error(`The shipped pair ${file} names a recording file that is not shipped.`);
  const runUrl = before.source.run_url;
  if (runUrl === undefined || runUrl !== after.source.run_url) throw new Error(`The shipped pair ${file} is not of one CI run.`);
  return {
    delta,
    summary: {
      id: await deltaId(delta),
      claim: delta.claim,
      declared_change: delta.declared_change,
      runners: delta.runners ?? null,
      one_run: delta.one_run === true,
      comparable: delta.comparable,
      limit: delta.limit ?? null,
      lab_rules: delta.lab_rules ?? null,
      refused_because: delta.refused_because,
      counts: delta.counts,
      moved: delta.steps
        .filter((step) => step.result === "better" || step.result === "worse" || step.result === "changed")
        .slice(0, MOVED_LISTED)
        .map(({ id, role, title, technique, result, before: was, after: now, price }) => ({ id, role, title, technique, result, before: was, after: now, ...(price === undefined ? {} : { price }) })),
      before: delta.before,
      after: delta.after,
      recordings: { before, after },
      origin: origin(delta, runUrl),
    },
  };
}

let pairs: Promise<DeltaEntry[]> | undefined;

/** The shipped pairs with their list entries, loaded once when they are first asked for. */
export function shippedPairs(): Promise<DeltaEntry[]> {
  if (!pairs) pairs = Promise.all(DELTAS.map(async ([path, read]) => load(path, await read())));
  return pairs;
}
