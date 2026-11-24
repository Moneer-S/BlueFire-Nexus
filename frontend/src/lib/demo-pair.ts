// The demo build's pair of runs. It is BUILT, not a result, and its file says
// so in its "built" key: two recordings of this repository's lab runs in CI, the
// after one changed by hand, compared by `bluefire-lab compare`. The demo shows
// it so that the page of a pair can be seen without the service; neither of its
// recordings is kept in the demo. Only the demo build loads this module.

import pairText from "./demo-pair.json?raw";
import { readDeltaEntry, type DeltaEntry } from "./api";

let pair: DeltaEntry | undefined;

export function builtPair(): DeltaEntry {
  if (!pair) {
    const value: unknown = JSON.parse(pairText);
    const built = value && typeof value === "object" && "built" in value ? value.built : undefined;
    if (typeof built !== "string") throw new Error("The demo pair does not say that it is built.");
    const entry = readDeltaEntry(value);
    pair = { delta: entry.delta, summary: { ...entry.summary, origin: { kind: "built", note: built } } };
  }
  return pair;
}
