// The list entries of the recordings shipped with BlueFire, worked out when a
// build is made, so that the demo build lists them without loading any of them
// whole. Each entry has the keys the service's list route gives a recording
// (`summarize` in bluefire/recordings.py), apart from its digest, which the
// interface does not read. The demo loads a recording itself only when it is
// opened, and reads it then as the live view reads every recording.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Plugin } from "vite";

const MODULE = "virtual:shipped-recording-summaries";
const RESOLVED = `\0${MODULE}`;
const FOLDER = fileURLToPath(new URL("../bluefire/data/recordings/", import.meta.url));

/** The service's note for a shipped recording (`SHIPPED_NOTE` in bluefire/recordings.py). */
const SHIPPED_NOTE = "Shipped with BlueFire. A workflow of this repository recorded it in the CI run at {run_url}. BlueFire checked that it follows the recording format and that its parts agree with each other.";
const SOURCE_KEYS = ["engine", "environment", "started", "finished", "run_url", "commit"] as const;

type Json = Record<string, unknown>;

function object(value: unknown, what: string): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${what} is not an object.`);
  return value as Json;
}

function list(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${what} is not a list.`);
  return value;
}

/** One shipped file's list entry, as the service gives it. */
function summary(file: string, text: string): Json {
  const recording = object(JSON.parse(text), file);
  const source = object(recording.source, `The source of ${file}`);
  const runUrl = source.run_url;
  // The service refuses to ship a recording that does not name its finished CI run.
  if (typeof runUrl !== "string" || typeof source.finished !== "string") throw new Error(`${file} does not name its finished CI run.`);
  return {
    id: recording.id,
    title: recording.title,
    kind: recording.kind,
    source: Object.fromEntries(SOURCE_KEYS.filter((key) => key in source).map((key) => [key, source[key]])),
    score: { ...object(recording.score, `The score of ${file}`) },
    counts: {
      steps: list(recording.steps, `The steps of ${file}`).length,
      events: list(recording.events, `The events of ${file}`).length,
      alerts: list(recording.alerts, `The alerts of ${file}`).length,
    },
    origin: { kind: "shipped", run_url: runUrl, note: SHIPPED_NOTE.replace("{run_url}", runUrl) },
    running: false,
  };
}

/**
 * Every shipped file's list entry with its file's name and SHA-256, in the order
 * of the names. The service lists the first file of each id; a later file of the
 * same id is another evaluation of that run, returned by its SHA-256.
 */
export function shippedSummaries(): { file: string; sha256: string; summary: Json }[] {
  return readdirSync(FOLDER)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((file) => {
      const bytes = readFileSync(`${FOLDER}${file}`);
      return { file, sha256: createHash("sha256").update(bytes).digest("hex"), summary: summary(file, bytes.toString("utf-8")) };
    });
}

/** Gives `virtual:shipped-recording-summaries`: the entries of shippedSummaries(), worked out once per build. */
export function shippedSummariesPlugin(): Plugin {
  return {
    name: "bluefire-shipped-recording-summaries",
    resolveId(source) {
      return source === MODULE ? RESOLVED : null;
    },
    load(id) {
      if (id !== RESOLVED) return null;
      const entries = shippedSummaries();
      for (const { file } of entries) this.addWatchFile(`${FOLDER}${file}`);
      return `export default ${JSON.stringify(entries)};\n`;
    },
  };
}
