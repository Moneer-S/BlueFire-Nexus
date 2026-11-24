// Small hand-built recordings for the live view's logic tests.
import type { Alert, Recording, RecordingEvent, Step } from "../src/live/recording";

const base = Date.parse("2026-01-01T10:00:00.000Z");

/** A recording time `seconds` after the fixture's start. */
export function at(seconds: number): string {
  return new Date(base + Math.round(seconds * 1000)).toISOString();
}

export function step(id: string, from: number | null, to: number | null, extra: Partial<Step> = {}): Step {
  return {
    id,
    order: Number(id) || 1,
    role: "test",
    title: `Test ${id}`,
    technique: { id: "T1000" },
    host: "target",
    ...(from === null ? {} : { started: at(from) }),
    ...(to === null ? {} : { ended: at(to) }),
    happened: { answer: "took effect", basis: "the test ran" },
    visibility: { answer: "telemetry only", basis: "events", events: 0 },
    outcome: "seen",
    ...extra,
  };
}

export function event(id: string, stepId: string, seconds: number): RecordingEvent {
  return { id, time: at(seconds), host: "target", sensor: "sysmon", kind: "process start", text: `run ${id}`, step: stepId, tied_by: "session" };
}

export function alert(id: string, stepId: string, seconds: number, events: string[], extra: Partial<Alert> = {}): Alert {
  return {
    id,
    time: at(seconds),
    host: "target",
    detector: "pinned",
    rule: { id: `rule-${id}`, title: `Rule ${id}`, level: "high", origin: "pinned" },
    counts: true,
    step: stepId,
    events,
    ...extra,
  };
}

export function recording(parts: { steps: Step[]; events?: RecordingEvent[]; alerts?: Alert[]; when?: "live" | "after the run" }): Recording {
  return {
    schema: "bluefire.recording/1",
    id: "fixture",
    title: "A few hand-built steps",
    kind: "test list",
    source: { engine: "fixture", environment: "tests", started: at(0), finished: at(600), tools: [] },
    network: {
      hosts: [{ id: "target", name: "Target", role: "Linux host under test", kind: "host" }],
      sensors: [{ id: "sysmon", name: "Sysmon", host: "target", records: "process starts" }],
      detectors: [
        { id: "pinned", name: "Published rules", rules: 10, when: parts.when ?? "after the run" },
        { id: "lab", name: "Lab rules", rules: 2, when: parts.when ?? "after the run" },
      ],
    },
    attacker: { kind: "scripted", description: "A script", goal: null },
    steps: parts.steps,
    events: parts.events ?? [],
    alerts: parts.alerts ?? [],
    score: { steps: parts.steps.filter((item) => item.role === "test").length, took_effect: 0, alerted: 0, seen: 0, unseen: 0, stopped: 0 },
    notes: [],
  };
}
