import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "../src/lib/api";
import { readRecording } from "../src/live/recording";

const summary = {
  id: "lab-run-1",
  title: "60 published tests on one Linux host",
  kind: "test list",
  source: { engine: "bluefire-lab", environment: "GitHub-hosted runner", started: "2026-11-23T17:25:50Z", finished: "2026-11-23T17:36:23Z" },
  score: { steps: 60, took_effect: 60, alerted: 3, seen: 56, unseen: 1, stopped: 8 },
  counts: { steps: 91, events: 1931, alerts: 233 },
  origin: { kind: "imported", note: "Imported. BlueFire checked that this file follows the recording format." },
  running: false,
  digest: "sha256:abc",
};

function answer(status: number, body: unknown) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(body), { status }));
}

describe("the recordings in the service's client", () => {
  it("lists the service's recordings, and counts an entry it cannot read as unreadable instead of dropping it silently", async () => {
    const fetch = answer(200, { schema_version: "bluefire.recording-list.v1", recordings: [summary, { id: "no title" }], unreadable_count: 1, omitted_count: 0 });
    const list = await api.recordings();
    expect(fetch.mock.calls[0]?.[0]).toBe("/api/v1/recordings");
    expect(list.recordings.map((item) => item.title)).toEqual(["60 published tests on one Linux host"]);
    expect(list.recordings[0]?.origin).toEqual(summary.origin);
    expect(list.unreadable_count).toBe(2);
  });

  it("refuses a list that is not the service's list of recordings", async () => {
    answer(200, { recordings: "none" });
    await expect(api.recordings()).rejects.toMatchObject({ code: "invalid_recording_list" });
  });

  it("returns one whole recording with its list entry", async () => {
    const fetch = answer(200, { schema_version: "bluefire.recording-entry.v1", summary, recording: { schema: "bluefire.recording/1" } });
    const entry = await api.recording("lab-run-1");
    expect(fetch.mock.calls[0]?.[0]).toBe("/api/v1/recordings/lab-run-1");
    expect(entry.summary.title).toBe(summary.title);
    expect(entry.recording).toEqual({ schema: "bluefire.recording/1" });
  });

  it("asks for nothing with an id the service would refuse", async () => {
    const fetch = answer(200, {});
    await expect(api.recording("../runs")).rejects.toMatchObject({ code: "invalid_recording_id", status: 400 });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("imports a recording file as the bytes it holds, and passes on a refusal with every problem the service named", async () => {
    const fetch = answer(201, { created: true, replaced: false, summary });
    // As the lab writes it: indented, with a character outside ASCII, so a file that was parsed and written again would differ.
    const file = new TextEncoder().encode('{\n "schema": "bluefire.recording/1",\n "id": "lab-run-1",\n "title": "Résumé"\n}\n');
    const result = await api.importRecording(file);
    expect(result.summary.id).toBe("lab-run-1");
    const [url, options] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("/api/v1/recordings");
    expect(options?.method).toBe("POST");
    const sent = (init: RequestInit | undefined) => {
      const body = JSON.parse(String(init?.body)) as { recording_file: string };
      expect(Object.keys(body)).toEqual(["recording_file"]);
      return Array.from(atob(body.recording_file), (character) => character.charCodeAt(0));
    };
    expect(sent(options)).toEqual(Array.from(file));

    // A byte order mark, a key twice and a NaN: the service is to see them, as the command line does.
    const odd = answer(201, { created: true, replaced: false, summary });
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"id": "lab-run-1", "id": "again", "n": NaN}')]);
    await api.importRecording(bytes);
    expect(sent(odd.mock.lastCall?.[1])).toEqual(Array.from(bytes));

    answer(422, { error: { code: "recording_invalid", message: "The recording is not valid: score.alerted is 2, but the steps give 1.", details: { problems: ["score.alerted is 2, but the steps give 1.", "score.seen is 1, but the steps give 0."] } } });
    const refusal = await api.importRecording(new TextEncoder().encode("{}")).catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(ApiError);
    expect(refusal).toMatchObject({ status: 422, code: "recording_invalid", message: "The recording is not valid: score.alerted is 2, but the steps give 1." });
    expect((refusal as ApiError).details).toEqual({ problems: ["score.alerted is 2, but the steps give 1.", "score.seen is 1, but the steps give 0."] });
  });
});

describe("the recordings in the demo build", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  // These read and parse the three shipped recordings, about 1.1 MB each, which takes seconds on a busy machine.
  const SHIPPED_FILES_TIMEOUT = 30_000;

  async function demoApi() {
    vi.stubEnv("VITE_DEMO_MODE", "true");
    vi.resetModules();
    return (await import("../src/lib/api")).api;
  }

  it("gives the real recordings that ship with the app, labelled as the service labels them", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    const demo = await demoApi();
    const list = await demo.recordings();
    expect(list).toMatchObject({ unreadable_count: 0, omitted_count: 0 });
    // The example, the two runs of the shipped pair, and the run evaluated twice, once by its first file.
    expect(list.recordings).toHaveLength(4);
    expect(new Set(list.recordings.map((item) => item.id)).size).toBe(4);
    expect(list.recordings.every((item) => item.origin.kind === "shipped")).toBe(true);
    const shipped = list.recordings.find((item) => item.score.unseen === 1 && item.source.run_url?.endsWith("/45227119895"));
    expect(shipped).toMatchObject({
      title: "60 published tests on one Linux host",
      kind: "test list",
      running: false,
      score: { steps: 60, took_effect: 60, alerted: 3, seen: 56, unseen: 1 },
      counts: { steps: 91 },
      source: { environment: "GitHub-hosted runner" },
    });
    expect(shipped?.origin.kind).toBe("shipped");
    const runUrl = shipped?.origin.kind === "shipped" ? shipped.origin.run_url : "";
    expect(runUrl).toMatch(/^https:\/\/github\.com\/.+\/actions\/runs\/\d+$/);
    expect(runUrl).toBe(shipped?.source.run_url);
    expect(shipped?.origin.note).toBe(`Shipped with BlueFire. This repository's lab workflow recorded it in the CI run at ${runUrl}. BlueFire checked that it follows the recording format and that its parts agree with each other.`);

    // Each list entry, which the build worked out of its file, says what the recording itself holds.
    for (const item of list.recordings) {
      const whole = readRecording((await demo.recording(item.id)).recording);
      expect(item).toEqual({
        id: whole.id, title: whole.title, kind: whole.kind,
        source: { engine: whole.source.engine, environment: whole.source.environment, started: whole.source.started, finished: whole.source.finished, run_url: whole.source.run_url, commit: whole.source.commit },
        score: whole.score,
        counts: { steps: whole.steps.length, events: whole.events.length, alerts: whole.alerts.length },
        origin: item.origin,
        running: false,
      });
    }
    const entry = await demo.recording(shipped?.id ?? "");
    expect(readRecording(entry.recording).steps).toHaveLength(91);
    await expect(demo.recording("not-shipped")).rejects.toMatchObject({ code: "recording_not_found", status: 404 });
    await expect(demo.importRecording(new TextEncoder().encode(JSON.stringify(entry.recording)))).rejects.toMatchObject({ code: "demo_recording_import_refused" });
    expect(fetch).not.toHaveBeenCalled();
  }, SHIPPED_FILES_TIMEOUT);

  it("gives the pair of runs that ships with the app, at the service's address, labelled as the service labels it", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    const demo = await demoApi();
    const { deltas } = await demo.recordingDeltas();
    expect(deltas).toHaveLength(2);
    const pair = deltas.find((item) => item.runners === 2);
    // The id the service gives this delta file, so an address of the pair is the same in both.
    expect(pair?.id).toBe("c4f1640a7f3ad9f0"); // pragma: allowlist secret
    const runUrl = "https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45365902367";
    expect(pair?.origin).toEqual({ kind: "shipped", run_url: runUrl, note: `Shipped with BlueFire, with both of its recordings. This repository's lab workflow made the two runs side by side, and this comparison of them, in the CI run at ${runUrl}. BlueFire checked that the comparison follows the delta format and names both recordings by the SHA-256 of their files, with every step it lists. It did not make the comparison: bluefire-lab compare did.` });
    expect(pair?.recordings.before.id).toBe(pair?.before.id);
    expect(pair?.recordings.after.origin.kind).toBe("shipped");
    const entry = await demo.recordingDelta(pair?.id ?? "");
    expect(entry.delta.schema).toBe("bluefire.delta/1");
    expect(entry.delta.declared_change).toBe("sensors:auditd");
    expect(entry.delta.limit).toBeNull();
    const step = await demo.recording(entry.delta.after.id);
    expect(readRecording(step.recording).id).toBe(entry.delta.after.id);
    await expect(demo.recordingDelta("0000000000000000")).rejects.toMatchObject({ code: "delta_not_found", status: 404 });
    expect(fetch).not.toHaveBeenCalled();
  }, SHIPPED_FILES_TIMEOUT);

  it("gives the run evaluated with two rule sets, each evaluation by its own file under the run's one id", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    const demo = await demoApi();
    const pair = (await demo.recordingDeltas()).deltas.find((item) => item.one_run === true);
    // The id the service gives this delta file.
    expect(pair?.id).toBe("c2ab518a2b6e0e9f"); // pragma: allowlist secret
    const runUrl = "https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682";
    expect(pair?.origin).toEqual({ kind: "shipped", run_url: runUrl, note: `Shipped with BlueFire, with both of its recordings. This repository's lab workflow ran the list once, evaluated its telemetry with two sets of the lab's rules, and compared the two, in the CI run at ${runUrl}. BlueFire checked that the comparison follows the delta format, names both recordings by the SHA-256 of their files with every step it lists, and that the two are one run. It did not make the comparison: bluefire-lab compare did.` });
    expect(pair?.lab_rules?.map((row) => [row.title, row.change])).toEqual([["Shell History File Truncated In Place", "new"]]);
    expect(pair?.moved?.map((step) => step.title)).toEqual(["Clear Bash history (echo)", "Clear Bash history (cat dev/null)", "Clear Bash history (echo)", "Clear Bash history (cat dev/null)"]);
    if (!pair) throw new Error("The demo should ship the run evaluated twice.");
    expect(pair.before.id).toBe(pair.after.id);
    // Each side's list entry is its own file's: the lab's rules alerted on two more tests after.
    expect(pair.recordings.before.score.alerted_with_lab_rules).toBe(17);
    expect(pair.recordings.after.score.alerted_with_lab_rules).toBe(19);
    const after = readRecording((await demo.recordingFile(pair.after.id, pair.after.sha256)).recording);
    const before = readRecording((await demo.recordingFile(pair.before.id, pair.before.sha256)).recording);
    expect(after.network.detectors.find((item) => item.id === "lab")?.verdicts?.some((item) => item.title === "Shell History File Truncated In Place")).toBe(true);
    expect(before.network.detectors.find((item) => item.id === "lab")?.verdicts?.some((item) => item.title === "Shell History File Truncated In Place")).toBe(false);
    await expect(demo.recordingFile(pair.after.id, "0".repeat(64))).rejects.toMatchObject({ code: "recording_file_not_found", status: 404 });
    expect(fetch).not.toHaveBeenCalled();
  }, SHIPPED_FILES_TIMEOUT);
});
