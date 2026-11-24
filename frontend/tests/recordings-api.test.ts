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

/** The bytes of what was sent, read as a browser reads a file. */
function bytesOf(blob: unknown): Promise<number[]> {
  return new Promise((resolve, reject) => {
    if (!(blob instanceof Blob)) return reject(new Error("nothing was sent"));
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result instanceof ArrayBuffer ? [...new Uint8Array(reader.result)] : []);
    reader.onerror = () => reject(reader.error ?? new Error("unreadable"));
    reader.readAsArrayBuffer(blob);
  });
}

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

  it("imports a recording file as its own bytes, and passes on a refusal with every problem the service named", async () => {
    const fetch = answer(201, { created: true, replaced: false, summary });
    // A byte order mark and a key twice: the service is to see them, as the command line does.
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"id": "lab-run-1", "id": "again", "n": NaN}')]);
    const result = await api.importRecording(new Blob([bytes]));
    expect(result.summary.id).toBe("lab-run-1");
    const [url, options] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("/api/v1/recordings");
    expect(options?.method).toBe("POST");
    expect(new Headers(options?.headers).get("Content-Type")).toBe("application/json");
    const prefix = new TextEncoder().encode('{"recording":');
    expect(await bytesOf(options?.body)).toEqual([...prefix, ...bytes, "}".charCodeAt(0)]);

    answer(422, { error: { code: "recording_invalid", message: "The recording is not valid: score.alerted is 2, but the steps give 1.", details: { problems: ["score.alerted is 2, but the steps give 1.", "score.seen is 1, but the steps give 0."] } } });
    const refusal = await api.importRecording(new Blob(["{}"])).catch((error: unknown) => error);
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

  async function demoApi() {
    vi.stubEnv("VITE_DEMO_MODE", "true");
    vi.resetModules();
    return (await import("../src/lib/api")).api;
  }

  it("gives the one real example that ships with the app, labelled as the service labels it", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    const demo = await demoApi();
    const list = await demo.recordings();
    expect(list).toMatchObject({ unreadable_count: 0, omitted_count: 0 });
    expect(list.recordings).toHaveLength(1);
    const shipped = list.recordings[0];
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

    const entry = await demo.recording(shipped?.id ?? "");
    expect(readRecording(entry.recording).steps).toHaveLength(91);
    await expect(demo.recording("not-shipped")).rejects.toMatchObject({ code: "recording_not_found", status: 404 });
    await expect(demo.importRecording(new Blob([JSON.stringify(entry.recording)]))).rejects.toMatchObject({ code: "demo_recording_import_refused" });
    expect(fetch).not.toHaveBeenCalled();
  });
});
