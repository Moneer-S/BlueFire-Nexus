// The single replay page: reads the recording held in the page itself and
// plays it, with the note on where the recording comes from that the page
// holds beside it. Nothing is fetched. The address can say where to start:
// ?step=<step id>&at=<0..2>&paused=1&mode=watch|analyse&select=<step id>

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./replay.css";
import { LiveView } from "./live/LiveView";
import type { LiveViewProps, OriginKind } from "./live/LiveView";
import { LiveViewBoundary } from "./live/LiveViewBoundary";
import { plainMarks } from "./live/format";
import { RecordingError, firstView, readRecording } from "./live/recording";
import type { Recording } from "./live/recording";

/** The recording the page holds, as it is played: one with defenses as its first defense judged the run. */
function readPage(): { recording: Recording } | { problem: string; empty: boolean } {
  const holder = document.getElementById("bluefire-recording");
  const text = holder?.textContent?.trim() ?? "";
  if (text === "" || text === "null") return { problem: "This page holds no recording. It is the template of the replay page: a recording is put into it to make a replay.", empty: true };
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    if (error instanceof SyntaxError) return { problem: "The recording in this page is not valid JSON.", empty: false };
    return { problem: "The recording in this page could not be read.", empty: false };
  }
  try {
    return { recording: firstView(readRecording(value)) };
  } catch (error) {
    if (error instanceof RecordingError) return { problem: error.message, empty: false };
    return { problem: `The recording in this page could not be checked: ${error instanceof Error ? error.message : "an unknown failure"}.`, empty: false };
  }
}

const NO_ORIGIN = "This page does not say where its recording comes from.";

/** The kinds of origin a page can hold: the app's own two, and the lab's, whose workflow writes the page of each run it records. */
const ORIGINS = new Set(["shipped", "imported", "lab run"]);

/** Where the recording comes from, as the command that made the page wrote it: the app's note on a shipped or an imported recording, or the lab's on the CI run that made it. */
function readOrigin(): { kind: string | null; note: string } {
  const text = document.getElementById("bluefire-origin")?.textContent?.trim() ?? "";
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { kind: null, note: NO_ORIGIN };
  }
  if (typeof value !== "object" || value === null || !("kind" in value) || !("note" in value)) return { kind: null, note: NO_ORIGIN };
  if (typeof value.kind !== "string" || !ORIGINS.has(value.kind) || typeof value.note !== "string" || value.note.trim() === "") return { kind: null, note: NO_ORIGIN };
  return { kind: value.kind, note: value.note };
}

/**
 * What the page plays, and the line it shows under the title. The CI run an
 * imported file names is only what the file says, as it is in the app: the
 * page does not link it as the run that made the recording, and says that the
 * file names it and BlueFire could not confirm it. A page that does not say
 * where its recording comes from is read the same way.
 */
function shown(recording: Recording, origin: { kind: string | null; note: string }): { recording: Recording; origin: string; originKind: OriginKind } {
  const claimed = recording.source.run_url;
  const originKind: OriginKind = origin.kind === "shipped" || origin.kind === "lab run" || origin.kind === "imported" ? origin.kind : "unsaid";
  if (origin.kind === "shipped" || origin.kind === "lab run" || claimed === undefined) return { recording, origin: origin.note, originKind };
  const source = { ...recording.source };
  delete source.run_url;
  return { recording: { ...recording, source }, origin: `${origin.note} The file names this CI run, which BlueFire cannot confirm: ${plainMarks(claimed)}`, originKind };
}

function readAddress(): NonNullable<LiveViewProps["initial"]> {
  const query = new URLSearchParams(window.location.search);
  const initial: NonNullable<LiveViewProps["initial"]> = {};
  const step = query.get("step");
  if (step) initial.step = step;
  const at = Number(query.get("at"));
  if (query.has("at") && Number.isFinite(at)) initial.at = at;
  if (query.get("paused") === "1") initial.paused = true;
  const mode = query.get("mode");
  if (mode === "watch" || mode === "analyse") initial.mode = mode;
  const select = query.get("select");
  if (select) initial.select = select;
  return initial;
}

function Problem({ title, text }: { title: string; text: string }) {
  return (
    <div className="replay-empty">
      <div>
        <h1>{title}</h1>
        <p>{text}</p>
      </div>
    </div>
  );
}

const root = document.getElementById("root");
if (root) {
  const page = readPage();
  const view = "recording" in page ? shown(page.recording, readOrigin()) : null;
  if (view) document.title = `${plainMarks(view.recording.title)}: BlueFire replay`;
  createRoot(root).render(
    <StrictMode>
      {view ? (
        <LiveViewBoundary fallback={(message) => <Problem title="This recording cannot be played" text={message} />}>
          <LiveView recording={view.recording} origin={view.origin} originKind={view.originKind} initial={readAddress()} />
        </LiveViewBoundary>
      ) : "problem" in page ? (
        <Problem title={page.empty ? "No recording here" : "This recording cannot be played"} text={page.problem} />
      ) : null}
    </StrictMode>,
  );
}
