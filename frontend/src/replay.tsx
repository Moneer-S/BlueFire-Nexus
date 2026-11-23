// The single replay page: reads the recording held in the page itself and
// plays it. Nothing is fetched. The address can say where to start:
// ?step=<step id>&at=<0..1>&paused=1&mode=watch|analyse&select=<step id>

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./replay.css";
import { LiveView } from "./live/LiveView";
import type { LiveViewProps } from "./live/LiveView";
import { LiveViewBoundary } from "./live/LiveViewBoundary";
import { RecordingError, readRecording } from "./live/recording";
import type { Recording } from "./live/recording";

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
    return { recording: readRecording(value) };
  } catch (error) {
    if (error instanceof RecordingError) return { problem: error.message, empty: false };
    return { problem: `The recording in this page could not be checked: ${error instanceof Error ? error.message : "an unknown failure"}.`, empty: false };
  }
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
  if ("recording" in page) document.title = `${page.recording.title}: BlueFire replay`;
  createRoot(root).render(
    <StrictMode>
      {"recording" in page ? (
        <LiveViewBoundary fallback={(message) => <Problem title="This recording cannot be played" text={message} />}>
          <LiveView recording={page.recording} initial={readAddress()} />
        </LiveViewBoundary>
      ) : (
        <Problem title={page.empty ? "No recording here" : "This recording cannot be played"} text={page.problem} />
      )}
    </StrictMode>,
  );
}
