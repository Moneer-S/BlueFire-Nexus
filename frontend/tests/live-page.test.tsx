import { fireEvent, render, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import type { LiveViewProps } from "../src/live/LiveView";
import { buildTimeline } from "../src/live/playback";
import type { Timeline } from "../src/live/playback";
import { countsForScore, type Recording } from "../src/live/recording";
import { Scrubber } from "../src/live/Scrubber";
import { alert, at, event, recording, step } from "./live-fixture";

afterEach(() => {
  vi.restoreAllMocks();
});

function open(value: Recording, initial: LiveViewProps["initial"]) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={initial} />);
}

const texts = (root: ParentNode, selector: string) => [...root.querySelectorAll(selector)].map((node) => node.textContent?.trim() ?? "");

describe("several late arrivals fired at once", () => {
  // The alerts of tests 1, 2 and 3 are all raised live at 20 s, while test 4 runs.
  const value = recording({
    when: "live",
    steps: [1, 2, 3].map((n) => step(String(n), n, n + 0.5, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } })).concat([step("4", 18, 25)]),
    events: [event("1-1", "1", 1.1), event("2-1", "2", 2.1), event("3-1", "3", 3.1), event("4-1", "4", 18.5)],
    alerts: [1, 2, 3].map((n) => alert(`a${n}`, String(n), n + 0.1, [`${n}-1`], { raised: at(20) })),
  });

  it("names every one of them under the step, in the log and on the engine, never fewer than the score counts", () => {
    const timeline = buildTimeline(value);
    const fire = timeline.fire.get("a1") ?? Number.NaN;
    const four = timeline.segments[3];
    if (!four) throw new Error("fixture");
    const { container, unmount } = open(value, { step: "4", at: (fire + 0.2 - four.start) / (four.end - four.start), paused: true });
    const late = container.querySelector(".lv-late")?.textContent ?? "";
    for (const rule of ["Rule a1", "Rule a2", "Rule a3"]) expect(late).toContain(rule);
    expect(late).toMatch(/^3 alerts raised after their steps ended/);
    const log = container.querySelector(".lv-log")?.textContent ?? "";
    for (const rule of ["Rule a1", "Rule a2", "Rule a3"]) expect(log).toContain(rule);
    const engine = container.querySelector(".lv-match--late");
    expect(engine?.textContent).toContain("2 more after their steps");
    for (const rule of ["Rule a1", "Rule a2", "Rule a3"]) expect(engine?.getAttribute("title")).toContain(rule);
    expect(container.querySelector(".lv-score-lead b")?.textContent).toBe("3");
    unmount();
  });

  it("draws twenty thousand of them on one engine without stalling, and names the newest in a tooltip of readable size", () => {
    // Every alert of test 1 is raised live at 20 s, while test 2 runs: the importer takes 20,000 alerts.
    const many = recording({
      when: "live",
      steps: [step("1", 1, 2, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }), step("2", 18, 25)],
      events: [event("1-1", "1", 1.5), event("2-1", "2", 18.5)],
      alerts: Array.from({ length: 20_000 }, (_, n) => alert(`a${n}`, "1", 1.5, ["1-1"], { raised: at(20) })),
    });
    const timeline = buildTimeline(many);
    const fire = timeline.fire.get("a0") ?? Number.NaN;
    const two = timeline.segments[1];
    if (!two) throw new Error("fixture");
    const started = performance.now();
    const { container, unmount } = open(many, { step: "2", at: (fire + 0.2 - two.start) / (two.end - two.start), paused: true });
    const took = performance.now() - started;
    const engine = container.querySelector(".lv-match--late");
    // Nothing is counted short: the engine says how many more were raised after their steps.
    expect(engine?.textContent).toContain("19999 more after their steps");
    // The tooltip names the newest and counts the rest: it does not grow with every arrival.
    const title = engine?.getAttribute("title") ?? "";
    expect(title).toContain("earlier ones, then");
    expect(title.length).toBeLessThan(5_000);
    // A copy of the names for every arrival took seven seconds here; one list takes well under one.
    expect(took).toBeLessThan(4_000);
    unmount();
  }, 60_000);
});

describe("the page's address", () => {
  const value = recording({ steps: [step("a", 10, 11), step("b", 20, 21), step("c", 30, 31)] });
  // The line, its tooltip, and whether a screen reader is told it.
  const notice = (container: HTMLElement) => {
    const found = container.querySelector(".lv-address");
    return found ? { line: found.textContent, full: found.getAttribute("title"), status: found.getAttribute("role") === "status" } : null;
  };

  it("says in one line when it names a step the recording does not hold, in watch mode", () => {
    const { container, unmount } = open(value, { step: "nope", paused: true });
    expect(notice(container)).toEqual({ line: 'Step "nope" is not in this recording.', full: 'The page\'s address names step "nope", which this recording does not hold, so the view opened at the start of the run.', status: true });
    unmount();
  });

  it("says so in analyse mode too, and opens on the whole run", () => {
    const { container, unmount } = open(value, { mode: "analyse", select: "nope" });
    expect(notice(container)).toEqual({ line: 'Step "nope" is not in this recording.', full: 'The page\'s address names step "nope", which this recording does not hold, so analyse mode opened on the whole run.', status: true });
    expect(within(container).getByRole("article", { name: "The whole run" })).toBeTruthy();
    unmount();
  });

  it("says nothing when every step it names is there", () => {
    const { container, unmount } = open(value, { step: "b", paused: true });
    expect(notice(container)).toBeNull();
    unmount();
  });
});

describe("analyse mode of a network with the same sensor on several hosts", () => {
  it("names each sensor's host in its lane and its column, so their counts can be told apart", () => {
    const base = recording({
      steps: [step("1", 1, 2, { host: "web", outcome: "seen", visibility: { answer: "telemetry only", basis: "recorded", events: 2 } })],
      events: [{ ...event("1-1", "1", 1.1), host: "web", sensor: "agent-web" }, { ...event("1-2", "1", 1.2), host: "db", sensor: "agent-db" }],
    });
    const value: Recording = {
      ...base,
      network: {
        ...base.network,
        hosts: [{ id: "web", name: "web", role: "web application", kind: "host" }, { id: "db", name: "db", role: "database", kind: "host" }],
        sensors: [
          { id: "agent-web", name: "Wazuh agent 4.14.10", host: "web", records: "log lines" },
          { id: "agent-db", name: "Wazuh agent 4.14.10", host: "db", records: "log lines" },
        ],
      },
    };
    // The table looks again for the chosen row once the page's font has loaded, which this test's document has no word of.
    Object.defineProperty(document, "fonts", { value: { ready: Promise.resolve() }, configurable: true });
    const { container, unmount } = open(value, { mode: "analyse", select: "1" });
    expect(texts(container, ".lv-ln-label.is-sensor")).toEqual(["Wazuh agent on web", "Wazuh agent on db"]);
    // The step ran on web; db's agent recorded one of its events too, and the detail counts both.
    expect(texts(container, ".lv-dt-sensors li")).toEqual(["Wazuh agent on web1 event", "Wazuh agent on db1 event"]);
    const columns = [...container.querySelectorAll("thead th.is-num")].map((cell) => ({ text: cell.textContent?.trim(), title: cell.getAttribute("title") }));
    expect(columns).toEqual(expect.arrayContaining([
      { text: "web", title: "The step's events from Wazuh agent on web that the recording keeps" },
      { text: "db", title: "The step's events from Wazuh agent on db that the recording keeps" },
    ]));
    unmount();
  });
});

describe("analyse mode of a recording without tests", () => {
  it("opens the table on every step, with All pressed and each row shown", () => {
    const value = recording({
      steps: [step("1", 1, 2, { role: "canary", outcome: "alerted" }), step("2", 3, 4, { role: "control", outcome: "unseen", visibility: { answer: "no telemetry", basis: "none", events: 0 } })],
    });
    const { container, unmount } = open(value, { mode: "analyse" });
    const roles = within(container).getByRole("group", { name: "Role" });
    expect(within(roles).getByRole("button", { name: /All/ }).getAttribute("aria-pressed")).toBe("true");
    expect(container.querySelectorAll("tr[data-step]")).toHaveLength(2);
    expect(container.textContent).not.toContain("No step has this role and outcome.");
    expect(container.querySelector(".lv-filter-count")?.textContent).toBe("2 of 2");
    unmount();
  });

  it("reads as English for a run of one step", () => {
    const value = recording({ steps: [step("1", 1, 2, { role: "canary", outcome: "alerted" })] });
    const { container, unmount } = open(value, { mode: "analyse" });
    expect(within(container).getByRole("group", { name: "Outcomes of the one step" })).toBeTruthy();
    expect(texts(container, ".lv-chips-scope")).toEqual(["the one step:"]);
    unmount();
  });
});

describe("one name for a step, and the recording's own words, on every part of the screen", () => {
  const lab = "nothing of the test was recorded besides its launcher's start";
  const base = recording({
    steps: [
      step("canary:a", 1, 2, { role: "canary", outcome: "alerted", technique: { id: "T1070.003" } }),
      step("control:b", 3, 4, { role: "control", outcome: "seen", visibility: { answer: "telemetry only", basis: "recorded", events: 1 } }),
      step("test:cc", 5, 6, { outcome: "seen", visibility: { answer: "telemetry only", basis: "recorded", events: 1 }, technique: { id: "T1082" } }),
      step("test:dd", 7, 8, { outcome: "unseen", visibility: { answer: "no telemetry", basis: lab, events: 0 }, technique: { id: "T1070.003" }, command: "sh -c cp x /tmp/\u202Etxt.exe", output: "done\u2067" }),
      step("hardened:cc", 9, 10, { role: "hardened", outcome: "seen", compared_with: "test:cc", visibility: { answer: "telemetry only", basis: "recorded", events: 1 }, technique: { id: "T1082" } }),
    ],
    events: [event("c-1", "control:b", 3.1), event("t-1", "test:cc", 5.1), event("h-1", "hardened:cc", 9.1)],
    alerts: [alert("info", "test:cc", 5.1, ["t-1"], { counts: false, rule: { id: "r-info", title: "Informational rule", level: "informational", origin: "pinned" } })],
  });
  const value: Recording = { ...base, ordinary: { events: 100, matches: [{ rule: "Binary Padding", level: "high", count: 3 }] }, score: { ...base.score, steps: 2, took_effect: 2, alerted: 0, seen: 1, unseen: 1, stopped: 0, false_alerts: 1 } };

  it("names each row of the table, its detail and the summary's reruns as the captions do, and shows the id an address takes", () => {
    // The table looks again for the chosen row once the page's font has loaded, which this test's document has no word of.
    Object.defineProperty(document, "fonts", { value: { ready: Promise.resolve() }, configurable: true });
    const { container, unmount } = open(value, { mode: "analyse", select: "test:dd" });
    // Among the tests, a row is its test's number; among every step, each is named by its role, as the captions name it.
    expect(texts(container, "tr[data-step] td.is-n").sort()).toEqual(["1", "2"]);
    expect(texts(container, "thead th.is-n")).toEqual(["Test"]);
    fireEvent.click(within(within(container).getByRole("group", { name: "Role" })).getByRole("button", { name: /All/ }));
    expect(texts(container, "tr[data-step] td.is-n").sort()).toEqual(["canary", "control", "rerun of test 1", "test 1", "test 2"]);
    expect(texts(container, "thead th.is-n")).toEqual(["Step"]);
    const detail = within(container).getByRole("article", { name: "Test 2" });
    expect(detail.textContent).toContain("4 of 5 steps");
    expect(detail.textContent).toContain("id test:dd");
    expect(detail.textContent).not.toMatch(/step \d+ of/);
    // What the recording says of the unseen test, and why a sensor is the place to start: its one record by one name in both.
    expect(detail.querySelector(".lv-dt-why")?.textContent).toBe(`It took effect, and ${lab}.`);
    expect(detail.querySelector(".lv-dt-hint")?.textContent).toBe("Start with a sensor: its only record is its launcher's start, which never counts. Other runs of T1070.003 were recorded: the canary alerted.");
    unmount();
  });

  it("counts a test with only informational matches apart from those for review, and a false alert once however many its events", () => {
    const { container, unmount } = open(value, { mode: "analyse" });
    const summary = within(container).getByRole("article", { name: "The whole run" });
    expect(within(summary).getByText("Seen, no alert").nextElementSibling?.textContent).toBe("1 with only informational matches");
    expect(summary.textContent).toContain("1 was unseen");
    expect(summary.querySelector(".lv-sum-gap")?.textContent).toBe("The test nobody saw: Test test:dd: nothing of the test was recorded besides its launcher's start. Open it to start fixing.");
    expect(summary.textContent).toContain("1 false alert");
    // A rerun is named by the test it reruns, never by a place in the list.
    expect(summary.textContent).toContain("Not stopped: rerun of test 1");
    unmount();
  });

  it("tells the unseen test in the caption and on the map in the recording's words, and shows a direction mark of its command as a tag", () => {
    const { container, unmount } = open(value, { step: "test:dd", at: 1.5, paused: true });
    expect(container.querySelector(".lv-why")?.textContent).toBe("Nothing of the test was recorded besides its launcher's start.");
    expect(container.querySelector(".lv-silence")?.textContent).toBe("It took effect.Nothing of the test was recorded besides its launcher's start.");
    const command = container.querySelector(".lv-host-command");
    expect(command?.textContent).toBe("sh -c cp x /tmp/U+202Etxt.exe");
    expect(command?.getAttribute("title")).toBe("sh -c cp x /tmp/[U+202E]txt.exe");
    expect(container.querySelector(".lv-step-chip")?.textContent).toBe("test 2");
    // The log between them says the same, the header's count too, and the footer names the step as they do.
    expect(container.querySelector(".lv-log-none")?.textContent).toBe("Nothing of the test was recorded besides its launcher's start.");
    expect(container.querySelector(".lv-score-item.is-unseen")?.getAttribute("title")).toContain("The recording says: Nothing of the test was recorded besides its launcher's start.");
    expect(texts(container, ".lv-stepno > b:not(.lv-stepno-sizer), .lv-stepno > span")).toEqual(["Test 2", "4 of 5 steps"]);
    unmount();
    const rerun = open(value, { step: "hardened:cc", at: 1.5, paused: true });
    expect(texts(rerun.container, ".lv-stepno > b:not(.lv-stepno-sizer)")).toEqual(["Hardened rerun of test 1"]);
    rerun.unmount();
  });

  it("marks an informational match as informational, never for review, on the map and in the log", () => {
    const { container, unmount } = open(value, { step: "test:cc", at: 1.5, paused: true });
    expect(texts(container, ".lv-chip--review")).toEqual(["informational"]);
    expect(texts(container, ".lv-log-mark").filter(Boolean)).toEqual(["informational"]);
    unmount();
  });
});

describe("a finished run with no steps", () => {
  it("is told as a run that finished, not as a plan", () => {
    const base = recording({ steps: [] });
    const value: Recording = { ...base, score: { ...base.score, steps: 0, took_effect: 0, alerted: 0, seen: 0, unseen: 0, stopped: 0 } };
    const { container, unmount } = open(value, {});
    expect(container.textContent).not.toContain("A plan");
    expect(container.querySelector(".lv-prov-button")?.textContent).toMatch(/^A run, recorded \d+ \w+ \d{4} on tests /);
    expect(container.querySelector(".lv-plan-note")?.textContent).toMatch(/^This run finished with no steps/);
    unmount();
    const source = { ...value.source };
    delete source.finished;
    const running = open({ ...value, source }, {});
    expect(running.container.textContent).toContain("A plan: nothing has run on this network yet");
    running.unmount();
  });
});

describe("the attacker's goal", () => {
  it("is named in the run's summary where it is claimed, and said not to be recorded as reached without a time", () => {
    const base = recording({ steps: [step("1", 10, 20), step("2", 30, 40)] });
    const value: Recording = { ...base, kind: "attack path", attacker: { ...base.attacker, goal: "Read the domain admin's password." }, score: { ...base.score, goal_seconds: 30 } };
    const reached = open(value, { mode: "analyse" });
    const goal = within(reached.container).getByText("Goal").nextElementSibling?.textContent ?? "";
    expect(goal).toBe("Read the domain admin's password.Reached 00:30.0 into the run.");
    reached.unmount();
    const unknown = open({ ...value, score: base.score }, { mode: "analyse" });
    expect(within(unknown.container).getByText("Goal").nextElementSibling?.textContent).toBe("Read the domain admin's password.The recording does not say it was reached.");
    unknown.unmount();
  });
});

describe("the timeline's alert lane", () => {
  it("keeps an ordered pinned alert in the score lane without calling its rule published", () => {
    const title = "Ordered credential search and remote archive";
    const value = recording({
      steps: [step("6", 10, 11), step("7", 20, 21), step("8", 30, 31, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } })],
      events: [event("s06-1", "6", 10.5), event("s07-1", "7", 20.5), event("s08-1", "8", 30.5)],
      alerts: [
        alert("sequence", "8", 30.5, ["s06-1", "s07-1", "s08-1"], {
          rule: { id: "ordered-credential", title, level: "high", origin: "pinned" },
        }),
      ],
    });
    const scored = value.alerts[0];
    if (!scored) throw new Error("fixture");
    expect(countsForScore(scored)).toBe(true);

    const timeline = buildTimeline(value);
    const { container, unmount } = render(
      <Scrubber recording={value} timeline={timeline} time={timeline.duration} real={0} revealed ended onSeek={() => undefined} />,
    );
    expect(container.querySelector(".lv-lane.is-alert")).not.toBeNull();
    const hint = container.querySelector(".lv-lanes-hint")?.getAttribute("title") ?? "";
    expect(hint).toContain("Lower row: alerts from rules in this defense");
    expect(hint).not.toContain("published");
    unmount();
  });
});

describe("keys on the timeline", () => {
  const value = recording({ steps: [step("1", 10, 12), step("2", 40, 45), step("3", 60, 62)] });

  function press(timeline: Timeline, time: number, key: string): number[] {
    const seeks: number[] = [];
    const { container, unmount } = render(<Scrubber recording={value} timeline={timeline} time={time} real={0} revealed={false} ended={false} onSeek={(to) => seeks.push(to)} />);
    const slider = container.querySelector("[role='slider']");
    if (!slider) throw new Error("no slider");
    fireEvent.keyDown(slider, { key });
    unmount();
    return seeks;
  }

  it.each(["ArrowRight", "ArrowUp", "PageUp"])("never moves back with %s, on the last step or at the end", (key) => {
    const timeline = buildTimeline(value);
    const last = timeline.segments[2];
    if (!last) throw new Error("fixture");
    for (const time of [(last.start + last.end) / 2, timeline.duration]) {
      const [to] = press(timeline, time, key);
      expect(to).toBeGreaterThanOrEqual(time);
    }
    // From the first step it still moves on to a later step's start.
    const [on] = press(timeline, 0.1, key);
    expect(on).toBeGreaterThan(0.1);
  });
});

describe("the head of the live view, in plain words", () => {
  const runUrl = "https://github.com/example/lab/actions/runs/7";
  const base = recording({
    steps: [step("1", 1, 2, { outcome: "alerted", visibility: { answer: "alert", basis: "rules", events: 1 } }), step("2", 4, 5), step("3", 7, 8, { role: "hardened", outcome: "stopped", happened: { answer: "blocked", basis: "the change stopped it" } })],
    events: [event("1-1", "1", 1.1), event("2-1", "2", 4.1)],
    alerts: [alert("a1", "1", 1.1, ["1-1"])],
  });
  const value: Recording = { ...base, source: { ...base.source, run_url: runUrl } };
  const note = `Shipped with BlueFire. A workflow of this repository recorded it in the CI run at ${runUrl}.`;

  function show(kind: LiveViewProps["originKind"], initial: LiveViewProps["initial"] = { step: "1", at: 1.5, paused: true }) {
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
    return render(<LiveView recording={value} origin={note} originKind={kind} initial={initial} />);
  }

  it("says in one line what the run is and when it was recorded, and opens to who checked it and the CI run", () => {
    const view = show("shipped");
    const line = view.getByRole("button", { name: /^A real run, recorded \d+ \w+ \d{4} on tests\s*· details$/ });
    // Until it is opened, neither the note nor the CI run's address is on screen.
    expect(view.queryByText(note)).toBeNull();
    expect(view.queryByRole("link")).toBeNull();
    fireEvent.click(line);
    expect(view.getByText(note)).toBeVisible();
    expect(view.getByRole("link", { name: "The CI run that made this recording (github.com)" })).toHaveAttribute("href", runUrl);
    view.unmount();
  });

  it("never calls an imported run, or one whose page does not say, a real run", () => {
    const imported = show("imported");
    expect(imported.getByRole("button", { name: /^An imported run, not verified by BlueFire, recorded / })).toBeVisible();
    imported.unmount();
    const unsaid = show("unsaid");
    expect(unsaid.getByRole("button", { name: /^A run of unknown origin, recorded / })).toBeVisible();
    unsaid.unmount();
  });

  it("says that the score counts up while the run plays, and names the reruns and the lab's rules plainly", () => {
    const view = show("shipped");
    const score = view.getByLabelText("The score so far");
    expect(score).toHaveTextContent("tests alerted so far");
    expect(score).toHaveTextContent("hardened reruns stopped");
    expect(score).not.toHaveTextContent("repeated tests");
    expect(view.container.textContent).toContain("short: repeats");
    expect(view.container.textContent).not.toContain("short: reruns");
    view.unmount();
    // At the end of the run the count is the run's own: no "so far".
    const end = show("shipped", { step: "3", at: 2, paused: true });
    expect(end.getByLabelText("The score so far")).not.toHaveTextContent("so far");
    end.unmount();
  });

  it("says once, where the first alert's time is shown, that the rules ran after the run", () => {
    const view = show("shipped");
    const race = view.getByRole("region", { name: "The race" });
    expect(race).toHaveTextContent("first alert · test 1 (the time of the event it matched)");
    expect(view.container.textContent).not.toContain("ran after the run, so an alert");
    view.unmount();
  });
});

describe("the hardened reruns while they play", () => {
  // One test, then three hardened reruns: the first two stopped by their change, the third not.
  const rerun = (id: string, from: number, stopped: boolean) =>
    step(id, from, from + 1, stopped ? { role: "hardened", outcome: "stopped", happened: { answer: "blocked", basis: "refused" }, visibility: { answer: "telemetry only", basis: "recorded", events: 1 } } : { role: "hardened", visibility: { answer: "telemetry only", basis: "recorded", events: 1 } });
  const value = recording({
    steps: [step("1", 1, 2, { visibility: { answer: "telemetry only", basis: "recorded", events: 1 } }), rerun("2", 10, true), rerun("3", 20, true), rerun("4", 30, false)],
    events: ["1", "2", "3", "4"].map((id, n) => event(`${id}-1`, id, [1.5, 10.5, 20.5, 30.5][n] ?? 0)),
  });

  it("are named and counted alike in the score and the race's sentence: how many of all of them were stopped so far", () => {
    for (const [id, stopped] of [
      ["2", 1],
      ["3", 2],
    ] as const) {
      const { container, unmount } = open(value, { step: id, at: 1, paused: true });
      expect(container.querySelector(".lv-score-reruns b")?.textContent?.replace(/\s+/g, " ").trim(), `rerun ${id}`).toBe(`${stopped} of 3`);
      expect(container.querySelector(".lv-score-reruns span")?.textContent, `rerun ${id}`).toBe("hardened reruns stopped");
      expect(container.querySelector(".lv-phase")?.textContent?.trim(), `rerun ${id}`).toBe(`Hardened reruns: ${stopped} of 3 stopped so far.`);
      unmount();
    }
  });
});

describe("where a run ran, in words", () => {
  const base = recording({ steps: [step("1", 1, 2)], events: [event("1-1", "1", 1.5)] });

  it.each([
    ["containers on a developer machine", "on containers on a developer machine"],
    ["GitHub-hosted runner", "on a GitHub-hosted runner"],
    ["Ubuntu host", "on an Ubuntu host"],
  ])("says %s as a sentence does, in the head, its details and the whole run's summary", (environment, words) => {
    const value: Recording = { ...base, source: { ...base.source, environment } };
    const watch = open(value, { step: "1", at: 1, paused: true });
    const head = watch.container.querySelector(".lv-prov-button");
    expect(head?.textContent).toContain(`2026 ${words}`);
    if (!head) throw new Error("the head should say where the run ran");
    fireEvent.click(head);
    expect(watch.container.querySelector(".lv-prov-pop")?.textContent).toContain(`fixture ${words}, `);
    watch.unmount();
    const analyse = open(value, { mode: "analyse" });
    expect(analyse.container.querySelector(".lv-sum-source")?.textContent).toContain(`fixture ${words}, `);
    analyse.unmount();
  });
});

describe("a step whose recording keeps fewer events than were recorded", () => {
  // Test 1 recorded 1,857 events; the recording keeps 2 of them, both by Sysmon.
  const value = recording({
    steps: [step("1", 10, 11, { visibility: { answer: "telemetry only", basis: "events", events: 1857, kept: 2 } }), step("2", 20, 21)],
    events: [event("1-1", "1", 10.2), event("1-2", "1", 10.4)],
  });

  it("says in its row how many of the recorded events it keeps, which the sensors' columns add up to", () => {
    const { container, unmount } = open(value, { mode: "analyse" });
    const row = container.querySelector("tr[data-step='1']");
    if (!row) throw new Error("the table should have test 1");
    expect(row.querySelector(".lv-kept-tag")?.textContent).toBe("2 of 1,857 events kept");
    const columns = [...row.querySelectorAll("td.is-num")].map((cell) => Number(cell.textContent?.replace(/,/g, "")));
    expect(columns.reduce((sum, value) => sum + value, 0)).toBe(2);
    // The column's hover text says it counts what the recording keeps.
    expect(container.querySelector("thead th.is-num")?.getAttribute("title")).toContain("the recording keeps");
    unmount();
  });
});
