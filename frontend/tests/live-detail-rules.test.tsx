import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { clockTime } from "../src/live/format";
import { LiveView } from "../src/live/LiveView";
import type { LiveViewProps } from "../src/live/LiveView";
import { readRecording, timeOf } from "../src/live/recording";

afterEach(() => {
  vi.restoreAllMocks();
});

function file(name: string): unknown {
  return JSON.parse(readFileSync(resolve(process.cwd(), `../bluefire/data/recordings/${name}.json`), "utf-8"));
}

function open(name: string, initial: LiveViewProps["initial"]) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={readRecording(file(name))} initial={initial} />);
}

interface RawAlert {
  step: string;
  time: string;
  raised?: string;
  events: string[];
  rule: { id: string; title: string; origin: string };
}

/** Each rule that matched a step, recounted from the recording's file: the different events it matched and when its first match came. */
function recount(name: string, stepId: string): Map<string, { events: number; first: number }> {
  const alerts = (file(name) as { alerts: RawAlert[] }).alerts.filter((alert) => alert.step === stepId);
  const rules = new Map<string, { events: Set<string>; first: number }>();
  for (const alert of alerts) {
    const moment = timeOf(alert.raised ?? alert.time);
    const entry = rules.get(alert.rule.title) ?? { events: new Set<string>(), first: moment };
    for (const id of alert.events) entry.events.add(id);
    entry.first = Math.min(entry.first, moment);
    rules.set(alert.rule.title, entry);
  }
  return new Map([...rules].map(([title, entry]) => [title, { events: entry.events.size, first: entry.first }]));
}

/** The rows of the detail's "Rules that matched": each one's title, its line of counts and its notes. */
function ruleRows(root: ParentNode) {
  return [...root.querySelectorAll("article.lv-dt .lv-dt-match")].map((row) => ({
    title: row.querySelector(".lv-dt-rule")?.textContent ?? "",
    counts: row.querySelector(".lv-dt-mmeta")?.textContent ?? "",
    notes: [...row.querySelectorAll(".lv-dt-mnote")].map((note) => note.textContent),
  }));
}

describe("the rules that matched, in the detail of analyse mode", () => {
  it("lists each of the nine rules of step 1 of the attack path once, with the events the file holds for it and when its first match came", () => {
    // Wazuh raises one match for each event: one rule matched 796 times there.
    const view = open("lab-range-one-path", { mode: "analyse", select: "s01" });
    const rows = ruleRows(view.container);
    const expected = recount("lab-range-one-path", "s01");
    expect(expected.size).toBe(9);
    expect(rows.map((row) => row.title).sort()).toEqual([...expected.keys()].sort());
    for (const row of rows) {
      const rule = expected.get(row.title);
      if (!rule) throw new Error(`The detail lists a rule the file does not hold for the step: ${row.title}`);
      const events = rule.events === 1 ? "1 event" : `${rule.events} events`;
      expect(row.counts, row.title).toMatch(new RegExp(`^${events} · (first at )?${clockTime(rule.first).replaceAll(".", "\\.")}( · |$)`));
    }
    // As many rows as the table's cell beside the detail counts rules: "1 alert 6 review 2 info".
    expect(view.container.querySelector('tr[data-step="s01"] td.is-rules')?.textContent).toBe("1 alert 6 review 2 info");
    expect(rows).toHaveLength(1 + 6 + 2);
  }, 60_000);

  it("says when the first match of a rule that matched many times came, and how many of its matches were raised after the step ended", () => {
    const rows = ruleRows(open("lab-range-one-path", { mode: "analyse", select: "s01" }).container);
    const many = rows.find((row) => row.title === "sshd: Attempt to login using a non-existent user");
    expect(many?.counts).toBe("796 events · first at 05:44:50.877 · none in ordinary activity");
    expect(many?.notes).toEqual(["18 of its 796 matches were raised after the step ended."]);
    // A rule that matched many times with no match raised late has no such note.
    expect(rows.find((row) => row.title === "sshd: brute force trying to get access to the system. Non existent user.")?.notes).toEqual([]);
  }, 60_000);

  it("keeps the line of a rule that matched once as it was: its event, its time, and a match raised late said in time", () => {
    const rows = ruleRows(open("lab-range-one-path", { mode: "analyse", select: "s01" }).container);
    expect(rows[0]).toEqual({ title: "Multiple authentication failures followed by a success.", counts: "1 event · 05:46:06.940", notes: ["Raised 280 ms after the step ended."] });
  }, 60_000);

  it("counts an event once where a match names it twice, as the step's fix page does", () => {
    // Test 42 of a later run of the 60 tests: its one match of this rule names the event 45-3 twice.
    const raw = (file("lab-pair-history-watch-after") as { alerts: RawAlert[] }).alerts.filter((alert) => alert.step === "test:23d348f3" && alert.rule.title === "Use Of Hidden Paths Or Files");
    expect(raw.map((alert) => alert.events)).toEqual([["45-3", "45-3"]]);
    const rows = ruleRows(open("lab-pair-history-watch-after", { mode: "analyse", select: "test:23d348f3" }).container);
    expect(rows.find((row) => row.title === "Use Of Hidden Paths Or Files")?.counts).toBe("1 event · 09:36:54.052 · 3 in ordinary activity");
  }, 60_000);
});

describe("a hardened rerun in watch mode", () => {
  const text = (root: ParentNode, selector: string) => root.querySelector(selector)?.textContent?.trim() ?? null;

  it("names the hardening change of a rerun the change did not stop, beside what it did, and in the text a screen reader is given", () => {
    // Step 65 of the run on one Linux machine: the rerun of test 10 with crontab limited to root, seen with no alert.
    const view = open("lab-linux-host", { step: "65", at: 1.5, paused: true });
    expect(text(view.container, ".lv-pair-side")).toBe("With the changetook effect, seen, no alertHardening change: crontab limited to root with /etc/cron.allow");
    expect(text(view.container, ".lv-caption .lv-sr")).toBe("Seen, no alert: 1 event recorded, 1 rule matched for review, none at alert level. Hardening change: crontab limited to root with /etc/cron.allow.");
  }, 60_000);

  it("tells a rerun the change stopped as before: its sentence names the change, once", () => {
    // Step 66: the rerun of test 14, stopped by the account's ~/.ssh owned by root.
    const view = open("lab-linux-host", { step: "66", at: 1.5, paused: true });
    expect(text(view.container, ".lv-why")).toBe("Hardening change: the account's ~/.ssh and authorized_keys owned by root.");
    expect(text(view.container, ".lv-caption .lv-sr")).toBe("Stopped: Hardening change: the account's ~/.ssh and authorized_keys owned by root.");
    expect(view.container.querySelector(".lv-pair")?.textContent).not.toContain("Hardening change");
  }, 60_000);
});
