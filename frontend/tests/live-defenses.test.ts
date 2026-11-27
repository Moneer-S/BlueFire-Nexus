import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { countsForScore, defensesOf, firstView, judgedBy, MAX_DEFENSES, MAX_DETECTORS, MAX_DETECTORS_WITH_DEFENSES, readRecording, RecordingError } from "../src/live/recording";
import type { Alert, Defense, Detector, Recording, Step, StepVerdict } from "../src/live/recording";

// One run judged by several defenses. Each recording here is built from the first
// defense's plain view of the path through range one that the app ships. The
// service's tests build the same recordings
// (tests_platform/test_recording_defenses.py); whether a verdict follows from the
// events and alerts of its view is checked there alone, as it is for a recording
// without defenses.

const SHIPPED = readFileSync(resolve(process.cwd(), "../bluefire/data/recordings/lab-range-one-path.json"), "utf-8");

type Judged = Recording & { defenses: Defense[] };

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** The shipped path as one plain view, whether it already holds several defenses or not. */
function plainShipped(): Recording {
  const whole = readRecording(JSON.parse(SHIPPED));
  return defensesOf(whole).length > 0 ? firstView(whole) : whole;
}

/** The keys of a step that say what a defense made of it, as that step has them. */
function verdictOf(step: Step): StepVerdict {
  const { visibility, outcome, outcome_with_lab_rules, first_event, first_alert, first_alert_with_lab_rules } = step;
  return copy({ visibility, outcome, outcome_with_lab_rules, first_event, first_alert, first_alert_with_lab_rules });
}

/**
 * The shipped path as one run judged by two defenses. The first is everything
 * the recording holds, so the top level is its view. The second records with
 * the same three agents and runs no rule set: the step that alerted is only
 * seen there, with no first alert, and its score follows.
 */
function judgedTwice(): Judged {
  const whole = plainShipped();
  const stock: Defense = {
    id: "wazuh-stock",
    name: "Wazuh with its stock rules",
    sensors: whole.network.sensors.map((sensor) => sensor.id),
    detectors: ["pinned"],
    steps: Object.fromEntries(whole.steps.map((step) => [step.id, verdictOf(step)])),
    ...(whole.ordinary ? { ordinary: whole.ordinary } : {}),
    score: whole.score,
  };
  const alone = copy(stock);
  Object.assign(alone, { id: "agents-alone", name: "The three agents with no rule set", detectors: [] });
  for (const verdict of Object.values(alone.steps)) {
    if (verdict.outcome !== "alerted") continue;
    verdict.visibility = { ...verdict.visibility, answer: "telemetry only", basis: "the agents recorded the step; no rule set ran" };
    verdict.outcome = "seen";
    delete verdict.first_alert;
  }
  alone.ordinary = { events: whole.ordinary?.events ?? 0, matches: [] };
  alone.score = { ...alone.score, alerted: 0, seen: alone.score.seen + alone.score.alerted };
  delete alone.score.first_alert_seconds;
  return { ...whole, id: "range-one-judged-twice", defenses: copy([stock, alone]) };
}

/**
 * A fourth sensor, a packet capture on web, that only the defense at `place`
 * has: it recorded one more event of the last step, which only that defense
 * counts.
 */
function withPacketCapture(value: Judged, place: number): Judged {
  const last = value.events[value.events.length - 1];
  const defense = value.defenses[place];
  const verdict = defense?.steps[last?.step ?? ""];
  if (!last || !defense || !verdict) throw new Error("fixture");
  value.network.sensors.push({ id: "packet-capture", name: "Packet capture", host: last.host, records: "packets" });
  value.events.push({ ...last, id: "capture-1", sensor: "packet-capture", kind: "packet" });
  defense.sensors.push("packet-capture");
  verdict.visibility = { ...verdict.visibility, events: (verdict.visibility.events ?? 0) + 1 };
  return value;
}

/** A match of the stock rules, below alert level, on the event the packet capture recorded. */
function onTheCapture(value: Judged): Alert {
  const seen = value.events[value.events.length - 1];
  if (!seen) throw new Error("fixture");
  return { id: "on-the-capture", time: seen.time, host: seen.host, detector: "pinned", rule: { id: "1", title: "A packet", level: "low", origin: "pinned" }, counts: false, step: seen.step, events: [seen.id] };
}

function ruleSet(id: string): Detector {
  return { id, name: `${id} rules`, rules: 1, when: "after the run" };
}

function refusal(value: unknown): string {
  try {
    readRecording(copy(value));
  } catch (error) {
    if (error instanceof RecordingError) return error.message;
    throw new Error(`not a RecordingError: ${String(error)}`);
  }
  throw new Error("the recording was accepted");
}

describe("a recording of one run judged by several defenses", () => {
  it("separates scored origin from authorship in the shipped ordered and public defenses", () => {
    const whole = readRecording(JSON.parse(SHIPPED));
    const ordered = judgedBy(whole, "ordered-credential");
    const counted = ordered.alerts.filter(countsForScore);
    const terminal = ordered.steps.find((step) => step.id === "s08");
    const orderedDetector = ordered.network.detectors.find((detector) => detector.id === "ordered-credential");

    expect(ordered.score.alerted).toBe(1);
    expect(terminal?.outcome).toBe("alerted");
    expect(counted).toHaveLength(1);
    expect(counted[0]).toMatchObject({ step: "s08", detector: "ordered-credential", counts: true, rule: { origin: "pinned" } });
    expect(orderedDetector?.name).toContain("Repository-authored Sigma rules");

    const publicView = judgedBy(whole, "sigma-public");
    const publicDetector = publicView.network.detectors.find((detector) => detector.id === "sigma");
    expect(publicView.score.alerted).toBe(0);
    expect(publicDetector?.name).toContain("Published Sigma rules");
    expect(publicDetector?.name).toContain("SigmaHQ/sigma");
  });

  it("is read whole, with its defenses in order, and a recording without defenses has none", () => {
    const read = readRecording(copy(judgedTwice()));
    expect(defensesOf(read).map((defense) => [defense.id, defense.name])).toEqual([["wazuh-stock", "Wazuh with its stock rules"], ["agents-alone", "The three agents with no rule set"]]);
    expect(defensesOf(plainShipped())).toEqual([]);
  });

  it("gives, judged by the first defense, the top level's steps, ordinary activity and score, as a recording without defenses", () => {
    const whole = readRecording(copy(judgedTwice()));
    const view = judgedBy(whole, "wazuh-stock");
    expect(view.steps).toEqual(whole.steps);
    expect(view.ordinary).toEqual(whole.ordinary);
    expect(view.score).toEqual(whole.score);
    // The first defense has every sensor and the one rule set, so its view holds everything.
    expect(view.events).toEqual(whole.events);
    expect(view.alerts).toEqual(whole.alerts);
    expect(view.network).toEqual(whole.network);
    // The view is a plain recording: nothing of the defenses is left in it, and the reader takes it.
    expect("defenses" in view).toBe(false);
    expect(readRecording(copy(view))).toEqual(view);
  });

  it("gives, judged by the second defense, no alert and that defense's verdict on every step", () => {
    const whole = readRecording(copy(judgedTwice()));
    const [, second] = defensesOf(whole);
    if (!second) throw new Error("fixture");
    const view = judgedBy(whole, "agents-alone");
    expect(view.alerts).toEqual([]);
    expect(view.network.detectors).toEqual([]);
    // The same agents recorded the same events.
    expect(view.events).toEqual(whole.events);
    expect(view.network.sensors).toEqual(whole.network.sensors);
    expect(view.steps.map((step) => [step.id, verdictOf(step)])).toEqual(whole.steps.map((step) => [step.id, second.steps[step.id]]));
    expect(view.steps.map((step) => step.outcome)).toEqual(whole.steps.map(() => "seen"));
    // The step the first defense alerted on has no first alert here: the key is gone, not the first defense's.
    expect(whole.steps[0]?.first_alert).toBeDefined();
    expect(view.steps[0] && "first_alert" in view.steps[0]).toBe(false);
    // What a step did is the step's own, whoever judges it.
    const own = ({ id, title, host, started, ended, command, output, happened }: Step) => ({ id, title, host, started, ended, command, output, happened });
    expect(view.steps.map(own)).toEqual(whole.steps.map(own));
    expect(view.ordinary).toEqual(second.ordinary);
    expect(view.score).toEqual(second.score);
    expect("defenses" in view).toBe(false);
    expect(readRecording(copy(view))).toEqual(view);
  });

  it("gives each defense only what its own sensors recorded", () => {
    const whole = readRecording(copy(withPacketCapture(judgedTwice(), 1)));
    const last = whole.steps[whole.steps.length - 1];
    if (!last) throw new Error("fixture");
    const first = judgedBy(whole, "wazuh-stock");
    const second = judgedBy(whole, "agents-alone");
    expect(first.events.map((event) => event.id)).not.toContain("capture-1");
    expect(first.network.sensors.map((sensor) => sensor.id)).not.toContain("packet-capture");
    expect(second.events.map((event) => event.id)).toContain("capture-1");
    expect(second.network.sensors.map((sensor) => sensor.id)).toContain("packet-capture");
    expect([first, second].map((view) => view.steps[view.steps.length - 1]?.visibility.events)).toEqual([1, 2]);
    expect(second.events).toHaveLength(first.events.length + 1);
  });

  it("gives an alert only to a defense that has its rule set and recorded every event it names", () => {
    // A third defense has the stock rules and the capture too; the first has the rules without it.
    const value = judgedTwice();
    const [stock] = value.defenses;
    if (!stock) throw new Error("fixture");
    value.defenses.push({ ...copy(stock), id: "stock-and-capture", name: "Wazuh with its stock rules and a packet capture" });
    withPacketCapture(value, 2);
    value.alerts.push(onTheCapture(value));
    const whole = readRecording(copy(value));
    expect(judgedBy(whole, "wazuh-stock").alerts.map((alert) => alert.id)).not.toContain("on-the-capture");
    expect(judgedBy(whole, "stock-and-capture").alerts.map((alert) => alert.id)).toContain("on-the-capture");
    expect(judgedBy(whole, "stock-and-capture").alerts).toHaveLength(judgedBy(whole, "wazuh-stock").alerts.length + 1);
  });

  it("names a defense the recording does not have", () => {
    const whole = readRecording(copy(judgedTwice()));
    expect(() => judgedBy(whole, "sigma-public")).toThrow('This recording has no defense "sigma-public".');
    expect(() => judgedBy(plainShipped(), "wazuh-stock")).toThrow(RecordingError);
  });

  it("is played as its first defense judged it, and a recording without defenses as it is", () => {
    const whole = readRecording(copy(withPacketCapture(judgedTwice(), 1)));
    expect(firstView(whole)).toEqual(judgedBy(whole, "wazuh-stock"));
    const plain = plainShipped();
    expect(firstView(plain)).toBe(plain);
  });

  it(`holds up to ${MAX_DETECTORS_WITH_DEFENSES} rule sets, of which a defense has up to ${MAX_DETECTORS}`, () => {
    const value = judgedTwice();
    const more = Array.from({ length: MAX_DETECTORS_WITH_DEFENSES - 1 }, (_, index) => `set-${index}`);
    value.network.detectors.push(...more.map(ruleSet));
    Object.assign(value.defenses[1] ?? {}, { detectors: more.slice(0, MAX_DETECTORS) });
    const whole = readRecording(copy(value));
    expect(whole.network.detectors).toHaveLength(MAX_DETECTORS_WITH_DEFENSES);
    expect(judgedBy(whole, "agents-alone").network.detectors.map((detector) => detector.id)).toEqual(more.slice(0, MAX_DETECTORS));
  });
});

type Refusal = [string, (value: Judged, second: Defense) => void, string];

const TOP_IS_FIRST = 'the first defense\'s, "wazuh-stock": the top level of a recording with defenses holds the verdicts of its first defense.';

describe("refusing a recording with defenses, with the defense and the key named, as the service does on import", () => {
  const refusals: Refusal[] = [
    ["with no defense in its list", (value) => { value.defenses = []; }, `The recording has 0 defenses; one with defenses has from 1 to ${MAX_DEFENSES}.`],
    ["with nine defenses", (value, second) => { value.defenses.push(...Array.from({ length: MAX_DEFENSES - 1 }, (_, index) => ({ ...second, id: `more-${index}` }))); }, `The recording has 9 defenses; one with defenses has from 1 to ${MAX_DEFENSES}.`],
    ["whose defenses share an id", (_value, second) => { second.id = "wazuh-stock"; }, 'Two defenses have the id "wazuh-stock".'],
    ["with a space in a defense's id", (_value, second) => { second.id = "agents alone"; }, 'The id of defense 2, "agents alone", is not 1 to 64 letters, digits, "-" or "_".'],
    ["whose defense has a sensor the network lacks", (_value, second) => { second.sensors.push("packet-capture"); }, 'The defense "agents-alone" names the sensor "packet-capture", which is not in the recording.'],
    ["whose defense names a sensor by a number", (_value, second) => { Object.assign(second, { sensors: [...second.sensors, 3] }); }, 'Item 4 of the sensors of the defense "agents-alone" is not text.'],
    ["whose defense has a rule set the network lacks", (_value, second) => { second.detectors = ["sigma"]; }, 'The defense "agents-alone" names the detector "sigma", which is not in the recording.'],
    ["whose defense names a rule set by null", (_value, second) => { Object.assign(second, { detectors: [null] }); }, 'Item 1 of the detectors of the defense "agents-alone" is not text.'],
    ["whose defense has no sensor", (_value, second) => { second.sensors = []; }, 'The defense "agents-alone" has no sensor; a defense records with at least one.'],
    [
      "whose defense has five rule sets",
      (value, second) => {
        const more = Array.from({ length: MAX_DETECTORS }, (_, index) => `set-${index}`);
        value.network.detectors.push(...more.map(ruleSet));
        second.detectors = ["pinned", ...more];
      },
      `The defense "agents-alone" has 5 detectors; the map draws at most ${MAX_DETECTORS}.`,
    ],
    ["with nine rule sets in its network", (value) => { value.network.detectors.push(...Array.from({ length: MAX_DETECTORS_WITH_DEFENSES }, (_, index) => ruleSet(`set-${index}`))); }, `The network has 9 detectors; a recording with defenses holds at most ${MAX_DETECTORS_WITH_DEFENSES}.`],
    ["whose defense leaves a step out", (_value, second) => { delete second.steps.s03; }, 'The defense "agents-alone" has no verdict on Step "s03"; a defense judges every step.'],
    ["whose defense judges a step the run lacks", (_value, second) => { if (second.steps.s10) second.steps.s99 = second.steps.s10; }, 'The defense "agents-alone" names the step "s99", which is not in the recording.'],
    ["whose defense gives a step an outcome the format does not have", (_value, second) => { Object.assign(second.steps.s01 ?? {}, { outcome: "missed" }); }, 'The outcome of Step "s01" for the defense "agents-alone" is "missed", which is not one of: stopped, no effect, alerted, seen, unseen, inconclusive.'],
    ["whose defense has no score", (_value, second) => { Object.assign(second, { score: undefined }); }, 'The score of the defense "agents-alone" is not an object.'],
    [
      "with an event of a sensor no defense has",
      (value, second) => {
        withPacketCapture(value, 1);
        second.sensors.pop();
        Object.assign(second.steps.s10?.visibility ?? {}, { events: 1 });
      },
      'Event "capture-1" is of the sensor "packet-capture", which no defense has: every event of a recording with defenses is of a sensor that one of them has.',
    ],
    [
      "with an alert of a rule set no defense has",
      (value) => {
        const last = value.alerts[value.alerts.length - 1];
        if (!last) throw new Error("fixture");
        // Rules that ran after the run raise nothing: the copied alert loses its raised time.
        const alert: Alert = { ...last, id: "sigma-1", detector: "sigma" };
        delete alert.raised;
        value.network.detectors.push(ruleSet("sigma"));
        value.alerts.push(alert);
      },
      'Alert "sigma-1" is of the detector "sigma", which no defense has: every alert of a recording with defenses is of a rule set that one of them has.',
    ],
    [
      // The stock rules are the first defense's, and the capture is the second's.
      "with an alert on an event its defense did not record",
      (value) => { value.alerts.push(onTheCapture(withPacketCapture(value, 1))); },
      'Alert "on-the-capture" is in no defense\'s view: no defense has its detector, "pinned", and the sensor of every event it names.',
    ],
    ["whose top level gives a step another outcome than its first defense", (value) => { Object.assign(value.steps[1] ?? {}, { outcome: "unseen" }); }, `The outcome of Step "s02" differs from ${TOP_IS_FIRST}`],
    ["whose top level gives another score than its first defense", (value) => { value.score = { ...value.score, seen: value.score.seen - 1 }; }, `The recording's score differs from ${TOP_IS_FIRST}`],
    ["whose top level has no ordinary activity where its first defense has", (value) => { delete value.ordinary; }, `The recording's ordinary differs from ${TOP_IS_FIRST}`],
    ["whose defense counts false alerts with no ordinary activity", (_value, second) => { delete second.ordinary; }, 'For the defense "agents-alone": The score\'s false_alerts is set, but the recording has no ordinary activity to count it from.'],
  ];

  it.each(refusals)("refuses one %s", (_case, change, message) => {
    const value = judgedTwice();
    const [, second] = value.defenses;
    if (!second) throw new Error("fixture");
    change(value, second);
    expect(refusal(value)).toBe(message);
  });
});
