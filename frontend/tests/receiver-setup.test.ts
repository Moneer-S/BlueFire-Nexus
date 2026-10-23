import { expect, it } from "vitest";
import { readReceiverConfiguration, readReceiverSelection, rememberReceiverConfiguration, rememberReceiverSelection } from "../src/lib/receiver-setup";
import { receiverScenarioSetupPath, receiverSetupSelectionFromSearch } from "../src/lib/receiver-navigation";
import type { ReceiverAssistanceSelection } from "../src/lib/receiver-assistance";
import type { RunConfiguration } from "../src/types";

const defaults = { mode: "simulate", autonomy: "off", provider: "", profileId: "sandbox-simulate.v1", scopeRefs: ["sandbox.workspace"], collectors: ["collector.filesystem.sandbox.v1"], actionImplementations: {}, approved: false, approvedBy: "" } as RunConfiguration;
it("retains exact selected version and native settings across remount without retaining approval", () => {
  const version = "lab:2:sha256:reviewed";
  rememberReceiverSelection(version);
  rememberReceiverConfiguration(version, { ...defaults, mode: "execute", profileId: "sandbox-execute.v1", scopeRefs: ["sandbox.workspace", "network.loopback"], approved: true, approvedBy: "previous operator" });
  expect(readReceiverSelection()).toBe(version);
  const restored = readReceiverConfiguration(version, defaults);
  expect(restored.mode).toBe("execute"); expect(restored.scopeRefs).toEqual(["sandbox.workspace", "network.loopback"]);
  expect(restored.approved).toBe(false); expect(restored.approvedBy).toBe("");
  expect(readReceiverConfiguration("lab:3:sha256:different", defaults)).toEqual(defaults);
});

it("builds a receiver setup route from an exact captured scenario selection", () => {
  const selection: ReceiverAssistanceSelection = {
    kind: "receiver_scenario",
    selection: { kind: "saved_scenario", scenario_id: "scenario.example", version: 2, digest: `sha256:${"b".repeat(64)}` },
    run_intent: { mode: "execute", autonomy: "off", ai_provider_id: null, runner_profile_id: "sandbox-execute.v1", target_scope: { scope_refs: ["sandbox.workspace"] }, collectors: [] },
  };
  const path = receiverScenarioSetupPath(selection)!;
  const url = new URL(path, "http://localhost");
  expect(url.pathname).toBe("/compare");
  expect(receiverSetupSelectionFromSearch(url.searchParams)).toEqual({ present: true, setup: selection, invalid: false });
  expect(receiverScenarioSetupPath({ ...selection, run_intent: { ...selection.run_intent, collectors: undefined } })).toBeUndefined();
  expect(receiverScenarioSetupPath({ ...selection, run_intent: { ...selection.run_intent, action_implementations: {} } })).toBeUndefined();
  expect(receiverScenarioSetupPath({ kind: "receiver_test", receiver_job_id: "job-00000000000000000000000000000000", receiver_context_digest: `sha256:${"c".repeat(64)}` })).toBeUndefined();
});

it.each([
  "receiver=1&saved_scenario=scenario.example&version=0&digest=sha256%3A" + "b".repeat(64),
  "receiver=1&saved_scenario=scenario.example&version=2&version=3&digest=sha256%3A" + "b".repeat(64),
  "receiver=0&saved_scenario=scenario.example&version=2&digest=sha256%3A" + "b".repeat(64),
  "receiver=1&receiver_setup=%7Bmalformed%7D",
])("rejects malformed receiver setup selections: %s", (query) => {
  expect(receiverSetupSelectionFromSearch(new URLSearchParams(query))).toEqual({ present: true, invalid: true });
});

it("rejects crafted payloads the setup cannot round-trip and duplicate receiver flags", () => {
  const setup = {
    kind: "receiver_scenario",
    selection: { kind: "saved_scenario", scenario_id: "scenario.example", version: 2, digest: `sha256:${"b".repeat(64)}` },
    run_intent: { mode: "execute", autonomy: "off", ai_provider_id: null, runner_profile_id: "sandbox-execute.v1", target_scope: { scope_refs: ["sandbox.workspace"] }, collectors: [] },
  };
  const missingCollectors = { ...setup, run_intent: { ...setup.run_intent, collectors: undefined } };
  const emptyMethods = { ...setup, run_intent: { ...setup.run_intent, action_implementations: {} } };
  for (const value of [missingCollectors, emptyMethods]) {
    expect(receiverSetupSelectionFromSearch(new URLSearchParams({ receiver: "1", receiver_setup: JSON.stringify(value) }))).toEqual({ present: true, invalid: true });
  }
  const duplicateFlag = new URLSearchParams({ receiver: "1", receiver_setup: JSON.stringify(setup) });
  duplicateFlag.append("receiver", "1");
  expect(receiverSetupSelectionFromSearch(duplicateFlag)).toEqual({ present: true, invalid: true });
});
