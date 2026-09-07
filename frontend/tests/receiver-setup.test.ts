import { expect, it } from "vitest";
import { readReceiverConfiguration, readReceiverSelection, rememberReceiverConfiguration, rememberReceiverSelection } from "../src/lib/receiver-setup";
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
