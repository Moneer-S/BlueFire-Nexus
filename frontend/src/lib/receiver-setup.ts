import type { RunConfiguration } from "../types";
import { runIntent, type RunIntent } from "./run-assistance";

const selectedKey = "bluefire.receiver-defense.selected.v1";
const configKey = (selection: string) => `bluefire.receiver-defense.settings.v1.${selection}`;
export function readReceiverSelection() { try { return sessionStorage.getItem(selectedKey) ?? ""; } catch { return ""; } }
export function rememberReceiverSelection(value: string) {
  sessionStorage.setItem(selectedKey, value);
  if (sessionStorage.getItem(selectedKey) !== value) throw new Error("The experiment selection could not be retained. Keep this page open until the test is saved.");
}
export function readReceiverConfiguration(selection: string, defaults: RunConfiguration): RunConfiguration {
  try {
    const raw = sessionStorage.getItem(configKey(selection));
    if (!raw || raw.length > 16000) return defaults;
    const intent = JSON.parse(raw) as RunIntent;
    const strings = (value: unknown): value is string[] => Array.isArray(value) && value.length <= 100 && value.every((item) => typeof item === "string" && item.length <= 200);
    if (!["simulate", "execute"].includes(intent.mode) || intent.autonomy !== "off" || intent.ai_provider_id !== null ||
      (intent.runner_profile_id !== null && typeof intent.runner_profile_id !== "string") || !strings(intent.target_scope?.scope_refs) ||
      (intent.collectors !== undefined && !strings(intent.collectors)) || (intent.action_implementations !== undefined &&
        (!intent.action_implementations || typeof intent.action_implementations !== "object" || Array.isArray(intent.action_implementations) || !Object.entries(intent.action_implementations).every(([key, value]) => key.length <= 200 && typeof value === "string" && value.length <= 200)))) return defaults;
    return { ...defaults, mode: intent.mode, profileId: intent.runner_profile_id ?? "", scopeRefs: intent.target_scope.scope_refs, collectors: intent.collectors ?? defaults.collectors, actionImplementations: intent.action_implementations ?? {} };
  } catch { return defaults; }
}
export function rememberReceiverConfiguration(selection: string, config: RunConfiguration) {
  const raw = JSON.stringify(runIntent(config));
  sessionStorage.setItem(configKey(selection), raw);
  if (sessionStorage.getItem(configKey(selection)) !== raw) throw new Error("These settings could not be retained. Keep this page open until the test is saved.");
}
