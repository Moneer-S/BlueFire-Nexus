import { createContext, type PropsWithChildren, useContext, useEffect, useState } from "react";
import { demoScenario } from "../lib/demo";
import type { RunConfiguration, RunRecord, Scenario } from "../types";

const scenarioKey = "bluefire.local.scenario.v1";
const settingsKey = "bluefire.local.run-config.v1";

export const UI_PREFERENCE_SCHEMA_VERSION = "bluefire.ui-preferences.v1" as const;
export type UiTheme = "dark" | "light" | "system";
export interface UiPreferenceDocument {
  schema_version: typeof UI_PREFERENCE_SCHEMA_VERSION;
  theme: UiTheme;
  effect_mode: "simulate" | "execute";
  autonomy: "off" | "assist" | "auto";
}

const preferenceFields = new Set(["schema_version", "theme", "effect_mode", "autonomy"]);

export function buildUiPreferenceDocument(theme: UiTheme, effectMode: RunConfiguration["mode"], autonomy: RunConfiguration["autonomy"]): UiPreferenceDocument {
  return { schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme, effect_mode: effectMode, autonomy };
}

export function parseUiPreferenceDocument(value: unknown): UiPreferenceDocument {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Preferences must be a JSON object.");
  const document = value as Record<string, unknown>;
  const unknown = Object.keys(document).filter((field) => !preferenceFields.has(field));
  if (unknown.length) throw new Error(`Unsupported preference fields were not applied: ${unknown.join(", ")}. Only theme, effect_mode, and autonomy are allowed.`);
  if (document.schema_version !== UI_PREFERENCE_SCHEMA_VERSION) throw new Error(`Unsupported preference schema. Expected ${UI_PREFERENCE_SCHEMA_VERSION}.`);
  if (document.theme !== "dark" && document.theme !== "light" && document.theme !== "system") throw new Error("Preference theme must be dark, light, or system.");
  if (document.effect_mode !== "simulate" && document.effect_mode !== "execute") throw new Error("Preference effect_mode must be simulate or execute.");
  if (document.autonomy !== "off" && document.autonomy !== "assist" && document.autonomy !== "auto") throw new Error("Preference autonomy must be off, assist, or auto.");
  return buildUiPreferenceDocument(document.theme, document.effect_mode, document.autonomy);
}

export function readBrowserUiPreferences(): UiPreferenceDocument | undefined {
  try {
    const value = window.localStorage.getItem(settingsKey);
    return value ? parseUiPreferenceDocument(JSON.parse(value) as unknown) : undefined;
  } catch {
    return undefined;
  }
}

function writeBrowserStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Browser preferences and drafts are best-effort when storage is unavailable.
  }
}

export function writeBrowserUiPreferences(document: UiPreferenceDocument) {
  writeBrowserStorage(settingsKey, JSON.stringify(buildUiPreferenceDocument(document.theme, document.effect_mode, document.autonomy)));
}

export function writeBrowserTheme(theme: UiTheme) {
  writeBrowserStorage("bluefire.theme", theme);
}

export function readBrowserTheme(): UiTheme {
  const preferences = readBrowserUiPreferences();
  if (preferences) return preferences.theme;
  try {
    const theme = window.localStorage.getItem("bluefire.theme");
    return theme === "dark" || theme === "light" || theme === "system" ? theme : "dark";
  } catch {
    return "dark";
  }
}

const defaultRunConfig: RunConfiguration = {
  mode: "simulate", autonomy: "off", provider: "deterministic-offline.v1", model: "deterministic-planner.v1", endpoint: "",
  profileId: "sandbox-simulate.v1", runnerIds: [], scopeRefs: ["sandbox.workspace"], safetyTier: "controlled",
  approvalPolicy: "profile", approved: false, approvedBy: "", maxSeconds: 120, maxSteps: 20, maxBytes: 8_388_608,
  collectors: ["collector.filesystem.sandbox.v1"], detectionBackends: ["structured-matcher"],
  cleanupPolicy: "always", counterfactual: "after_block", fixtureMode: true,
  actionImplementations: {},
};

function strings(value: unknown, fallback: string[]) { return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : fallback; }
function collectors(value: unknown) {
  const allowed = new Set(["collector.filesystem.sandbox.v1"]);
  const selected = strings(value, defaultRunConfig.collectors).filter((item) => allowed.has(item));
  return selected.length ? selected : defaultRunConfig.collectors;
}
function finite(value: unknown, fallback: number) { return typeof value === "number" && Number.isFinite(value) ? value : fallback; }
function oneOf<T extends string>(value: unknown, options: readonly T[], fallback: T): T { return typeof value === "string" && options.includes(value as T) ? value as T : fallback; }
function normalizeRunConfig(value: Partial<RunConfiguration>): RunConfiguration {
  const implementations = value.actionImplementations && typeof value.actionImplementations === "object" && !Array.isArray(value.actionImplementations) ? Object.fromEntries(Object.entries(value.actionImplementations).filter((entry): entry is [string, string] => typeof entry[1] === "string")) : defaultRunConfig.actionImplementations;
  return {
    mode: oneOf(value.mode, ["simulate", "execute"] as const, defaultRunConfig.mode),
    autonomy: oneOf(value.autonomy, ["off", "assist", "auto"] as const, defaultRunConfig.autonomy),
    provider: typeof value.provider === "string" ? value.provider === "offline" ? "deterministic-offline.v1" : value.provider : defaultRunConfig.provider,
    model: typeof value.model === "string" ? value.model : defaultRunConfig.model,
    endpoint: "",
    profileId: typeof value.profileId === "string" ? value.profileId : defaultRunConfig.profileId,
    runnerIds: strings(value.runnerIds, defaultRunConfig.runnerIds), scopeRefs: strings(value.scopeRefs, defaultRunConfig.scopeRefs),
    safetyTier: oneOf(value.safetyTier, ["safe", "controlled", "restricted"] as const, defaultRunConfig.safetyTier),
    approvalPolicy: oneOf(value.approvalPolicy, ["profile", "every_restricted", "every_action"] as const, defaultRunConfig.approvalPolicy),
    approved: value.approved === true, approvedBy: typeof value.approvedBy === "string" ? value.approvedBy : "",
    maxSeconds: finite(value.maxSeconds, defaultRunConfig.maxSeconds), maxSteps: finite(value.maxSteps, defaultRunConfig.maxSteps), maxBytes: finite(value.maxBytes, defaultRunConfig.maxBytes),
    collectors: collectors(value.collectors), detectionBackends: strings(value.detectionBackends, defaultRunConfig.detectionBackends),
    cleanupPolicy: oneOf(value.cleanupPolicy, ["always", "on_success", "manual"] as const, defaultRunConfig.cleanupPolicy),
    counterfactual: oneOf(value.counterfactual, ["disabled", "after_block", "always_preview"] as const, defaultRunConfig.counterfactual),
    fixtureMode: typeof value.fixtureMode === "boolean" ? value.fixtureMode : defaultRunConfig.fixtureMode,
    actionImplementations: implementations,
  };
}

function readLocal<T>(key: string, fallback: T): T {
  try { const value = window.localStorage.getItem(key); return value ? JSON.parse(value) as T : fallback; }
  catch { return fallback; }
}

interface ProductState {
  scenario: Scenario;
  setScenario: (scenario: Scenario, dirty?: boolean) => void;
  dirty: boolean;
  markSaved: () => void;
  runConfig: RunConfiguration;
  setRunConfig: (config: RunConfiguration) => void;
  clearApproval: () => void;
  activeRun: RunRecord | null;
  setActiveRun: (run: RunRecord | null) => void;
}

const ProductContext = createContext<ProductState | null>(null);

export function ProductProvider({ children }: PropsWithChildren) {
  const [scenario, setScenarioState] = useState<Scenario>(() => readLocal(scenarioKey, structuredClone(demoScenario)));
  const [runConfig, setRunConfigState] = useState<RunConfiguration>(() => {
    const preferences = readBrowserUiPreferences();
    return { ...normalizeRunConfig({ mode: preferences?.effect_mode, autonomy: preferences?.autonomy }), approved: false, approvedBy: "" };
  });
  const [activeRun, setActiveRun] = useState<RunRecord | null>(null);
  const [dirty, setDirty] = useState(false);

  const clearApproval = () => setRunConfigState((current) => ({ ...current, approved: false, approvedBy: "" }));
  const setScenario = (next: Scenario, markDirty = true) => { const previousBehaviors = new Map(scenario.steps.map((step) => [step.id, step.behavior_id])); const nextBehaviors = new Map(next.steps.map((step) => [step.id, step.behavior_id])); setScenarioState(next); setDirty(markDirty); setRunConfigState((current) => ({ ...current, approved: false, approvedBy: "", actionImplementations: Object.fromEntries(Object.entries(current.actionImplementations).filter(([stepId]) => previousBehaviors.get(stepId) === nextBehaviors.get(stepId))) })); };
  const setRunConfig = (next: RunConfiguration) => setRunConfigState((current) => {
    const normalized = normalizeRunConfig(next);
    if (current.mode !== normalized.mode) normalized.actionImplementations = {};
    const currentIntent = { ...current, approved: false, approvedBy: "" };
    const nextIntent = { ...normalized, approved: false, approvedBy: "" };
    return JSON.stringify(currentIntent) === JSON.stringify(nextIntent) ? normalized : nextIntent;
  });
  useEffect(() => { writeBrowserStorage(scenarioKey, JSON.stringify(scenario)); }, [scenario]);
  useEffect(() => { writeBrowserUiPreferences(buildUiPreferenceDocument(readBrowserTheme(), runConfig.mode, runConfig.autonomy)); }, [runConfig.autonomy, runConfig.mode]);
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => { if (dirty) event.preventDefault(); };
    window.addEventListener("beforeunload", warn); return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  const value = { scenario, setScenario, dirty, markSaved: () => setDirty(false), runConfig, setRunConfig, clearApproval, activeRun, setActiveRun };
  return <ProductContext.Provider value={value}>{children}</ProductContext.Provider>;
}

export function useProduct() {
  const context = useContext(ProductContext);
  if (!context) throw new Error("useProduct must be used inside ProductProvider");
  return context;
}
