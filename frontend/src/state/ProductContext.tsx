import { createContext, type PropsWithChildren, useContext, useEffect, useState } from "react";
import { demoScenario } from "../lib/demo";
import type { RunConfiguration, RunRecord, Scenario } from "../types";

const scenarioKey = "bluefire.local.scenario.v1";
const settingsKey = "bluefire.local.run-config.v1";

const defaultRunConfig: RunConfiguration = {
  mode: "simulate", autonomy: "off", provider: "deterministic-offline.v1", model: "deterministic-planner.v1", endpoint: "",
  profileId: "sandbox-simulate.v1", runnerIds: [], scopeRefs: ["sandbox.workspace"], safetyTier: "controlled",
  approvalPolicy: "profile", approved: false, approvedBy: "", maxSeconds: 120, maxSteps: 20, maxBytes: 8_388_608,
  collectors: ["runner-local", "filesystem-observer"], detectionBackends: ["structured-matcher"],
  cleanupPolicy: "always", counterfactual: "after_block", fixtureMode: true,
  actionImplementations: {},
};

function strings(value: unknown, fallback: string[]) { return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : fallback; }
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
    collectors: strings(value.collectors, defaultRunConfig.collectors), detectionBackends: strings(value.detectionBackends, defaultRunConfig.detectionBackends),
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
    const stored = readLocal<Partial<RunConfiguration> & Record<string, unknown>>(settingsKey, {});
    return { ...normalizeRunConfig(stored), approved: false, approvedBy: "" };
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
  useEffect(() => { window.localStorage.setItem(scenarioKey, JSON.stringify(scenario)); }, [scenario]);
  useEffect(() => { const { approved, approvedBy, endpoint, ...persistentConfig } = runConfig; void approved; void approvedBy; void endpoint; window.localStorage.setItem(settingsKey, JSON.stringify(persistentConfig)); }, [runConfig]);
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
