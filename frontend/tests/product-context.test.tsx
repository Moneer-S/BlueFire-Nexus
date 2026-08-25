import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { buildUiPreferenceDocument, parseUiPreferenceDocument, ProductProvider, UI_PREFERENCE_SCHEMA_VERSION, useProduct } from "../src/state/ProductContext";

const settingsKey = "bluefire.local.run-config.v1";

function Harness() {
  const { scenario, setScenario, runConfig, setRunConfig, clearApproval } = useProduct();
  return <div>
    <output aria-label="approval-state">{runConfig.approved ? "approved" : "unchecked"}</output>
    <output aria-label="operator-state">{runConfig.approvedBy || "blank"}</output>
    <output aria-label="mode-state">{runConfig.mode}</output>
    <output aria-label="autonomy-state">{runConfig.autonomy}</output>
    <output aria-label="profile-state">{runConfig.profileId}</output>
    <output aria-label="provider-state">{runConfig.provider}</output>
    <button onClick={() => setRunConfig({ ...runConfig, approved: true, approvedBy: "operator-a" })}>Approve</button>
    <button onClick={() => setRunConfig({ ...runConfig, profileId: "changed-profile.v1" })}>Change intent</button>
    <button onClick={() => setRunConfig({ ...runConfig, provider: "changed-provider.v1", model: "changed-model", profileId: "changed-profile.v1", scopeRefs: ["changed.scope"], safetyTier: "restricted", maxSeconds: 999, collectors: ["changed-collector"], detectionBackends: ["changed-backend"], cleanupPolicy: "manual", counterfactual: "always_preview", fixtureMode: false, actionImplementations: { step: "changed-action" } })}>Change authority fields</button>
    <button onClick={() => setScenario({ ...scenario, title: `${scenario.title} changed` })}>Change scenario</button>
    <button onClick={clearApproval}>Submit run</button>
  </div>;
}

describe("ephemeral Execute approval", () => {
  beforeEach(() => window.localStorage.clear());

  it("always initializes unchecked and replaces a legacy authority-heavy browser payload", async () => {
    window.localStorage.setItem("bluefire.theme", "light");
    window.localStorage.setItem(settingsKey, JSON.stringify({ approved: true, approvedBy: "persisted-operator", mode: "execute", endpoint: "https://browser-endpoint.invalid", api_key: "must-not-survive" })); // pragma: allowlist secret
    render(<ProductProvider><Harness /></ProductProvider>);

    expect(screen.getByLabelText("approval-state")).toHaveTextContent("unchecked");
    expect(screen.getByLabelText("operator-state")).toHaveTextContent("blank");
    expect(screen.getByLabelText("mode-state")).toHaveTextContent("simulate");
    await waitFor(() => expect(JSON.parse(window.localStorage.getItem(settingsKey) ?? "{}")).toEqual({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "light", effect_mode: "simulate", autonomy: "off" }));
  });

  it("hydrates only the three strict preferences while runtime authority remains canonical", async () => {
    window.localStorage.setItem(settingsKey, JSON.stringify(buildUiPreferenceDocument("system", "execute", "assist")));
    render(<ProductProvider><Harness /></ProductProvider>);

    expect(screen.getByLabelText("mode-state")).toHaveTextContent("execute");
    expect(screen.getByLabelText("autonomy-state")).toHaveTextContent("assist");
    expect(screen.getByLabelText("profile-state")).toHaveTextContent("sandbox-simulate.v1");
    expect(screen.getByLabelText("provider-state")).toHaveTextContent("deterministic-offline.v1");
    expect(screen.getByLabelText("approval-state")).toHaveTextContent("unchecked");

    await userEvent.click(screen.getByRole("button", { name: "Change authority fields" }));
    await waitFor(() => expect(JSON.parse(window.localStorage.getItem(settingsKey) ?? "{}")).toEqual({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "system", effect_mode: "execute", autonomy: "assist" }));
  });

  it("clears approval when any intent or scenario field changes", async () => {
    const user = userEvent.setup();
    render(<ProductProvider><Harness /></ProductProvider>);

    await user.click(screen.getByRole("button", { name: "Approve" }));
    expect(screen.getByLabelText("approval-state")).toHaveTextContent("approved");
    await user.click(screen.getByRole("button", { name: "Change intent" }));
    expect(screen.getByLabelText("approval-state")).toHaveTextContent("unchecked");
    expect(screen.getByLabelText("operator-state")).toHaveTextContent("blank");

    await user.click(screen.getByRole("button", { name: "Approve" }));
    await user.click(screen.getByRole("button", { name: "Change scenario" }));
    expect(screen.getByLabelText("approval-state")).toHaveTextContent("unchecked");
  });

  it("consumes approval after a submission boundary", async () => {
    const user = userEvent.setup();
    render(<ProductProvider><Harness /></ProductProvider>);
    await user.click(screen.getByRole("button", { name: "Approve" }));
    await user.click(screen.getByRole("button", { name: "Submit run" }));
    expect(screen.getByLabelText("approval-state")).toHaveTextContent("unchecked");
    expect(screen.getByLabelText("operator-state")).toHaveTextContent("blank");
  });
});

describe("strict UI preference schema", () => {
  it("round-trips exactly theme, effect mode, and autonomy", () => {
    expect(buildUiPreferenceDocument("dark", "simulate", "auto")).toEqual({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "dark", effect_mode: "simulate", autonomy: "auto" });
    expect(parseUiPreferenceDocument({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "light", effect_mode: "execute", autonomy: "off" })).toEqual({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "light", effect_mode: "execute", autonomy: "off" });
  });

  it("rejects unknown authority fields instead of applying them", () => {
    expect(() => parseUiPreferenceDocument({ schema_version: UI_PREFERENCE_SCHEMA_VERSION, theme: "dark", effect_mode: "simulate", autonomy: "off", profileId: "must-not-import", endpoint: "https://must-not-import.invalid" })).toThrow(/profileId, endpoint/);
  });
});
