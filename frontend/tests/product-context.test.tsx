import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

const settingsKey = "bluefire.local.run-config.v1";

function Harness() {
  const { scenario, setScenario, runConfig, setRunConfig, clearApproval } = useProduct();
  return <div>
    <output aria-label="approval-state">{runConfig.approved ? "approved" : "unchecked"}</output>
    <output aria-label="operator-state">{runConfig.approvedBy || "blank"}</output>
    <button onClick={() => setRunConfig({ ...runConfig, approved: true, approvedBy: "operator-a" })}>Approve</button>
    <button onClick={() => setRunConfig({ ...runConfig, profileId: "changed-profile.v1" })}>Change intent</button>
    <button onClick={() => setScenario({ ...scenario, title: `${scenario.title} changed` })}>Change scenario</button>
    <button onClick={clearApproval}>Submit run</button>
  </div>;
}

describe("ephemeral Execute approval", () => {
  it("always initializes unchecked and strips a stored identity", async () => {
    window.localStorage.setItem(settingsKey, JSON.stringify({ approved: true, approvedBy: "persisted-operator", mode: "execute", endpoint: "https://browser-endpoint.invalid", api_key: "must-not-survive" })); // pragma: allowlist secret
    render(<ProductProvider><Harness /></ProductProvider>);

    expect(screen.getByLabelText("approval-state")).toHaveTextContent("unchecked");
    expect(screen.getByLabelText("operator-state")).toHaveTextContent("blank");
    await waitFor(() => { const saved = JSON.parse(window.localStorage.getItem(settingsKey) ?? "{}"); expect(saved).not.toHaveProperty("approved"); expect(saved).not.toHaveProperty("approvedBy"); expect(saved).not.toHaveProperty("endpoint"); expect(saved).not.toHaveProperty("api_key"); });
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
