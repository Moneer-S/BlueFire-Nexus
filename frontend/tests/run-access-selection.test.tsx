import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import { RunConfigurationPanel } from "../src/components/RunConfiguration";
import { demoCatalog } from "../src/lib/demo";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

it("shows configured access without granting it when an environment profile changes", async () => {
  const catalog = structuredClone(demoCatalog);
  const execute = catalog.runner_profiles.find(profile => profile.mode === "execute")!;
  catalog.runner_profiles.push({ ...execute, id: "owned.receiver.v1", scope: ["sandbox.workspace", "network.loopback"] });
  function Setup() {
    const { scenario, runConfig, setRunConfig } = useProduct();
    return <><RunConfigurationPanel scenario={scenario} config={runConfig} onChange={setRunConfig} catalog={catalog}/><output aria-label="Requested configuration">{JSON.stringify(runConfig)}</output><button onClick={() => setRunConfig({ ...runConfig, approved: true, approvedBy: "test-operator" })}>Set prior acknowledgement</button></>;
  }
  render(<MemoryRouter><ProductProvider><Setup/></ProductProvider></MemoryRouter>);
  const user = userEvent.setup();
  await user.click(screen.getByRole("radio", { name: /^Execute/ }));
  await user.selectOptions(screen.getByLabelText("Environment profile"), "owned.receiver.v1");
  const network = screen.getByRole("checkbox", { name: /Connections to the local lab receiver/ });
  expect(network).not.toBeChecked();
  expect(screen.getByRole("checkbox", { name: /Files in the selected workspace/ })).toBeChecked();
  expect(JSON.parse(screen.getByLabelText("Requested configuration").textContent!).scopeRefs).toEqual(["sandbox.workspace"]);
  expect(screen.getByText("Created files and cleanup · Required")).toBeVisible();
  expect(screen.queryByRole("checkbox", { name: /collector.filesystem/ })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Set prior acknowledgement" }));
  await user.click(network);
  expect(JSON.parse(screen.getByLabelText("Requested configuration").textContent!)).toMatchObject({ scopeRefs: ["sandbox.workspace", "network.loopback"], approved: false, approvedBy: "" });
  await user.click(screen.getByText("Environment and scope references"));
  expect(screen.getByLabelText(/^Target scope/)).toHaveValue("sandbox.workspace, network.loopback");
});

it("chooses a readable provider name while preserving its exact configuration identity", async () => {
  const catalog = structuredClone(demoCatalog);
  catalog.ai.providers!.push({ provider_id: "exact.connection.v1", kind: "openai_responses", model: "reviewed-model" });
  function Setup() {
    const { scenario, runConfig, setRunConfig } = useProduct();
    return <><RunConfigurationPanel scenario={scenario} config={runConfig} onChange={setRunConfig} catalog={catalog}/><output aria-label="Requested configuration">{JSON.stringify(runConfig)}</output></>;
  }
  render(<MemoryRouter><ProductProvider><Setup/></ProductProvider></MemoryRouter>);
  const user = userEvent.setup();
  await user.click(screen.getByText("AI provider & environment details"));
  const option = screen.getByRole("option", { name: "Responses API · reviewed-model" });
  expect(option).toHaveValue("exact.connection.v1");
  await user.selectOptions(screen.getByLabelText("Provider"), option);
  expect(JSON.parse(screen.getByLabelText("Requested configuration").textContent!)).toMatchObject({ provider: "exact.connection.v1", model: "reviewed-model", endpoint: "", autonomy: "off" });
  expect(screen.getByText("exact.connection.v1", { selector: "code" })).toBeVisible();
});
