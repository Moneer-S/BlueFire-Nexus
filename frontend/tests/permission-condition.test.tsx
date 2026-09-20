import { render, screen } from "@testing-library/react";
import { useDetectionDraft } from "../src/state/useDetectionDraft";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { PermissionConditionControl, permissionConditionForSelection, permissionPredictedFields, permissionSelection, type PermissionCondition } from "../src/components/PermissionConditionControl";

it("maps the finite permission conditions to strict observed fields", () => {
  expect(permissionSelection("world_writable")).toEqual({ artifact_type: "file_observation", permission_status: "available", other_write_bit: true });
  expect(permissionSelection("non_owner_writable")).toEqual({ artifact_type: "file_observation", permission_status: "available", non_owner_write_bit: true });
  expect(permissionConditionForSelection(permissionSelection("non_owner_writable"))).toBe("non_owner_writable");
  expect(permissionConditionForSelection({ artifact_type: "file_observation", other_write_bit: true })).toBeUndefined();
  expect(permissionPredictedFields("world_writable")).toEqual(["artifact_type", "permission_status", "other_write_bit"]);
  expect(permissionPredictedFields("non_owner_writable")).toEqual(["artifact_type", "permission_status", "non_owner_write_bit"]);
});

it("renders plain-language condition choices and discloses metadata limits", async () => {
  const user = userEvent.setup(); let selected: PermissionCondition = "staged";
  const view = render(<PermissionConditionControl value={selected} onChange={(value) => { selected = value; view.rerender(<PermissionConditionControl value={selected} onChange={(next) => { selected = next; }} />); }} />);
  await user.selectOptions(screen.getByRole("combobox", { name: "Detection condition" }), "world_writable");
  expect(screen.getByText(/effective access remains not evaluated/i)).toBeInTheDocument();
});

it("rejects an invalid retained permission condition without crashing the editor", () => {
  const binding = "permission-condition-invalid-retained";
  sessionStorage.setItem(`bluefire.detection-draft.v1:${binding}`, JSON.stringify({
    binding,
    value: { title: "draft", permissionCondition: "unknown" },
  }));
  function Probe() {
    const draft = useDetectionDraft(binding, { title: "", permissionCondition: "staged" }, ["permissionCondition"], { permissionCondition: (value) => value === "staged" || value === "world_writable" || value === "non_owner_writable" });
    return <><output>{draft.value.permissionCondition}</output>{draft.warning ? <p role="alert">{draft.warning}</p> : null}</>;
  }
  render(<Probe />);
  expect(screen.getByText("staged")).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent(/retained draft could not be read/i);
  expect(sessionStorage.getItem(`bluefire.detection-draft.v1:${binding}`)).toContain('"unknown"');
});
