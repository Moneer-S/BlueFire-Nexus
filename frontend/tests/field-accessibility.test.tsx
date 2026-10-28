import { createRef } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Field } from "../src/components/Primitives";

describe("Field accessibility", () => {
  it("names the research control from its label and describes it with the hint", () => {
    render(<Field label="Required research reason" hint="Recorded in immutable tuning decisions and lifecycle history."><input /></Field>);

    const control = screen.getByRole("textbox", { name: "Required research reason" });
    expect(control).toHaveAccessibleDescription("Recorded in immutable tuning decisions and lifecycle history.");
    expect(control).toHaveAttribute("aria-describedby", screen.getByText("Recorded in immutable tuning decisions and lifecycle history.").id);
  });

  it("keeps an existing ID, ref, handlers, and description when adding validation help", async () => {
    const ref = createRef<HTMLInputElement>();
    const changed = vi.fn();
    render(<><p id="existing-help">Existing input description.</p><p id="existing-error">Existing error detail.</p><Field label="Profile name" hint="Choose a useful name." error="A name is required."><input id="profile-name" ref={ref} aria-describedby="existing-help" aria-errormessage="existing-error" aria-invalid="true" defaultValue="Current" onChange={changed} /></Field></>);

    const control = screen.getByRole("textbox", { name: "Profile name" });
    expect(control).toHaveAttribute("id", "profile-name");
    expect(ref.current).toBe(control);
    expect(control).toHaveAccessibleDescription("Existing input description. Choose a useful name. A name is required.");
    expect(control).toHaveAttribute("aria-errormessage", "existing-error");
    expect(control).toHaveAttribute("aria-invalid", "true");
    await userEvent.setup().click(screen.getByText("Profile name", { exact: true }));
    expect(control).toHaveFocus();
    fireEvent.change(control, { target: { value: "Updated" } });
    expect(changed).toHaveBeenCalledOnce();
    expect(control).toHaveValue("Updated");
  });

  it("supports nested native controls without replacing their explicit accessible labels", () => {
    render(<><Field label="Method" hint="Choose a supported method."><div className="custom-control"><select aria-label="Method for sample 2"><option>Native</option></select></div></Field><Field label="Notes" hint="Describe this observation."><><textarea rows={2} /></></Field><p id="saved-label">Saved field name</p><Field label="Field name" hint="Keep the supplied label."><input aria-labelledby="saved-label" /></Field></>);

    expect(screen.getByRole("combobox", { name: "Method for sample 2" })).toHaveAccessibleDescription("Choose a supported method.");
    expect(screen.getByRole("textbox", { name: "Notes" })).toHaveAccessibleDescription("Describe this observation.");
    const savedLabelControl = screen.getByRole("textbox", { name: "Saved field name" });
    expect(savedLabelControl).toHaveAttribute("aria-labelledby", "saved-label");
    expect(savedLabelControl).toHaveAccessibleDescription("Keep the supplied label.");
  });

  it("keeps label associations stable and removes only its own descriptions when help changes", () => {
    const { rerender } = render(<><p id="retained-help">Keep this description.</p><Field label="First" hint="Temporary hint." error="Temporary error."><input aria-describedby="retained-help" /></Field><Field label="Second"><input /></Field></>);
    const first = screen.getByRole("textbox", { name: "First" });
    const second = screen.getByRole("textbox", { name: "Second" });
    const firstId = first.getAttribute("aria-labelledby");
    expect(firstId).toBeTruthy();
    expect(firstId).not.toBe(second.getAttribute("aria-labelledby"));
    expect(first).toHaveAttribute("aria-invalid", "true");

    rerender(<><p id="retained-help">Keep this description.</p><Field label="First"><input aria-describedby="retained-help" /></Field><Field label="Second"><input /></Field></>);
    expect(screen.getByRole("textbox", { name: "First" })).toBe(first);
    expect(first).toHaveAttribute("aria-labelledby", firstId);
    expect(first).toHaveAttribute("aria-describedby", "retained-help");
    expect(first).toHaveAccessibleDescription("Keep this description.");
    expect(first).not.toHaveAttribute("aria-invalid");
  });
});
