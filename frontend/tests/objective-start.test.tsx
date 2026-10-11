import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { expect, it } from "vitest";
import { ObjectiveStart } from "../src/components/ObjectiveStart";

function Navigation() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output aria-label="Current location">{location.pathname}{location.search}</output><button onClick={() => navigate(-1)}>Return to start</button></>;
}

function mount(path = "/getting-started") {
  return render(<MemoryRouter initialEntries={[path]}><Navigation /><Routes>
    <Route path="/getting-started" element={<ObjectiveStart />} />
    <Route path="*" element={<h1>Existing environment review</h1>} />
  </Routes></MemoryRouter>);
}

it("requires a deliberate objective choice without creating any stored authority", () => {
  const before = { ...localStorage };
  mount();
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Review environment" })).toBeDisabled();
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
  expect({ ...localStorage }).toEqual(before);
});

it.each([
  ["data-handoff", "/compare?receiver=1", "Retained receiver redaction policy"],
  ["file-access", "/file-access", "File permission correction"],
  ["ad-access", "/ad-smb", "Scoped share permission correction"],
  ["s3-access", "/s3-access", "Scoped bucket-policy correction"],
])("opens only the existing %s review and restores the choice on Back", async (goal, target, change) => {
  const user = userEvent.setup();
  const before = { ...localStorage };
  mount("/getting-started?context=retained");
  await user.selectOptions(screen.getByRole("combobox", { name: "Objective" }), goal);
  expect(screen.getByText(change)).toBeVisible();
  expect(screen.getByText("Not checked")).toBeVisible();
  expect(screen.getByLabelText("Current location")).toHaveTextContent(`/getting-started?context=retained&goal=${goal}`);
  const link = screen.getByRole("link", { name: "Review environment" });
  expect(link).toHaveAttribute("href", target);
  await user.click(link);
  expect(screen.getByRole("heading", { name: "Existing environment review" })).toBeVisible();
  expect(screen.getByLabelText("Current location")).toHaveTextContent(target);
  await user.click(screen.getByRole("button", { name: "Return to start" }));
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue(goal);
  expect({ ...localStorage }).toEqual(before);
});

it("restores a valid direct URL without triggering preparation and permits clearing it", async () => {
  mount("/getting-started?goal=s3-access&context=retained");
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue("s3-access");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Objective" }), "");
  expect(screen.getByRole("button", { name: "Review environment" })).toBeDisabled();
  expect(screen.getByLabelText("Current location")).toHaveTextContent("/getting-started?context=retained");
});

it.each(["unknown", "__proto__", "https://example.test"])("refuses an unsupported goal %s without selecting another question", (goal) => {
  mount(`/getting-started?goal=${encodeURIComponent(goal)}`);
  expect(screen.getByRole("alert")).toHaveTextContent("This objective is unavailable");
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Review environment" })).toBeDisabled();
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
});
