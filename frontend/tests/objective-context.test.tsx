import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import { ObjectiveContext } from "../src/components/ObjectiveContext";

it("returns from a comparison workspace without losing its source and retest context", () => {
  render(<MemoryRouter initialEntries={["/compare?receiver=1&source=run-source&replay=run-retest&goal=data-handoff"]}>
    <ObjectiveContext expected="data-handoff" />
  </MemoryRouter>);
  expect(screen.getByRole("complementary", { name: "Selected objective" })).toHaveTextContent("Can a redaction requirement stop unredacted records while allowing legitimate redacted use?");
  const returnLink = screen.getByRole("link", { name: "Change objective" });
  const target = new URL(returnLink.getAttribute("href")!, "https://example.test");
  expect(target.pathname).toBe("/getting-started");
  expect(target.searchParams.get("source")).toBe("run-source");
  expect(target.searchParams.get("replay")).toBe("run-retest");
  expect(target.searchParams.get("goal")).toBe("data-handoff");
});

it("does not show a different objective's question when a destination link mismatches", () => {
  render(<MemoryRouter initialEntries={["/s3-access?exercise=draft&context=retained&goal=ad-access"]}>
    <ObjectiveContext expected="s3-access" />
  </MemoryRouter>);
  expect(screen.getByRole("complementary", { name: "Objective context" })).toHaveTextContent("This objective link does not match this workspace.");
  expect(screen.queryByText("Can we remove the probe identity's share access while preserving legitimate domain reads?")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Choose an objective" })).toHaveAttribute("href", "/getting-started?exercise=draft&context=retained");
});
