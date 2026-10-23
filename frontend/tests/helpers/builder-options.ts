import { screen } from "@testing-library/react";
import { expect } from "vitest";

export async function builderOptions(user: { click: (element: Element) => Promise<void> }, open = true) {
  const summary = screen.getByText("View options", { selector: "summary" });
  const details = summary.closest("details")!;
  expect(summary).toBeVisible();
  if (details.open !== open) await user.click(summary);
  expect(details.open).toBe(open);
  if (open) expect(screen.getByRole("group", { name: "Selection tools" })).toBeVisible();
}
