import { screen } from "@testing-library/react";
import { expect } from "vitest";

export async function builderOptions(user: { click: (element: Element) => Promise<void> }, open = true) {
  const summary = screen.getByLabelText("View options", { selector: "summary" });
  const details = summary.closest("details")!;
  expect(summary).toBeVisible();
  if (details.open !== open) await user.click(summary);
  expect(details.open).toBe(open);
  if (open) expect(screen.getByRole("group", { name: "Selection tools" })).toBeVisible();
}

export async function focusSuccessPath(user: { click: (element: Element) => Promise<void> }) {
  await builderOptions(user);
  await user.click(screen.getByRole("button", { name: "Focus on success path" }));
  await builderOptions(user, false);
}
