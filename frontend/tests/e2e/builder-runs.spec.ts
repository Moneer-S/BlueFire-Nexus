import { expect, test } from "@playwright/test";

test("builder supports add, undo, redo, filtering, and keyboard shortcuts", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  await page.goto("./#/builder");
  await expect(page.getByRole("heading", { name: "Compose a typed adaptive graph" })).toBeVisible();
  const nodes = page.locator(".react-flow__node");
  const initial = await nodes.count();
  await page.locator(".palette-list > button").first().click();
  await expect(nodes).toHaveCount(initial + 1);
  await page.getByRole("button", { name: "Undo" }).click();
  await expect(nodes).toHaveCount(initial);
  await page.getByRole("button", { name: "Redo" }).click();
  await expect(nodes).toHaveCount(initial + 1);

  const search = page.getByRole("textbox", { name: "Search palette" });
  await search.fill("credential");
  await expect(page.locator(".palette-list > button")).toHaveCount(1);
  await search.fill("");
  await page.locator(".react-flow__pane").click({ position: { x: 20, y: 20 } });
  await page.keyboard.press("Control+z");
  await expect(nodes).toHaveCount(initial);
  expect(consoleErrors).toEqual([]);
});

test("Execute approval cannot bypass canonical review and is unchecked after reload", async ({ page }) => {
  await page.goto("./#/runs");
  await expect(page.getByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
  await page.getByRole("radio", { name: /Execute/ }).check();
  await page.getByText("Policy, approval & budgets").click();
  const approval = page.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ });
  const operator = page.getByRole("textbox", { name: "Prepared operator label" });
  await expect(approval).toBeDisabled();
  await expect(operator).toBeDisabled();

  await page.getByRole("button", { name: "Run preflight" }).click();
  await expect(page.getByText("Demo mode previews Execute configuration but never dispatches runner effects.")).toBeVisible();
  await expect(approval).toBeDisabled();

  await page.evaluate(() => window.localStorage.setItem("bluefire.local.run-config.v1", JSON.stringify({ mode: "execute", approved: true, approvedBy: "persisted-e2e" })));
  await page.reload();
  await page.getByText("Policy, approval & budgets").click();
  const reloadedApproval = page.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ });
  const reloadedOperator = page.getByRole("textbox", { name: "Prepared operator label" });
  await expect(reloadedApproval).not.toBeChecked();
  await expect(reloadedOperator).toHaveValue("");
  await expect(reloadedApproval).toBeDisabled();
});
