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

test("builder workspace exposes commands, layout, focus, legend, panels, and confirmed deletion", async ({ page }) => {
  await page.goto("./#/builder");
  await expect(page.getByLabel("Graph legend")).toContainText("Action");
  await expect(page.getByLabel("Graph legend")).toContainText("Simulation");
  await expect(page.getByLabel("Graph legend")).toContainText("Research");
  await expect(page.getByLabel("Graph legend")).toContainText("Success");
  await expect(page.getByLabel("Graph legend")).toContainText("Partial");
  await expect(page.getByLabel("Graph legend")).toContainText("Blocked");
  await expect(page.getByLabel("Graph legend")).toContainText("Failed");

  await page.getByRole("button", { name: "Hide behavior palette" }).click();
  await expect(page.locator(".palette-panel")).toBeHidden();
  await page.getByRole("button", { name: "Show behavior palette" }).click();
  await expect(page.locator(".palette-panel")).toBeVisible();
  await page.getByRole("button", { name: "Hide node inspector" }).click();
  await expect(page.locator(".inspector-panel")).toBeHidden();
  await page.getByRole("button", { name: "Show node inspector" }).click();
  await expect(page.locator(".inspector-panel")).toBeVisible();

  await page.getByRole("button", { name: "Auto-layout" }).click();
  await expect(page.getByText("Graph arranged by outcome-route depth. Disconnected nodes are grouped in the final column.")).toBeVisible();
  await page.getByRole("button", { name: "Fit graph" }).click();
  await page.getByRole("button", { name: "Fit selection" }).click();
  await expect(page.getByRole("button", { name: /Commands Ctrl\/Cmd K/ })).toBeVisible();

  await page.getByRole("button", { name: "Enter graph focus mode" }).click();
  await expect(page.locator(".builder-page")).toHaveClass(/builder-focus/);
  await expect(page.getByText("Esc to exit")).toBeVisible();
  await page.keyboard.press("Control+K");
  const commandDialog = page.getByRole("dialog", { name: "Builder commands" });
  await expect(commandDialog).toBeVisible();
  await expect(commandDialog.locator(".builder-command-list > button")).toHaveCount(9);
  for (const action of ["Auto-layout", "Fit graph", "Fit selection", "Hide behavior palette", "Hide node inspector", "Exit graph focus mode", "Validate graph", "Undo", "Redo"]) await expect(commandDialog.getByRole("button", { name: new RegExp(`^${action}`) })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(commandDialog).toBeHidden();
  await expect(page.locator(".builder-page")).toHaveClass(/builder-focus/);
  await page.keyboard.press("Escape");
  await expect(page.locator(".builder-page")).not.toHaveClass(/builder-focus/);

  const nodes = page.locator(".react-flow__node"); const initial = await nodes.count(); let prompt = "";
  page.once("dialog", async (dialog) => { prompt = dialog.message(); await dialog.dismiss(); });
  await page.getByRole("button", { name: "Delete selected node" }).click();
  expect(prompt).toContain("Delete 1 node");
  await expect(nodes).toHaveCount(initial);
});

test("Execute approval cannot bypass canonical review and legacy authority is scrubbed after reload", async ({ page }) => {
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
  await expect(page.getByRole("radio", { name: "Simulate Synthetic evidence" })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ })).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => JSON.parse(window.localStorage.getItem("bluefire.local.run-config.v1") ?? "{}"))).toEqual({
    schema_version: "bluefire.ui-preferences.v1",
    theme: "dark",
    effect_mode: "simulate",
    autonomy: "off",
  });
});
