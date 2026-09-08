import { expect, test } from "@playwright/test";

test("builder supports add, undo, redo, filtering, and keyboard shortcuts", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  await page.goto("./#/builder");
  await expect(page.getByRole("heading", { name: "Endpoint control validation", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "Show all branches", exact: true }).click();
  const nodes = page.locator(".react-flow__node");
  const initial = await nodes.count();
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.locator(".palette-list > button").first().click();
  await expect(nodes).toHaveCount(initial + 1);
  await page.getByRole("button", { name: "Undo" }).click();
  await expect(nodes).toHaveCount(initial);
  await page.getByRole("button", { name: "Redo" }).click();
  await expect(nodes).toHaveCount(initial + 1);

  await page.getByRole("button", { name: "Add step", exact: true }).click();
  const search = page.getByRole("textbox", { name: "Search palette" });
  await search.fill("credential");
  await expect(page.locator(".palette-list > button")).toHaveCount(1);
  await search.fill("");
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.locator(".react-flow__pane").click({ position: { x: 20, y: 20 } });
  await page.keyboard.press("Control+z");
  await expect(nodes).toHaveCount(initial);
  expect(consoleErrors).toEqual([]);
});

test("builder workspace exposes commands, layout, focus, legend, panels, and confirmed deletion", async ({ page }) => {
  await page.goto("./#/builder");
  await expect(page.locator(".palette-panel")).toBeHidden();
  await expect(page.locator(".inspector-panel")).toBeHidden();
  await expect(page.getByText(/Review run includes the whole experiment/)).toBeVisible();
  const draftBefore = await page.evaluate(() => window.localStorage.getItem("bluefire.local.scenario.v1"));
  await page.getByRole("button", { name: "Show all branches", exact: true }).click();
  await page.getByText("View options", { exact: true }).click();
  await page.getByLabel("Show input connections", { exact: true }).check();
  await page.getByText("View options", { exact: true }).click();
  expect(await page.evaluate(() => window.localStorage.getItem("bluefire.local.scenario.v1"))).toBe(draftBefore);
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await expect(page.locator(".palette-panel")).toBeVisible();
  await page.getByRole("button", { name: "Show node inspector" }).click();
  await expect(page.locator(".palette-panel")).toBeHidden();
  await expect(page.locator(".inspector-panel")).toBeVisible();
  await page.getByRole("button", { name: "Hide node inspector" }).click();
  await expect(page.locator(".inspector-panel")).toBeHidden();

  await page.getByRole("button", { name: "Auto-layout" }).click();
  await expect(page.getByText("Steps arranged in reading order. Use Undo to restore your positions.")).toBeVisible();
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
  for (const action of ["Auto-layout", "Fit graph", "Fit selection", "Show behavior palette", "Show node inspector", "Exit graph focus mode", "Validate graph", "Undo", "Redo"]) await expect(commandDialog.getByRole("button", { name: new RegExp(`^${action}`) })).toBeVisible();
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

  page.once("dialog", async (dialog) => { await dialog.accept(); });
  await page.getByRole("button", { name: "Delete selected node" }).click();
  await expect(nodes).toHaveCount(initial - 1);
  await expect(page.locator('.react-flow__node[data-id="place_fixture"]')).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => {
    const scenario = JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1") ?? "null");
    return {
      binding: scenario.steps.some((step: { inputs: Record<string, { from_step: string }> }) => Object.values(step.inputs).some((binding) => binding.from_step === "place_fixture")),
      layout: scenario.layout?.place_fixture !== undefined,
      route: scenario.edges.some((edge: { from_step: string; to_step: string }) => edge.from_step === "place_fixture" || edge.to_step === "place_fixture"),
      start: scenario.start,
      step: scenario.steps.some((step: { id: string }) => step.id === "place_fixture"),
    };
  })).toEqual({ binding: false, layout: false, route: false, start: "run_fixture", step: false });

  await page.reload();
  await expect(page.getByRole("heading", { name: "Endpoint control validation", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "Show all branches", exact: true }).click();
  await expect(nodes).toHaveCount(initial - 1);
  await expect(page.locator('.react-flow__node[data-id="place_fixture"]')).toHaveCount(0);
});

test("keyboard selection, copy and deletion follow the focused step", async ({ page }) => {
  await page.goto("./#/builder");
  await page.getByRole("button", { name: "Show all branches", exact: true }).click();
  const first = page.locator('.react-flow__node[data-id="place_fixture"]');
  const second = page.locator('.react-flow__node[data-id="run_fixture"]');
  await second.focus();
  await page.keyboard.press("Enter");
  await expect(second).toHaveClass(/selected/);
  await expect(first).not.toHaveClass(/selected/);
  await page.keyboard.press("Control+c");
  await expect(page.locator(".compatibility-banner")).toContainText("run_fixture copied");
  page.once("dialog", (dialog) => dialog.accept());
  await second.focus();
  await page.keyboard.press("Delete");
  await expect(second).toHaveCount(0);
  await expect(first).toHaveCount(1);
  await page.getByRole("button", { name: "Undo", exact: true }).click();
  await expect(second).toHaveCount(1);
  await expect(first).toHaveCount(1);
});

test("keyboard selection retains focus and text fields keep native copy", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("./#/builder");
  await page.getByRole("button", { name: "Show all branches", exact: true }).click();
  for (const id of ["run_fixture", "place_fixture", "run_fixture"]) {
    const node = page.locator(`.react-flow__node[data-id="${id}"]`);
    await node.focus();
    await page.keyboard.press("Enter");
    await expect(node).toHaveClass(/selected/);
    await expect(node).toBeFocused();
    await page.keyboard.press("Control+c");
    await expect(page.locator(".compatibility-banner")).toContainText(`${id} copied`);
    await expect(node).toBeFocused();
  }
  const name = page.getByRole("textbox", { name: "Experiment name", exact: true });
  await name.fill("Native text clipboard");
  await name.press("Control+a");
  await page.keyboard.press("Control+c");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Native text clipboard");
  await expect(name).toBeFocused();
  await expect(page.locator(".compatibility-banner")).toContainText("run_fixture copied");
});

test("laptop canvas and step details fit the viewport without losing the experiment", async ({ page }) => {
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    await page.setViewportSize(viewport);
    await page.goto("./#/builder");
    await expect(page.getByRole("heading", { name: "Endpoint control validation", level: 1 })).toBeVisible();
    const canvas = await page.locator(".graph-canvas").boundingBox();
    expect(canvas?.y).toBeLessThan(360);
    expect(canvas?.height).toBeGreaterThan(350);
    await page.getByRole("button", { name: "Show node inspector" }).click();
    const details = await page.locator(".inspector-panel").boundingBox();
    expect(details).not.toBeNull();
    expect(details!.y + details!.height).toBeLessThanOrEqual(viewport.height);
    await page.getByRole("button", { name: "Close step details" }).click();
  }
  await page.setViewportSize({ width: 683, height: 384 });
  await page.reload();
  await expect(page.getByRole("list", { name: "Experiment steps" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Review run" })).toBeVisible();
  await expect(page.locator(".inspector-panel")).toBeHidden();
});

test("large branched experiments keep complete data while focusing readable sections", async ({ page }) => {
  await page.goto("./#/builder");
  for (let index = 0; index < 18; index += 1) {
    await page.getByRole("button", { name: "Add step", exact: true }).click();
    await page.locator(".palette-list > button").first().click();
  }
  const section = page.getByRole("combobox", { name: "Path section", exact: true });
  await expect(section).toBeVisible();
  const serialized = await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"));
  const complete = JSON.parse(serialized!);
  expect(complete.steps.length).toBeGreaterThanOrEqual(25);
  expect(complete.edges.some((edge: { outcome: string }) => edge.outcome === "blocked")).toBe(true);
  await section.selectOption("0");
  await expect(page.locator(".react-flow__node")).toHaveCount(8);
  await page.getByRole("button", { name: "Next section", exact: true }).click();
  await expect(section).toHaveValue("1");
  await expect(page.locator(".react-flow__node")).toHaveCount(8);
  await section.selectOption("all");
  await expect(page.locator(".react-flow__node")).toHaveCount(complete.steps.length);
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(complete.steps.length);
  expect(await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"))).toBe(serialized);
  await page.reload();
  await expect(section).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"))).toBe(serialized);
  expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(8);
});

test("Execute approval cannot bypass canonical review and legacy authority is scrubbed after reload", async ({ page }) => {
  await page.goto("./#/runs");
  await expect(page.getByRole("heading", { name: "Runs", level: 1 })).toBeVisible();
  await page.getByRole("link", { name: "Review new run", exact: true }).click();
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
