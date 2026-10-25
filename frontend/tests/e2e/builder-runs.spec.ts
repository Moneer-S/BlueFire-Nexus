import { expect, test, type Page } from "@playwright/test";
import { demoScenario } from "../../src/lib/demo";

async function viewOptions(page: Page, open: boolean) {
  if (await page.locator("details.graph-options").evaluate(element => (element as HTMLDetailsElement).open) !== open) {
    await page.getByLabel("View options", { exact: true }).click();
  }
}

async function expectPaintedOutcomeRoutes(page: Page) {
  const expected = demoScenario.edges.map((edge, index) => ({
    id: `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`,
    pathCount: 1, finitePath: true, nonzeroLength: true, painted: true, visibleAncestors: true,
    finiteBounds: true, dashed: edge.outcome !== "success",
  })).sort((left, right) => left.id.localeCompare(right.id));
  const routes = page.locator(".react-flow__edge");
  await expect(routes).toHaveCount(expected.length);
  // Straight SVG paths may have a zero-width or zero-height box despite a
  // visible stroke. Check their saved identities and painted geometry directly.
  await expect.poll(() => routes.evaluateAll(edges => edges.map(edge => {
    const paths = edge.querySelectorAll<SVGPathElement>(".react-flow__edge-path");
    const path = paths[0];
    const style = path ? getComputedStyle(path) : undefined;
    const box = path?.getBoundingClientRect();
    const d = path?.getAttribute("d");
    let length = Number.NaN;
    try { length = path?.getTotalLength() ?? Number.NaN; } catch { /* Invalid geometry fails the assertion. */ }
    let visibleAncestors = Boolean(path);
    for (let ancestor: Element | null = path ?? null; ancestor; ancestor = ancestor.parentElement) {
      const ancestorStyle = getComputedStyle(ancestor);
      if (ancestorStyle.display === "none" || ["hidden", "collapse"].includes(ancestorStyle.visibility)
        || Number(ancestorStyle.opacity) === 0) visibleAncestors = false;
    }
    const strokeWidth = Number.parseFloat(style?.strokeWidth ?? "");
    return {
      id: edge.getAttribute("data-id") ?? "", pathCount: paths.length,
      finitePath: Boolean(d && !/NaN|Infinity/.test(d)), nonzeroLength: Number.isFinite(length) && length > 0,
      painted: Boolean(style && style.stroke !== "none" && style.stroke !== "transparent"
        && !/rgba\([^)]*,\s*0(?:\.0*)?\)$/.test(style.stroke)
        && Number.isFinite(strokeWidth) && strokeWidth > 0 && Number(style.strokeOpacity) > 0),
      visibleAncestors,
      finiteBounds: Boolean(box && [box.x, box.y, box.width, box.height].every(Number.isFinite)
        && box.width >= 0 && box.height >= 0 && (box.width > 0 || box.height > 0)),
      dashed: Boolean(style && style.strokeDasharray !== "none"),
    };
  }).sort((left, right) => left.id.localeCompare(right.id)))).toEqual(expected);
}

test("builder supports add, undo, redo, filtering, and keyboard shortcuts", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  await page.addInitScript(draft => localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(draft)), demoScenario);
  await page.goto("./#/builder");
  await expect(page.getByRole("heading", { name: "Endpoint control validation", level: 1 })).toBeVisible();
  const nodes = page.locator(".react-flow__node");
  const initial = await nodes.count();
  expect(initial).toBe(7);
  const savedBeforeAdd = await page.evaluate(() => window.localStorage.getItem("bluefire.local.scenario.v1"));
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.locator(".palette-list > button").first().click();
  await expect(nodes).toHaveCount(initial + 1);
  await expect.poll(() => page.evaluate(() => JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!).steps.length)).toBe(initial + 1);
  await page.getByRole("button", { name: "Undo" }).click();
  await expect(nodes).toHaveCount(initial);
  expect(await page.evaluate(() => window.localStorage.getItem("bluefire.local.scenario.v1"))).toBe(savedBeforeAdd);
  await page.getByRole("button", { name: "Redo" }).click();
  await expect(nodes).toHaveCount(initial + 1);
  await expect.poll(() => page.evaluate(() => JSON.parse(window.localStorage.getItem("bluefire.local.scenario.v1")!).steps.length)).toBe(initial + 1);

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
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(demoScenario.steps.length);
  await expectPaintedOutcomeRoutes(page);
  await expect(page.getByRole("navigation", { name: "Focused connected path" })).toHaveCount(0);
  const draftBefore = await page.evaluate(() => window.localStorage.getItem("bluefire.local.scenario.v1"));
  await viewOptions(page, true);
  await page.getByLabel("Show input connections", { exact: true }).check();
  await viewOptions(page, false);
  expect(await page.evaluate(() => window.localStorage.getItem("bluefire.local.scenario.v1"))).toBe(draftBefore);
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await expect(page.locator(".palette-panel")).toBeVisible();
  await page.getByRole("button", { name: "Show node inspector" }).click();
  await expect(page.locator(".palette-panel")).toBeHidden();
  await expect(page.locator(".inspector-panel")).toBeVisible();
  await page.getByRole("button", { name: "Hide node inspector" }).click();
  await expect(page.locator(".inspector-panel")).toBeHidden();

  await page.getByRole("button", { name: "Auto-layout" }).click();
  await expect(page.getByText("Steps arranged by their connections. Use Undo to restore your positions.")).toBeVisible();
  await page.getByRole("button", { name: "Fit visible graph" }).click();
  await viewOptions(page, true);
  await page.getByRole("button", { name: "Focus selected step" }).click();
  await expect(page.getByRole("button", { name: "Commands", exact: true })).toBeVisible();
  await viewOptions(page, false);

  await page.getByRole("button", { name: "Enter graph focus mode" }).click();
  await expect(page.locator(".builder-page")).toHaveClass(/builder-focus/);
  await expect(page.getByText("Esc to exit")).toBeVisible();
  await page.keyboard.press("Control+K");
  const commandDialog = page.getByRole("dialog", { name: "Builder commands" });
  await expect(commandDialog).toBeVisible();
  await expect(commandDialog.locator(".builder-command-list > button")).toHaveCount(9);
  for (const action of ["Auto-layout", "Fit visible graph", "Focus selected step", "Show behavior palette", "Show node inspector", "Exit graph focus mode", "Validate graph", "Undo", "Redo"]) await expect(commandDialog.getByRole("button", { name: new RegExp(`^${action}`) })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(commandDialog).toBeHidden();
  await expect(page.locator(".builder-page")).toHaveClass(/builder-focus/);
  await page.keyboard.press("Escape");
  await expect(page.locator(".builder-page")).not.toHaveClass(/builder-focus/);

  const nodes = page.locator(".react-flow__node"); const initial = await nodes.count();
  expect(initial).toBe(7);
  const deleteDialog = page.getByRole("dialog", { name: "Delete from experiment?" });
  await viewOptions(page, true);
  await expect(page.getByRole("group", { name: "Selection tools" })).toBeVisible();
  await page.getByRole("button", { name: "Delete selected node" }).click();
  await expect(deleteDialog).toBeVisible();
  await expect(deleteDialog.getByText("Place deterministic fixture", { exact: true })).toBeVisible();
  await expect(deleteDialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
  await deleteDialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(deleteDialog).toBeHidden();
  await expect(page.getByRole("button", { name: "Delete selected node" })).toBeFocused();
  await expect(page.getByRole("button", { name: "Delete selected node" })).toBeVisible();
  await expect(nodes).toHaveCount(initial);

  await page.getByRole("button", { name: "Delete selected node" }).click();
  await expect(deleteDialog).toBeVisible();
  await deleteDialog.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(deleteDialog).toBeHidden();
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
  await viewOptions(page, true);
  await expect(page.getByRole("button", { name: "Focus on success path", exact: true })).toBeVisible();
  await viewOptions(page, false);
  await expect(nodes).toHaveCount(initial - 1);
  await expect(page.locator('.react-flow__node[data-id="place_fixture"]')).toHaveCount(0);
});

test("keyboard selection, copy and deletion follow the focused step", async ({ page }) => {
  await page.goto("./#/builder");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(demoScenario.steps.length);
  const first = page.locator('.react-flow__node[data-id="place_fixture"]');
  const second = page.locator('.react-flow__node[data-id="run_fixture"]');
  await second.focus();
  await page.keyboard.press("Enter");
  await expect(second).toHaveClass(/selected/);
  await expect(first).not.toHaveClass(/selected/);
  await page.keyboard.press("Control+c");
  await expect(page.locator(".compatibility-banner")).toContainText("Run reviewed fixture program copied.");
  await expect(page.locator("details.graph-options")).toHaveJSProperty("open", false);
  await second.focus();
  await page.keyboard.press("Delete");
  const deleteDialog = page.getByRole("dialog", { name: "Delete from experiment?" });
  await expect(deleteDialog.getByText("Run reviewed fixture program", { exact: true })).toBeVisible();
  await expect(deleteDialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
  await deleteDialog.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(second).toHaveCount(0);
  await expect(first).toHaveCount(1);
  await expect(first).toHaveClass(/selected/);
  await expect(first).toBeFocused();
  await viewOptions(page, true);
  await expect(page.getByRole("group", { name: "Selection tools" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete selected node" })).toBeEnabled();
  await viewOptions(page, false);
  await page.getByRole("button", { name: "Undo", exact: true }).click();
  await expect(second).toHaveCount(1);
  await expect(first).toHaveCount(1);
});

test("keyboard selection retains focus and text fields keep native copy", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("./#/builder");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(demoScenario.steps.length);
  for (const [id, title] of [["run_fixture", "Run reviewed fixture program"], ["place_fixture", "Place deterministic fixture"], ["run_fixture", "Run reviewed fixture program"]] as const) {
    const node = page.locator(`.react-flow__node[data-id="${id}"]`);
    await node.focus();
    await page.keyboard.press("Enter");
    await expect(node).toHaveClass(/selected/);
    await expect(node).toBeFocused();
    await page.keyboard.press("Control+c");
    await expect(page.locator(".compatibility-banner")).toContainText(`${title} copied.`);
    await expect(node).toBeFocused();
  }
  const name = page.getByRole("textbox", { name: "Experiment name", exact: true });
  await name.fill("Native text clipboard");
  await name.press("Control+a");
  await page.keyboard.press("Control+c");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Native text clipboard");
  await expect(name).toBeFocused();
  await expect(page.locator(".compatibility-banner")).toContainText("Run reviewed fixture program copied.");
});

test("laptop canvas and step details fit the viewport without losing the experiment", async ({ page }) => {
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    await page.setViewportSize(viewport);
    await page.goto("./#/builder");
    await expect(page.getByRole("heading", { name: "Endpoint control validation", level: 1 })).toBeVisible();
    await expect(page.locator(".react-flow__node:visible")).toHaveCount(demoScenario.steps.length);
    await expect(page.locator(".graph-disclosure")).toHaveCount(0);
    await expect(page.getByRole("navigation", { name: "Focused connected path" })).toHaveCount(0);
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
  await expect(page.getByRole("button", { name: "Canvas", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await expect(page.getByRole("list", { name: "Experiment steps" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Review run" })).toBeVisible();
  await expect(page.locator(".inspector-panel")).toBeHidden();
});

test("large branched experiments keep complete data while optionally focusing connected paths", async ({ page }) => {
  await page.goto("./#/builder");
  for (let index = 0; index < 18; index += 1) {
    await page.getByRole("button", { name: "Add step", exact: true }).click();
    await page.locator(".palette-list > button").first().click();
  }
  await viewOptions(page, true);
  const section = page.getByRole("combobox", { name: "Step group", exact: true });
  await expect(section).toBeVisible();
  const serialized = await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"));
  const complete = JSON.parse(serialized!);
  expect(complete.steps.length).toBeGreaterThanOrEqual(25);
  expect(complete.edges.some((edge: { outcome: string }) => edge.outcome === "blocked")).toBe(true);
  await expect(page.locator(".react-flow__node")).toHaveCount(complete.steps.length);
  await section.selectOption("0");
  await viewOptions(page, false);
  await expect(page.getByRole("navigation", { name: "Focused connected path" })).toBeVisible();
  const focusedIds = await page.locator(".react-flow__node").evaluateAll(nodes => nodes.map(node => node.getAttribute("data-id")));
  expect(focusedIds.length).toBeGreaterThan(0);
  expect(focusedIds.length).toBeLessThan(complete.steps.length);
  for (const [index, id] of focusedIds.entries()) {
    if (index === 0) continue;
    expect(complete.edges.some((edge: { from_step: string; to_step: string }) => edge.from_step === focusedIds[index - 1] && edge.to_step === id)).toBe(true);
  }
  await page.getByRole("button", { name: "Return to whole plan", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(complete.steps.length);
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(complete.steps.length);
  expect(await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"))).toBe(serialized);
  await page.reload();
  await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(complete.steps.length);
  await expect(page.getByRole("navigation", { name: "Focused connected path" })).toHaveCount(0);
  await page.getByRole("button", { name: "Canvas", exact: true }).click();
  await viewOptions(page, true);
  await expect(section).toBeVisible();
  await expect(section).toHaveValue("all");
  await section.selectOption("0");
  await viewOptions(page, false);
  await page.reload();
  await viewOptions(page, true);
  await expect(section).toHaveValue("0");
  expect(await page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"))).toBe(serialized);
  expect(await page.locator(".react-flow__node").evaluateAll(nodes => nodes.map(node => node.getAttribute("data-id")))).toEqual(focusedIds);
});

test("Execute approval cannot bypass canonical review and legacy authority is scrubbed after reload", async ({ page }) => {
  await page.goto("./#/runs");
  await expect(page.getByRole("heading", { name: "Runs", level: 1 })).toBeVisible();
  await page.getByRole("link", { name: "Review new run", exact: true }).click();
  await page.getByRole("radio", { name: /Execute/ }).check();
  await page.getByText("Policy, approval & budgets").click();
  const approval = page.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ });
  const operator = page.getByRole("textbox", { name: "Prepared operator label" });
  await expect(approval).toHaveCount(0);
  await expect(operator).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create approval-gated job" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Approve and release job" })).toHaveCount(0);

  await page.getByRole("button", { name: "Check run" }).click();
  await expect(page.getByText("Demo mode previews Execute configuration but never dispatches runner effects.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create approval-gated job" })).toBeDisabled();

  await page.evaluate(() => window.localStorage.setItem("bluefire.local.run-config.v1", JSON.stringify({ mode: "execute", approved: true, approvedBy: "persisted-e2e" })));
  await page.reload();
  await expect(page.getByRole("radio", { name: "Simulate Synthetic evidence only" })).toBeChecked();
  await expect(page.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ })).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => JSON.parse(window.localStorage.getItem("bluefire.local.run-config.v1") ?? "{}"))).toEqual({
    schema_version: "bluefire.ui-preferences.v1",
    theme: "dark",
    effect_mode: "simulate",
    autonomy: "off",
  });
});
