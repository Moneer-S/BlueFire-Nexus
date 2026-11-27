import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { launchService } from "./start-service";

// In a window 700 pixels high the app's page of a recorded run grows with the
// live view and scrolls, the transport stuck at the window's foot. Each line of
// the step's words is then whole above the transport or under it, never cut in
// half by it, and scrolling to the page's end brings every line above it.

interface Step { id: string; title: string; outcome: string }
interface Recording { steps: Step[] }

const repository = resolve(process.cwd(), "..");
const linux: Recording = JSON.parse(readFileSync(join(repository, "bluefire/data/recordings/lab-linux-host.json"), "utf-8"));
const LINES = [".lv-kicker", ".lv-plain", ".lv-verdict", ".lv-pair", ".lv-fix-hint"];
let service: Awaited<ReturnType<typeof launchService>> | undefined;

test.beforeAll(async () => {
  test.setTimeout(180_000);
  service = await launchService(8771);
});

test.afterAll(async () => {
  await service?.stop();
});

/** Each line of the step's words that the transport covers in part: its name, its top and bottom, and the transport's top. */
async function cutLines(page: Page): Promise<string[]> {
  return page.evaluate((lines) => {
    const bar = document.querySelector(".lv-transport")?.getBoundingClientRect();
    if (!bar) return ["no transport"];
    const cut: string[] = [];
    for (const selector of lines) {
      const line = document.querySelector(`.lv-caption ${selector}`);
      if (!line) continue;
      const box = line.getBoundingClientRect();
      if (box.height === 0) continue;
      // Whole above the transport, or not above it at all.
      if (box.bottom > bar.top + 0.5 && box.top < bar.top - 0.5) cut.push(`${selector} ${Math.round(box.top)}..${Math.round(box.bottom)} under a transport from ${Math.round(bar.top)}`);
    }
    return cut;
  }, LINES);
}

/** Each line of the step's words that is not whole above the transport. */
async function linesBelowTheTransport(page: Page): Promise<string[]> {
  return page.evaluate((lines) => {
    const bar = document.querySelector(".lv-transport")?.getBoundingClientRect();
    if (!bar) return ["no transport"];
    return lines.flatMap((selector) => {
      const line = document.querySelector(`.lv-caption ${selector}`);
      const box = line?.getBoundingClientRect();
      return box && box.height > 0 && box.bottom > bar.top + 0.5 ? [`${selector} ${Math.round(box.top)}..${Math.round(box.bottom)} under a transport from ${Math.round(bar.top)}`] : [];
    });
  }, LINES);
}

test("in the app at 1366 by 700 the transport never cuts a line of the unseen test's words, and scrolling to the end shows them all", async ({ page }) => {
  test.setTimeout(180_000);
  const unseen = linux.steps.find((step) => step.outcome === "unseen");
  if (!unseen) throw new Error("The run on one Linux machine should hold its unseen test.");
  await page.setViewportSize({ width: 1366, height: 700 });
  await page.goto(service?.url ?? "");
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Runs", exact: true }).click();
  const item = page.getByRole("region", { name: "Recorded runs" }).getByRole("listitem").filter({ hasText: "60 published tests on one Linux host" });
  await item.getByRole("link", { name: "60 published tests on one Linux host", exact: true }).click();
  await expect(page).toHaveURL(/#\/runs\/recorded\/[A-Za-z0-9_-]+/);

  // Opened afresh twice, paused late in the step: the layout must not depend on what was measured first.
  for (const attempt of [1, 2]) {
    await page.goto(page.url().replace(/(#\/runs\/recorded\/[A-Za-z0-9_-]+).*$/, `$1?step=${unseen.id}&at=1&paused=1`));
    await page.reload();
    await expect(page.locator(".lv-caption .lv-word")).toHaveText("unseen");
    // The view settles its plan of the room after a frame or two.
    await page.waitForTimeout(1500);
    await page.evaluate(() => window.scrollTo(0, 0));
    expect(await cutLines(page), `load ${attempt}, at the top of the page`).toEqual([]);
    await page.evaluate(() => window.scrollTo(0, document.scrollingElement?.scrollHeight ?? 0));
    await page.waitForTimeout(300);
    expect(await linesBelowTheTransport(page), `load ${attempt}, at the page's end`).toEqual([]);
  }
});
