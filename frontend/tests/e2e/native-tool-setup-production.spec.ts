import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import process from "node:process";
import { URL } from "node:url";
import { expect, test, type Locator, type Page } from "@playwright/test";

// Run serially against a fresh production service with isolated product state
// and no enrolled local runner. One browser session consumes the launch token
// once; all profile changes below use visible product controls.
const VIEWPORTS = [
  { width: 1440, height: 900 },
  { width: 1366, height: 768 },
  { width: 1024, height: 768 },
] as const;
const GZIP_ACTION = "sandbox.collection.atomic-gzip.v1";
const VERSION = "1.12-1ubuntu3.2";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Native-tool browser test is missing ${name}.`);
  return value;
}

function validatedLaunchUrl(): URL {
  let parsed: URL;
  try { parsed = new URL(requiredEnvironment("BLUEFIRE_PRODUCTION_URL")); }
  catch { throw new Error("The production launch URL is invalid."); }
  if (parsed.protocol !== "http:" || !["127.0.0.1", "[::1]", "::1"].includes(parsed.hostname)
    || parsed.username || parsed.password || parsed.search
    || !["/", "/index.html"].includes(parsed.pathname)
    || !/^#bluefire-session=[A-Za-z0-9_-]{64}$/.test(parsed.hash)) {
    throw new Error("A constrained HTTP loopback browser-capability launch URL is required.");
  }
  if (process.env.VITE_DEMO_MODE === "true") throw new Error("This test requires the production UI, not demo mode.");
  return parsed;
}

async function screenshotDirectory(): Promise<string> {
  const value = requiredEnvironment("BLUEFIRE_BROWSER_SCREENSHOT_DIR");
  if (!isAbsolute(value) || await fs.realpath(value) !== resolve(value)) {
    throw new Error("The screenshot directory must be an existing absolute, non-aliased path.");
  }
  const entry = await fs.lstat(value);
  if (!entry.isDirectory() || entry.isSymbolicLink()) throw new Error("The screenshot path must be a regular directory.");
  return value;
}

async function capture(page: Page, directory: string, name: string): Promise<void> {
  // Never retain a capability fragment in browser artifacts, including on failure.
  if (new URL(page.url()).hash.includes("bluefire-session")) throw new Error("The launch fragment was not scrubbed.");
  const output = await fs.open(join(directory, name), "wx", 0o600);
  try { await output.writeFile(await page.screenshot({ fullPage: false })); }
  finally { await output.close(); }
}

async function checkHorizontalFit(page: Page, dialog: Locator, label: string): Promise<void> {
  const sizes = await dialog.evaluate((element) => ({
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: document.documentElement.clientWidth,
    dialogWidth: element.clientWidth,
    contentWidth: element.scrollWidth,
    left: element.getBoundingClientRect().left,
    right: element.getBoundingClientRect().right,
  }));
  expect.soft(sizes.documentWidth, `${label}: document horizontal overflow`).toBeLessThanOrEqual(sizes.viewportWidth + 1);
  expect.soft(sizes.contentWidth, `${label}: dialog horizontal overflow`).toBeLessThanOrEqual(sizes.dialogWidth + 1);
  expect.soft(sizes.left, `${label}: dialog left edge`).toBeGreaterThanOrEqual(0);
  expect.soft(sizes.right, `${label}: dialog right edge`).toBeLessThanOrEqual(page.viewportSize()!.width + 1);
}

async function reachable(control: Locator): Promise<void> {
  // Ordinary browser scrolling only; do not resize the dialog or alter CSS.
  await control.scrollIntoViewIfNeeded();
  await expect(control).toBeVisible();
  await expect.soft(control).toBeInViewport({ ratio: 1 });
}

function profileCard(page: Page, id: string): Locator {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return page.getByRole("region", { name: new RegExp(`\\(${escaped}\\)$`) });
}

async function expectUnboundDraft(card: Locator): Promise<void> {
  await expect(card.getByText("Draft", { exact: true })).toBeVisible();
  await expect(card.getByRole("button", { name: /^Validate & activate / })).toBeVisible();
  await expect(card.getByRole("button", { name: /^Deactivate / })).toHaveCount(0);
  await expect(card.getByText("GNU gzip binding", { exact: true }).locator(".."))
    .toContainText("Not configured");
}

test.use({ trace: "off", video: "off", screenshot: "off", serviceWorkers: "block" });

test("production gzip setup stays usable and refuses saving without a local runner", async ({ page }) => {
  test.setTimeout(180_000);
  const launch = validatedLaunchUrl();
  const directory = await screenshotDirectory();
  const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.name));
  await page.setViewportSize(VIEWPORTS[0]);
  try { await page.goto(launch.href, { waitUntil: "domcontentloaded" }); }
  catch { throw new Error("The production browser launch did not complete; the capability URL is withheld."); }
  await expect.poll(() => new URL(page.url()).hash.includes("bluefire-session=")).toBe(false);
  await expect(page.getByRole("img", { name: "Local service connected", exact: true }).first()).toBeVisible();

  // Observe requests generated by the UI, without issuing or intercepting any.
  const mutations: string[] = [];
  page.on("request", (request) => {
    if (!["GET", "HEAD", "OPTIONS"].includes(request.method())) {
      mutations.push(new URL(request.url()).pathname);
    }
  });
  const expectedMutations: string[] = [];
  for (const viewport of VIEWPORTS) {
    const size = `${viewport.width}x${viewport.height}`;
    await test.step(`Inactive GNU gzip setup at ${size}`, async () => {
      await page.setViewportSize(viewport);
      expect(await page.evaluate(() => window.visualViewport?.scale ?? 1)).toBe(1);
      const navigation = page.getByRole("navigation", { name: "Primary navigation" });
      await navigation.getByRole("link", { name: "Settings", exact: true }).click();
      await navigation.getByRole("link", { name: "Runner Profiles", exact: true }).click();
      await expect(page.getByRole("heading", { name: "Runner profiles", exact: true })).toBeVisible();
      await page.getByRole("button", { name: "New profile", exact: true }).click();
      const form = page.getByRole("dialog", { name: "Draft runner profile" });
      await form.getByLabel(/^Configuration template/).selectOption("sandbox-execute.v1");
      const id = `gzip-ui-${size}-${suffix}.v1`;
      await form.getByLabel(/^Profile ID/).fill(id);
      await form.getByRole("combobox", { name: "Platform", exact: true }).selectOption("linux");
      const gzip = form.getByRole("checkbox", { name: /Compress selected records.*Atomic gzip/i });
      await gzip.check();
      await expect(gzip).toBeChecked();
      const chmod = form.getByRole("checkbox", { name: /Change sample file permissions.*GNU chmod/i });
      if (await chmod.count()) { await chmod.check(); await expect(chmod).toBeChecked(); }
      await reachable(form.getByRole("button", { name: "Save profile draft", exact: true }));
      await form.getByRole("button", { name: "Save profile draft", exact: true }).click();
      expectedMutations.push(`/api/v1/resources/runner-profiles/${id}`);
      await expect(form).toBeHidden();
      let card = profileCard(page, id);
      await expectUnboundDraft(card);
      const trigger = card.getByRole("button", { name: /^Set up GNU gzip for / });
      await trigger.click();
      const dialog = page.getByRole("dialog", { name: "Set up GNU gzip", exact: true });
      await expect(dialog).toContainText(id);
      await expect(dialog).toContainText("Ubuntu Noble, Linux amd64");
      await expect(dialog).toContainText("1.12-1ubuntu3.1 or 1.12-1ubuntu3.2");
      await expect(dialog).toContainText("Inspection does not execute gzip or activate the profile.");
      const location = dialog.getByRole("textbox", { name: "Installation location", exact: true });
      const version = dialog.getByRole("textbox", { name: "Declared GNU version", exact: true });
      const inspect = dialog.getByRole("button", { name: "Inspect installation", exact: true });
      const save = dialog.getByRole("button", { name: "Save tool binding", exact: true });
      await expect(location).toHaveValue("/usr/bin/gzip");
      await expect(version).toHaveValue("");
      await expect(inspect).toBeDisabled();
      await expect(save).toBeDisabled();
      await capture(page, directory, `native-tool-gzip-${size}-initial.png`);
      await checkHorizontalFit(page, dialog, `${size} initial`);
      await location.click();
      await page.keyboard.press("Tab");
      await expect(version).toBeFocused();
      await page.keyboard.type(VERSION);
      await expect(version).toHaveValue(VERSION);
      await reachable(inspect);
      const inspectionPath = `/api/v1/resources/runner-profiles/${id}/inspect-native-tool`;
      const responsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === inspectionPath && response.request().method() === "POST");
      await inspect.click();
      const response = await responsePromise;
      expectedMutations.push(inspectionPath);
      expect(response.request().postDataJSON()).toEqual({
        schema_version: "bluefire.native-tool-candidate.v1", action_id: GZIP_ACTION,
        installation_location: "/usr/bin/gzip", tool_version: VERSION,
      });
      expect(response.status()).toBe(409);
      const refusal = dialog.getByRole("alert");
      await expect(refusal).toHaveText("Start the local runner in Runners, then inspect this installation. The draft does not need activation.");
      await reachable(refusal);
      await capture(page, directory, `native-tool-gzip-${size}-unavailable.png`);
      await checkHorizontalFit(page, dialog, `${size} unavailable`);
      await expect(save).toBeDisabled();
      await expect(dialog.getByRole("status", { name: "Reviewed GNU build verified" })).toHaveCount(0);
      await reachable(save);
      const cancel = dialog.getByRole("button", { name: "Cancel", exact: true });
      await reachable(cancel);
      await cancel.click();
      await expect(dialog).toBeHidden();
      await expect(trigger).toBeFocused();
      await expectUnboundDraft(card);
      await page.reload({ waitUntil: "domcontentloaded" });
      card = profileCard(page, id);
      await expectUnboundDraft(card);
      await expect(card.getByRole("button", { name: /^Set up GNU gzip for / })).toBeEnabled();
    });
  }
  expect(mutations).toEqual(expectedMutations);
  expect(pageErrors, "No browser runtime errors during the setup journey").toEqual([]);
});
