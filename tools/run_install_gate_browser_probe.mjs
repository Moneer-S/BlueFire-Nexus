import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const TOKEN = /^[A-Za-z0-9_-]{64}$/;
const INPUT_LIMIT = 256;

export async function readCapability(input) {
  let raw = "";
  for await (const chunk of input) {
    raw += chunk.toString("utf8");
    if (Buffer.byteLength(raw, "utf8") > INPUT_LIMIT) throw new Error("invalid input");
  }
  const value = JSON.parse(raw);
  if (!value || Object.keys(value).length !== 1 || typeof value.capability !== "string" || !TOKEN.test(value.capability)) {
    throw new Error("invalid input");
  }
  return value.capability;
}

export async function guardRoute(route, origin) {
  let response;
  try {
    if (new URL(route.request().url()).origin !== origin) { await route.abort(); return; }
    response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15_000 });
    if (response.status() >= 300 && response.status() < 400) { await route.abort(); return; }
    await route.fulfill({ response });
  } catch { await route.abort().catch(() => {}); }
  finally { if (response) await response.dispose(); }
}

export async function probe(chromium, settings, capability) {
  if (!TOKEN.test(capability) || !Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535) {
    throw new Error("invalid probe settings");
  }
  const origin = `http://127.0.0.1:${settings.port}`;
  // Playwright owns the private debugging pipe; no remotely accessible control port.
  const context = await chromium.launchPersistentContext(settings.profile, {
    executablePath: settings.edge,
    headless: true,
    chromiumSandbox: false,
    serviceWorkers: "block",
    viewport: { width: 1365, height: 900 },
    args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"],
  });
  try {
    context.setDefaultTimeout(15_000);
    context.setDefaultNavigationTimeout(15_000);
    await context.route("**/*", route => guardRoute(route, origin));
    await context.routeWebSocket("**/*", socket => socket.close());
    const page = context.pages()[0] ?? await context.newPage();
    await page.goto(`${origin}/`, { waitUntil: "domcontentloaded" });
    await page.getByRole("heading", { name: "Connect to your workspace", exact: true }).waitFor({ state: "visible" });
    if (page.url() !== `${origin}/`) throw new Error("connection page changed origin or route");
    await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    capability = "";
    await page.getByText("Local service connected", { exact: true }).waitFor({ state: "visible" });
    await page.getByRole("heading", { name: "Recent runs", exact: true }).waitFor({ state: "visible" });
    await page.getByRole("link", { name: "Open experiments", exact: true }).waitFor({ state: "visible" });
    await page.getByRole("link", { name: "Detection Lab", exact: true }).waitFor({ state: "visible" });
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.getByText("Local service connected", { exact: true }).waitFor({ state: "visible" });
    const separateTab = await context.newPage();
    await separateTab.goto(`${origin}/`, { waitUntil: "domcontentloaded" });
    await separateTab.getByRole("heading", { name: "Connect to your workspace", exact: true }).waitFor({ state: "visible" });
    await separateTab.close();
    await page.goto(`${origin}/#/runs?setup=execute`, { waitUntil: "domcontentloaded" });
    await page.getByRole("region", { name: "Guided local Execute", exact: true }).waitFor({ state: "visible" });
    for (const heading of ["Prepare, review, and run", "Make the local runner ready", "Run, observe, and clean up"]) {
      await page.getByText(heading, { exact: true }).waitFor({ state: "visible" });
    }
    return {
      engine: "edge-headless",
      browser_sandbox: "disabled-for-ephemeral-probe",
      network_scope: "loopback-only",
      javascript_executed: true,
      authenticated_root_rendered: true,
      catalog_data_rendered: true,
      runs_navigation_present: true,
      runs_route_rendered: true,
      guided_execute_rendered: true,
      explicit_connection_form: true,
      same_tab_reload_authenticated: true,
      new_tab_requires_connection: true,
    };
  } finally { await context.close(); }
}

async function main() {
  const [modulePath, edge, profile, rawPort] = process.argv.slice(2);
  if (process.argv.length !== 6 || ![modulePath, edge, profile].every(path => typeof path === "string" && isAbsolute(path))
      || !/^[0-9]{1,5}$/.test(rawPort ?? "") || Number(process.versions.node.split(".")[0]) < 22) throw new Error("invalid runtime");
  const metadata = JSON.parse(readFileSync(new URL("package.json", pathToFileURL(modulePath)), "utf8"));
  if (metadata.name !== "playwright-core") throw new Error("invalid browser module");
  const capability = await readCapability(process.stdin);
  const { chromium } = await import(pathToFileURL(modulePath).href);
  const report = await probe(chromium, { edge, profile, port: Number(rawPort) }, capability);
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const timeout = setTimeout(() => process.exit(2), 60_000);
  main().catch(() => { process.exitCode = 2; }).finally(() => clearTimeout(timeout));
}
