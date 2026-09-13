#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const TIMEOUT_MS = 120_000;
const MAX_PROCESS_OUTPUT_BYTES = 256 * 1024;
const MAX_REPORT_BYTES = 16 * 1024;
const CAPABILITY_FRAGMENT = /^#bluefire-session=([A-Za-z0-9_-]{64})$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);
const CANDIDATE_ID = /^detection-[0-9a-f]{20}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const FIXTURE_ID = /^gate07-browser-[0-9a-f]{16}$/;
const REPORT_KEYS = [
  "backend",
  "candidate_id",
  "demo_mode",
  "evaluated_fixture_ids",
  "matched_fixture_ids",
  "observed_at",
  "operation_sequence",
  "origin",
  "production_browser_interaction",
  "query_digest",
  "schema_version",
  "visible_state",
];
const BACKEND_KEYS = ["execution", "execution_version", "parser", "parser_version"];
const OPERATION_SEQUENCE = [
  "bootstrap_production_session",
  "open_detection_lab",
  "verify_sqlite_backend",
  "create_sqlite_hypothesis",
  "parse_sqlite_query",
  "execute_malicious_fixture",
  "reload_and_verify_persisted_state",
];

class JourneyError extends Error {}

function sameKeys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function validateLaunchUrl(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new JourneyError("BLUEFIRE_PRODUCTION_URL is not a valid URL.");
  }
  const capabilityMatch = parsed.hash.match(CAPABILITY_FRAGMENT);
  if (
    parsed.protocol !== "http:"
    || !LOOPBACK_HOSTS.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || parsed.search
    || !["/", "/index.html"].includes(parsed.pathname)
    || !capabilityMatch
  ) {
    throw new JourneyError("BLUEFIRE_PRODUCTION_URL must be a constrained loopback capability URL.");
  }
  return { parsed, capability: capabilityMatch[1] };
}

function validateReportPath(raw) {
  if (!isAbsolute(raw) || !raw.toLowerCase().endsWith(".json") || existsSync(raw)) {
    throw new JourneyError("The report must be a new absolute JSON path.");
  }
  const parent = dirname(raw);
  if (!existsSync(parent) || !lstatSync(parent).isDirectory() || realpathSync(parent) !== resolve(parent)) {
    throw new JourneyError("The report parent must be an existing non-aliased directory.");
  }
  return raw;
}

function validateReport(path, launch, capability) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_REPORT_BYTES) {
    throw new JourneyError("The browser report is missing or is not one bounded regular file.");
  }
  let report;
  let raw;
  try {
    raw = readFileSync(path, "utf8");
    report = JSON.parse(raw);
  } catch {
    throw new JourneyError("The browser report is not valid JSON.");
  }
  if (!sameKeys(report, REPORT_KEYS) || !sameKeys(report.backend, BACKEND_KEYS)) {
    throw new JourneyError("The browser report schema is not exact.");
  }
  if (
    report.schema_version !== "bluefire.detection-production-browser.v1"
    || report.production_browser_interaction !== true
    || report.demo_mode !== false
    || report.origin !== launch.origin
    || !CANDIDATE_ID.test(report.candidate_id)
    || report.visible_state !== "fixture_exercised"
    || !SHA256.test(report.query_digest)
    || report.backend.parser !== "SQLite bounded executor"
    || report.backend.execution !== "SQLite in-memory bounded executor"
    || typeof report.backend.parser_version !== "string"
    || !report.backend.parser_version
    || typeof report.backend.execution_version !== "string"
    || !report.backend.execution_version
    || !Array.isArray(report.evaluated_fixture_ids)
    || report.evaluated_fixture_ids.length !== 1
    || !FIXTURE_ID.test(report.evaluated_fixture_ids[0])
    || JSON.stringify(report.matched_fixture_ids) !== JSON.stringify(report.evaluated_fixture_ids)
    || JSON.stringify(report.operation_sequence) !== JSON.stringify(OPERATION_SEQUENCE)
    || typeof report.observed_at !== "string"
    || Number.isNaN(Date.parse(report.observed_at))
    || raw.includes(capability)
    || raw.includes(launch.href)
  ) {
    throw new JourneyError("The browser report did not prove the production SQLite UI journey.");
  }
}

function sanitized(value, launchUrl, capability) {
  return value
    .replaceAll(launchUrl, "<redacted-production-url>")
    .replaceAll(capability, "<redacted-capability>")
    .replace(/#bluefire-session=[A-Za-z0-9_-]{64}/g, "#bluefire-session=<redacted>");
}

function terminateProcessTree(child) {
  const pid = child.pid;
  if (!Number.isSafeInteger(pid) || pid <= 0) return;
  if (process.platform === "win32") {
    const systemRoot = process.env.SystemRoot;
    const taskkill = systemRoot ? join(systemRoot, "System32", "taskkill.exe") : "";
    if (taskkill && existsSync(taskkill)) {
      spawnSync(taskkill, ["/PID", String(pid), "/T", "/F"], {
        windowsHide: true,
        stdio: "ignore",
        timeout: 10_000,
      });
    }
    child.kill("SIGKILL");
    return;
  }
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}

function boundedCapture(stream, state, terminate) {
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    state.bytes += Buffer.byteLength(chunk, "utf8");
    if (state.bytes > MAX_PROCESS_OUTPUT_BYTES) {
      state.overflow = true;
      terminate();
      return;
    }
    state.text += chunk;
  });
}

async function run() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--report") {
    throw new JourneyError("Usage: run_detection_browser_journey.mjs --report <new-absolute-json-path>");
  }
  const rawLaunchUrl = process.env.BLUEFIRE_PRODUCTION_URL;
  if (!rawLaunchUrl) throw new JourneyError("BLUEFIRE_PRODUCTION_URL is required.");
  const { parsed: launch, capability } = validateLaunchUrl(rawLaunchUrl);
  const reportPath = validateReportPath(args[1]);

  const scriptPath = fileURLToPath(import.meta.url);
  const repository = resolve(dirname(scriptPath), "..");
  const frontend = join(repository, "frontend");
  const config = join(frontend, "playwright.detection.config.ts");
  const playwrightCli = join(frontend, "node_modules", "@playwright", "test", "cli.js");
  if (!existsSync(config) || !existsSync(playwrightCli)) {
    throw new JourneyError("The local Playwright harness or dependency is unavailable.");
  }

  const artifactPrefix = join(dirname(reportPath), ".bluefire-detection-browser-");
  const artifactRoot = mkdtempSync(artifactPrefix);
  const artifactIdentity = lstatSync(artifactRoot);
  const artifactDirectory = join(artifactRoot, "results");
  const childEnvironment = {
    ...process.env,
    BLUEFIRE_PRODUCTION_URL: rawLaunchUrl,
    BLUEFIRE_BROWSER_REPORT_PATH: reportPath,
    BLUEFIRE_BROWSER_ARTIFACT_DIR: artifactDirectory,
    VITE_DEMO_MODE: "false",
  };
  const child = spawn(process.execPath, [
    playwrightCli,
    "test",
    "--config",
    config,
    "detection-production.spec.ts",
    "--project=chromium",
  ], {
    cwd: frontend,
    env: childEnvironment,
    shell: false,
    detached: process.platform !== "win32",
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let terminationRequested = false;
  const terminate = () => {
    if (terminationRequested) return;
    terminationRequested = true;
    terminateProcessTree(child);
  };
  const stdout = { text: "", bytes: 0, overflow: false };
  const stderr = { text: "", bytes: 0, overflow: false };
  boundedCapture(child.stdout, stdout, terminate);
  boundedCapture(child.stderr, stderr, terminate);

  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    terminate();
  }, TIMEOUT_MS);
  let exit;
  try {
    exit = await new Promise((resolveExit, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolveExit({ code, signal }));
    });
  } finally {
    clearTimeout(timeout);
    const resolvedArtifacts = resolve(artifactRoot);
    const artifactRelativePath = relative(resolve(dirname(reportPath)), resolvedArtifacts);
    let currentArtifact;
    try {
      currentArtifact = lstatSync(resolvedArtifacts);
    } catch {
      currentArtifact = null;
    }
    if (
      currentArtifact?.isDirectory()
      && !currentArtifact.isSymbolicLink()
      && currentArtifact.dev === artifactIdentity.dev
      && currentArtifact.ino === artifactIdentity.ino
      && realpathSync(resolvedArtifacts) === resolvedArtifacts
      && artifactRelativePath.startsWith(".bluefire-detection-browser-")
      && !artifactRelativePath.includes("..")
      && !isAbsolute(artifactRelativePath)
    ) {
      rmSync(resolvedArtifacts, { recursive: true, force: true });
    }
  }

  if (timedOut) throw new JourneyError("The production browser journey exceeded its 120-second bound.");
  if (stdout.overflow || stderr.overflow) throw new JourneyError("The production browser journey exceeded its output bound.");
  if (exit.code !== 0) {
    const details = sanitized(`${stdout.text}\n${stderr.text}`, rawLaunchUrl, capability).trim();
    throw new JourneyError(`The production browser interaction failed.${details ? `\n${details}` : ""}`);
  }
  if (!existsSync(reportPath)) throw new JourneyError("The production browser interaction emitted no report.");
  validateReport(reportPath, launch, capability);
  process.stdout.write("Gate07 production browser journey completed.\n");
}

run().catch((error) => {
  const message = error instanceof JourneyError ? error.message : "The production browser journey failed unexpectedly.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
