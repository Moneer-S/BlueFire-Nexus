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
const MAX_REPORT_BYTES = 24 * 1024;
const CAPABILITY_FRAGMENT = /^#bluefire-session=([A-Za-z0-9_-]{64})$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);
const SOURCE_PIN = "8543c5b05bd9bbcace9fc37f30bba96b675b6f33"; // pragma: allowlist secret -- public Git commit
const SOURCE_PATH = "bluefire/data/mitre_attack_t1082_v19_2.json";
const LICENSE_PATH = "bluefire/data/mitre_attack_v19_2_LICENSE.txt";
const BEHAVIOR_ID = "research.attack.system-information-discovery.v1";
const ACTION_ID = "research.attack.system-information-discovery-action.v1";
const INTAKE_ID = "intake.mitre-t1082.v1";
const INTAKE_DESTINATION_ID = "gate09-browser-reviewed-t1082";
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const STABLE_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const OPERATION_SEQUENCE = [
  "bootstrap_production_session",
  "open_research_sources",
  "verify_pinned_source",
  "expand_intake_review",
  "configure_reviewed_intake",
  "activate_reviewed_intake",
  "open_behaviors",
  "verify_imported_behavior",
  "verify_behavior_provenance",
  "reload_and_verify_persisted_state",
];
const REPORT_KEYS = [
  "action_id",
  "activation_operation",
  "attribution_visible",
  "behavior_id",
  "behavior_provenance_reference",
  "behavior_provenance_visible",
  "demo_mode",
  "execution_state",
  "imported_paths",
  "intake_destination_id",
  "intake_record_sha256",
  "intake_state_ref",
  "observed_at",
  "operation_receipt_sha256",
  "operation_receipt_state_ref",
  "operation_receipt_visible",
  "operation_sequence",
  "origin",
  "production_browser_interaction",
  "runner_profile_id",
  "schema_version",
  "source_classification",
  "source_content_handling",
  "source_id",
  "source_license",
  "source_pin",
  "source_project",
  "source_version",
  "technique_id",
  "transformation_visible",
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

function validateReport(path, launch, capability, expectedProfileId, expectedRecordSha256) {
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
  if (
    !sameKeys(report, REPORT_KEYS)
    || report.schema_version !== "bluefire.source-intake-production-browser.v1"
    || report.production_browser_interaction !== true
    || report.demo_mode !== false
    || report.origin !== launch.origin
    || report.source_id !== "research.mitre-attack-enterprise.v1"
    || report.source_project !== "mitre/cti"
    || report.source_version !== "19.2"
    || report.source_pin !== SOURCE_PIN
    || report.source_license !== "LicenseRef-MITRE-ATTACK-2026"
    || report.source_classification !== "metadata_import"
    || report.source_content_handling !== "vendored_declarative"
    || JSON.stringify(report.imported_paths) !== JSON.stringify([SOURCE_PATH, LICENSE_PATH])
    || report.attribution_visible !== true
    || report.transformation_visible !== true
    || report.behavior_id !== BEHAVIOR_ID
    || report.behavior_provenance_visible !== true
    || report.behavior_provenance_reference !== `urn:bluefire:source-intake:${INTAKE_ID}:sha256:${expectedRecordSha256.slice("sha256:".length)}`
    || report.technique_id !== "T1082"
    || report.action_id !== ACTION_ID
    || report.activation_operation !== "already_active_revalidated"
    || report.execution_state !== "action"
    || report.intake_destination_id !== INTAKE_DESTINATION_ID
    || report.intake_record_sha256 !== expectedRecordSha256
    || report.intake_state_ref !== `source-intakes/${INTAKE_DESTINATION_ID}/${INTAKE_ID}.json`
    || report.operation_receipt_visible !== true
    || !SHA256.test(report.operation_receipt_sha256)
    || report.operation_receipt_state_ref !== `source-intakes/${INTAKE_DESTINATION_ID}/${INTAKE_ID}.operation-receipt.json`
    || report.runner_profile_id !== expectedProfileId
    || JSON.stringify(report.operation_sequence) !== JSON.stringify(OPERATION_SEQUENCE)
    || typeof report.observed_at !== "string"
    || Number.isNaN(Date.parse(report.observed_at))
    || raw.includes(capability)
    || raw.includes(launch.href)
  ) {
    throw new JourneyError("The browser report did not prove the production source-intake journey.");
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
    throw new JourneyError("Usage: run_source_intake_browser_journey.mjs --report <new-absolute-json-path>");
  }
  const rawLaunchUrl = process.env.BLUEFIRE_PRODUCTION_URL;
  if (!rawLaunchUrl) throw new JourneyError("BLUEFIRE_PRODUCTION_URL is required.");
  const expectedProfileId = process.env.BLUEFIRE_GATE09_PROFILE_ID;
  const expectedRecordSha256 = process.env.BLUEFIRE_GATE09_EXPECTED_RECORD_SHA256;
  if (!expectedProfileId || expectedProfileId.length > 200 || !STABLE_ID.test(expectedProfileId)) {
    throw new JourneyError("BLUEFIRE_GATE09_PROFILE_ID is invalid.");
  }
  if (!expectedRecordSha256 || !SHA256.test(expectedRecordSha256)) {
    throw new JourneyError("BLUEFIRE_GATE09_EXPECTED_RECORD_SHA256 is invalid.");
  }
  const { parsed: launch, capability } = validateLaunchUrl(rawLaunchUrl);
  const reportPath = validateReportPath(args[1]);

  const scriptPath = fileURLToPath(import.meta.url);
  const repository = resolve(dirname(scriptPath), "..");
  const frontend = join(repository, "frontend");
  const config = join(frontend, "playwright.source-intake.config.ts");
  const playwrightCli = join(frontend, "node_modules", "@playwright", "test", "cli.js");
  if (!existsSync(config) || !existsSync(playwrightCli)) {
    throw new JourneyError("The local Playwright harness or dependency is unavailable.");
  }

  const artifactPrefix = join(dirname(reportPath), ".bluefire-source-intake-browser-");
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
    "source-intake-production.spec.ts",
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
      && artifactRelativePath.startsWith(".bluefire-source-intake-browser-")
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
  validateReport(reportPath, launch, capability, expectedProfileId, expectedRecordSha256);
  process.stdout.write("Gate09 production browser journey completed.\n");
}

run().catch((error) => {
  const message = error instanceof JourneyError
    ? error.message
    : "The production browser journey failed unexpectedly.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
