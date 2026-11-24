import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * Starts the app's service on a fresh workspace and gives the address it
 * prints, with its one-time connection code, and a way to stop it.
 * BLUEFIRE_PYTHON names the Python that has the app's dependencies; the
 * service runs from this checkout's source.
 */
export async function launchService(port = 8765): Promise<{ url: string; stop: () => Promise<void> }> {
  const repository = resolve(process.cwd(), "..");
  const workspace = mkdtempSync(join(tmpdir(), "bluefire-service-"));
  const service = spawn(
    process.env.BLUEFIRE_PYTHON ?? "python3",
    ["-m", "bluefire.cli", "--runs-dir", workspace, "ui", "--no-browser", "--port", String(port)],
    { cwd: repository, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  const url = await new Promise<string>((ready, failed) => {
    const read = (chunk: Buffer) => {
      output += chunk.toString();
      const address = output.match(/http:\/\/127\.0\.0\.1:\d+\/\S*#bluefire-session=\S+/);
      if (address) ready(address[0]);
    };
    service.stdout.on("data", read);
    service.stderr.on("data", read);
    service.once("exit", code => failed(new Error(`the service stopped with ${code} before it printed its address:\n${output}`)));
    setTimeout(() => failed(new Error(`the service printed no address in 40 seconds:\n${output}`)), 40_000);
  });

  return {
    url,
    stop: async () => {
      service.kill("SIGINT");
      await new Promise(stopped => service.once("exit", stopped));
      rmSync(workspace, { recursive: true, force: true });
    },
  };
}

// The tests' own service: its address goes to the tests that walk the screens.
export default async function startService() {
  const { url, stop } = await launchService();
  process.env.BLUEFIRE_SERVICE_URL = url;
  return stop;
}
