import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// Starts the app's service on a fresh workspace and hands the address it
// prints to the tests. BLUEFIRE_PYTHON names the Python that has the app's
// dependencies; the service runs from this checkout's source.
export default async function startService() {
  const repository = resolve(process.cwd(), "..");
  const workspace = mkdtempSync(join(tmpdir(), "bluefire-service-"));
  const service = spawn(
    process.env.BLUEFIRE_PYTHON ?? "python3",
    ["-m", "bluefire.cli", "--runs-dir", workspace, "ui", "--no-browser"],
    { cwd: repository, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  process.env.BLUEFIRE_SERVICE_URL = await new Promise<string>((ready, failed) => {
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

  return async () => {
    service.kill("SIGINT");
    await new Promise(stopped => service.once("exit", stopped));
    rmSync(workspace, { recursive: true, force: true });
  };
}
