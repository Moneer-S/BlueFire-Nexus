import { createReadStream, lstatSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, resolve } from "node:path";

// This listener serves only reviewed production assets. It has no API or authority.
export default async function setup() {
  const root = resolve(process.env.BLUEFIRE_S3_BROWSER_BUNDLE!);
  const assets = new Map<string, string>();
  for (const name of readdirSync(root)) {
    const file = join(root, name);
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) || !lstatSync(file).isFile() || lstatSync(file).isSymbolicLink()) throw new Error("The production asset tree is not flat and regular.");
    assets.set(`/ui/${name}`, file);
  }
  if (!assets.has("/ui/index.html") || !assets.has("/ui/app.js")) throw new Error("The production bundle is incomplete.");
  const types: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2" };
  const server = createServer((request, response) => {
    const raw = request.url ?? "";
    const file = assets.get(raw === "/ui/" ? "/ui/index.html" : raw);
    if (!file || !["GET", "HEAD"].includes(request.method ?? "")) {
      response.writeHead(404, { "Cache-Control": "no-store" }); response.end(); return;
    }
    response.writeHead(200, { "Content-Type": types[extname(file)] ?? "application/octet-stream", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
    if (request.method === "HEAD") { response.end(); return; }
    createReadStream(file).on("error", () => response.destroy()).pipe(response);
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 15_000;
  await new Promise<void>((ready, reject) => {
    server.once("error", reject);
    server.listen(Number(process.env.BLUEFIRE_S3_BROWSER_PORT), "127.0.0.1", ready);
  });
  return async () => {
    server.closeAllConnections();
    await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
  };
}
