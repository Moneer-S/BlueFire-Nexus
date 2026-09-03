import { createReadStream, statSync } from "node:fs";
import { createServer, type ServerResponse } from "node:http";
import { extname, resolve, sep } from "node:path";

const ROOT = resolve(process.cwd(), "dist");
const MIME_TYPES: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

function refuse(response: ServerResponse, status: number, message: string) {
  response.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  response.end(message);
}

export default async function globalSetup() {
  const server = createServer((request, response) => {
    if (request.method !== "GET" && request.method !== "HEAD") return refuse(response, 405, "Method not allowed");
    const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const relative = decodeURIComponent(pathname).replace(/^\/ui\/?/, "") || "index.html";
    const target = resolve(ROOT, relative);
    if (target !== ROOT && !target.startsWith(`${ROOT}${sep}`)) return refuse(response, 403, "Forbidden");
    let file = target;
    try {
      if (!statSync(file).isFile()) file = resolve(ROOT, "index.html");
    } catch {
      file = resolve(ROOT, "index.html");
    }
    response.writeHead(200, {
      "Content-Type": MIME_TYPES[extname(file)] ?? "application/octet-stream",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    if (request.method === "HEAD") return response.end();
    createReadStream(file).on("error", () => refuse(response, 500, "Read failed")).pipe(response);
  });

  await new Promise<void>((resolveReady, reject) => {
    server.once("error", reject);
    server.listen(5173, "127.0.0.1", resolveReady);
  });

  return async () => {
    await new Promise<void>((resolveClosed, reject) => server.close((error) => error ? reject(error) : resolveClosed()));
  };
}
