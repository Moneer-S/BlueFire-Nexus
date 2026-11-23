"""The stand-in internet of a range: a small web server on ports 80 and 443. Standard library only.

It serves a read-only tree of files, stores the body of every POST /upload as
<n>.bin with a line `<n> <peer> <sha256> <size>` in index.tsv, and writes one
line `<peer> <method> <path> <status> <time>` to its access log per request.
It is range infrastructure, not a technique. The image of the range's internet
host runs it as /usr/local/sbin/inet-server.

    inet-server <tree> <uploads folder> <access log> <certificate> <key> [<http port> <https port>]
"""

import hashlib
import http.server
import ssl
import sys
import threading
import time
from pathlib import Path

LARGEST_UPLOAD = 64 * 1024 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "inet"
    sys_version = ""
    lock = threading.Lock()
    tree: Path
    uploads: Path
    log: Path

    def answer(self, status: int, body: bytes, kind: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - the name http.server calls
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self.answer(200, b"inet: the range's stand-in internet\n")
        parts = [part for part in path.split("/") if part]
        target = self.tree.joinpath(*parts) if parts and ".." not in parts else None
        if target is None or not target.is_file():
            return self.answer(404, b"not found\n")
        self.answer(200, target.read_bytes(), "application/octet-stream")

    def do_POST(self) -> None:  # noqa: N802
        size = int(self.headers.get("Content-Length") or 0)
        if self.path.split("?", 1)[0] != "/upload" or not 0 <= size <= LARGEST_UPLOAD:
            return self.answer(404, b"not found\n")
        body = self.rfile.read(size)
        with self.lock:
            index = self.uploads / "index.tsv"
            number = len(index.read_text().splitlines()) + 1 if index.exists() else 1
            (self.uploads / f"{number}.bin").write_bytes(body)
            with index.open("a") as out:
                out.write(f"{number} {self.client_address[0]} {hashlib.sha256(body).hexdigest()} {size}\n")
        self.answer(200, f"stored {number}\n".encode())

    def log_request(self, code="-", size="-") -> None:
        path = "".join(c if c.isprintable() and c != " " else "?" for c in self.path)
        with self.lock, self.log.open("a") as out:
            out.write(f"{self.client_address[0]} {self.command} {path} {code} {time.time():.6f}\n")

    def log_message(self, format, *args) -> None:  # noqa: A002 - the name http.server calls
        pass


def serve(tree, uploads, log, certificate, key, ports=(80, 443), host="0.0.0.0") -> list:
    """Start the server on both ports, each in a thread of its own; return the two servers."""

    handler = type("Bound", (Handler,), {"tree": Path(tree), "uploads": Path(uploads), "log": Path(log)})
    plain = http.server.ThreadingHTTPServer((host, ports[0]), handler)
    secure = http.server.ThreadingHTTPServer((host, ports[1]), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    # The handshake runs in the request's own thread, so that a client that never speaks TLS holds up no other.
    secure.socket = context.wrap_socket(secure.socket, server_side=True, do_handshake_on_connect=False)
    for server in (plain, secure):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return [plain, secure]


if __name__ == "__main__":
    arguments = sys.argv[1:]
    ports = tuple(int(port) for port in arguments[5:7]) or (80, 443)
    serve(*arguments[:5], ports=ports)
    threading.Event().wait()
