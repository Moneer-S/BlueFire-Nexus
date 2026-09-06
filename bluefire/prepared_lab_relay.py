"""Bounded fixed-destination byte relay for the ordinary authenticated lab UI.

This layer never interprets API requests, creates credentials, or forwards to a
caller-selected destination. The product server retains its session authority.
"""

from __future__ import annotations

import select
import socket
import stat
import threading
import time
from pathlib import Path


def remove_owned_socket(path: Path, identity: tuple[int, int]) -> bool:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return True
    if not stat.S_ISSOCK(current.st_mode) or (current.st_dev, current.st_ino) != identity:
        return False
    path.unlink()
    return True


def private_socket(path: Path) -> tuple[int, int]:
    details = path.lstat()
    if not stat.S_ISSOCK(details.st_mode) or details.st_uid != 1000 or details.st_mode & 0o077:
        raise ValueError("the UI bridge is not a private lab-account socket")
    return details.st_dev, details.st_ino


def tcp_listener(port: int) -> socket.socket:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("the UI port must be an unprivileged literal port")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Linux permits an immediate restart while prior accepted connections
        # remain in TIME_WAIT. No SO_REUSEPORT: an active listener still conflicts.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(8)
    except BaseException:
        listener.close()
        raise
    return listener


class Relay:
    def __init__(self, stop: threading.Event) -> None:
        self.stop = stop
        self.limit = threading.BoundedSemaphore(8)
        self.connections: set[socket.socket] = set()
        self.lock = threading.Lock()

    def copy(self, client: socket.socket, target: tuple[str, int] | Path) -> None:
        try:
            family = getattr(socket, "AF_UNIX", -1) if isinstance(target, Path) else socket.AF_INET
            with client, socket.socket(family, socket.SOCK_STREAM) as peer:
                with self.lock:
                    self.connections.update((client, peer))
                peer.settimeout(10)
                peer.connect(str(target) if isinstance(target, Path) else target)
                client.settimeout(10)
                started = last_data = time.monotonic()
                total = 0
                while not self.stop.is_set() and time.monotonic() - started < 600:
                    ready, _, _ = select.select([client, peer], [], [], 1)
                    if not ready:
                        if time.monotonic() - last_data > 60:
                            return
                        continue
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        total += len(data)
                        if total > 64 * 1024 * 1024:
                            return
                        (peer if source is client else client).sendall(data)
                        last_data = time.monotonic()
        except (OSError, TimeoutError, ValueError):
            pass
        finally:
            with self.lock:
                self.connections.discard(client)
                if "peer" in locals():
                    self.connections.discard(peer)
            self.limit.release()

    def serve(self, listener: socket.socket, target: tuple[str, int] | Path) -> None:
        listener.settimeout(0.5)
        with listener:
            while not self.stop.is_set():
                try:
                    client, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                if not self.limit.acquire(blocking=False):
                    client.close()
                    continue
                threading.Thread(target=self.copy, args=(client, target), daemon=True).start()

    def close(self) -> None:
        self.stop.set()
        with self.lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
