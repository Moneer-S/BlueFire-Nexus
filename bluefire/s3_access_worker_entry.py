"""Fixed Linux -I -S -B entrypoint for the native-owned S3 worker channel.

Only protected manifest/root bindings are arguments. Native admission owns
containment, hard deadlines and the post-ready credential/permit channels.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType


def _identity() -> tuple[int, str]:
    pid = os.getpid()
    with Path("/proc/self/stat").open("rb") as source:
        raw = source.read(4097)
    if len(raw) > 4096 or not raw.startswith(str(pid).encode("ascii") + b" ("):
        raise ValueError("Worker process identity is unavailable.")
    fields = raw.rsplit(b") ", 1)[1].split()
    start = fields[19].decode("ascii")
    if not start.isdecimal() or not 1 <= len(start) <= 32 or start.startswith("0"):
        raise ValueError("Worker process identity is unavailable.")
    return pid, start


def main(argv=None) -> int:
    os.environ.clear()
    if not (
        sys.platform.startswith("linux")
        and sys.flags.isolated
        and sys.flags.no_site
        and sys.dont_write_bytecode
    ):
        return 2
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 4 or args[::2] != ["--runtime-root", "--runtime-digest"]:
        return 2
    worker_root = Path(__file__).parent
    if "bluefire" in sys.modules or any(not stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (0, 1)):
        return 2
    # The native owner verifies this exact worker tree before executing it.
    # Avoid the normal package initializer and its unrelated application imports.
    package = ModuleType("bluefire")
    package.__path__ = [str(worker_root)]
    sys.modules["bluefire"] = package
    spec = importlib.util.spec_from_file_location(
        "bluefire.s3_access_runtime", worker_root / "s3_access_runtime.py"
    )
    if spec is None or spec.loader is None:
        return 2
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    runtime = module.validate_runtime(Path(args[1]), args[3])
    if runtime.worker_root != worker_root:
        return 2
    factory = runtime.create_factory()
    worker = importlib.import_module("bluefire.s3_access_worker")
    pid, created = _identity()
    status: int = worker.run_worker(
        sys.stdin.buffer,
        sys.stdout.buffer,
        factory=factory,
        clock=lambda: datetime.now(timezone.utc),
        process_id=pid,
        creation_identity=created,
        nonce=secrets.token_hex(32),
        expected_runtime_digest=runtime.runtime_digest,
        expected_worker_generation=runtime.worker_generation,
    )
    return status


if __name__ == "__main__":
    try:
        status = main()
    except BaseException:
        status = 2
    raise SystemExit(status)
