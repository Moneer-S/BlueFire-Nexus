"""Prepare the Linux CI job's private setup-python cache and verify its runtime.

The hosted shared cache is intentionally not modified. setup-python supports
AGENT_TOOLSDIRECTORY, but its Linux downloads retain the build cache's RPATH.
Only recognized references in this job's newly installed runtime are relocated.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_ENTRIES = 30_000
MAX_ELFS = 512
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_SECONDS = 180
MAX_OUTPUT_BYTES = 16_384
PATCHELF = Path("/usr/bin/patchelf")
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class Refusal(Exception):
    """A static, path-free CI diagnostic."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise Refusal(code)


def _path(value: str) -> Path:
    path = Path(value)
    _require(bool(value) and path.is_absolute(), "absolute_path_required")
    _require(not any(char.isspace() or ord(char) < 32 for char in value), "invalid_path")
    _require(".." not in path.parts, "invalid_path")
    return path


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size, info.st_mtime_ns)


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _ancestors(path: Path) -> None:
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        _require(stat.S_ISDIR(info.st_mode), "ancestor_not_directory")
        _require(info.st_uid in (0, os.getuid()), "ancestor_owner")
        writable = bool(info.st_mode & 0o022)
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        _require(not writable or (sticky_root and item != path), "ancestor_writable")


def _root(root: Path, token: str) -> None:
    _ancestors(root)
    info = root.lstat()
    _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "cache_mode")
    _require(token == f"{info.st_dev}:{info.st_ino}:{info.st_uid}", "cache_identity")


def _diagnose_shared_cache(value: str) -> None:
    """Report only category/ownership/mode, never a machine path."""
    try:
        path = _path(value)
        chain = (*reversed(path.parents), path)
        _require(len(chain) <= 32, "diagnostic_depth")
        for depth, item in enumerate(chain):
            info = item.lstat()
            owner = (
                "root" if info.st_uid == 0 else "self" if info.st_uid == os.getuid() else "other"
            )
            category = "cache" if item == path else "ancestor"
            print(
                json.dumps(
                    {
                        "stage": "shared_cache",
                        "category": category,
                        "depth": depth,
                        "owner": owner,
                        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                        "symlink": stat.S_ISLNK(info.st_mode),
                    }
                )
            )
    except (OSError, Refusal):
        print('{"stage":"shared_cache","status":"unavailable"}')


def _exports(values: dict[str, str], paths: tuple[Path, ...] = ()) -> None:
    for key, value in values.items():
        _require(bool(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key)), "export_key")
        _require(not any(char in value for char in "\r\n\0"), "export_value")
    for path in paths:
        _path(str(path))
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        output.write("".join(f"{key}={value}\n" for key, value in values.items()))
    if paths:
        with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as output:
            output.write("".join(f"{path}\n" for path in paths))


def prepare() -> None:
    _diagnose_shared_cache(
        os.environ.get("AGENT_TOOLSDIRECTORY") or os.environ.get("RUNNER_TOOL_CACHE", "")
    )
    parent = _path(os.environ["RUNNER_TEMP"])
    _ancestors(parent)
    root = Path(tempfile.mkdtemp(prefix="bluefire-python-cache-", dir=parent))
    info = root.lstat()
    token = f"{info.st_dev}:{info.st_ino}:{info.st_uid}"
    _root(root, token)
    _exports({"AGENT_TOOLSDIRECTORY": str(root), "BLUEFIRE_CI_PYTHON_CACHE_ID": token})


def _prefix(root: Path, interpreter: Path) -> Path:
    _require(_inside(interpreter, root), "interpreter_outside_cache")
    parts = interpreter.relative_to(root).parts
    _require(
        len(parts) == 5 and parts[0] == "Python" and parts[2:] == ("x64", "bin", "python"),
        "interpreter_layout",
    )
    _require(bool(re.fullmatch(r"3\.(?:10|11|12)\.\d+", parts[1])), "interpreter_version")
    prefix = root / "Python" / parts[1] / "x64"
    _ancestors(prefix)
    _require(_inside(interpreter.resolve(strict=True), prefix), "interpreter_link_escape")
    return prefix


def _check_entry(path: Path, prefix: Path) -> os.stat_result:
    info = path.lstat()
    _require(info.st_uid == os.getuid(), "runtime_owner")
    if stat.S_ISLNK(info.st_mode):
        direct = Path(os.path.normpath(path.parent / os.readlink(path)))
        _require(_inside(direct, prefix), "runtime_link_escape")
        _require(_inside(path.resolve(strict=True), prefix), "runtime_link_escape")
    else:
        _require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "runtime_file_kind")
        _require(not info.st_mode & 0o022, "runtime_writable")
    return info


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "runtime_deadline")
    return min(10.0, remaining)


def _walk_error(error: OSError) -> None:
    raise Refusal("runtime_walk_failed") from error


def _runtime_elf(header: bytes) -> bool:
    if not header.startswith(b"\x7fELF"):
        return False
    _require(len(header) >= 18 and header[4] in (1, 2) and header[5] in (1, 2), "invalid_elf")
    kind = int.from_bytes(header[16:18], "little" if header[5] == 1 else "big")
    _require(kind in (1, 2, 3), "invalid_elf")
    # Installed config/python.o is a build input, not a dynamically loaded ELF.
    return kind in (2, 3)


def _inventory(prefix: Path, deadline: float) -> tuple[list[Path], dict[Path, tuple[int, ...]]]:
    elfs: list[Path] = []
    identities: dict[Path, tuple[int, ...]] = {}
    total = 0
    for directory, dirs, files in os.walk(prefix, followlinks=False, onerror=_walk_error):
        _remaining(deadline)
        for path in (Path(directory), *(Path(directory) / name for name in dirs + files)):
            if path in identities:
                continue
            _require(len(identities) < MAX_ENTRIES, "runtime_entry_limit")
            info = _check_entry(path, prefix)
            identities[path] = _identity(info)
            if not stat.S_ISREG(info.st_mode):
                continue
            total += info.st_size
            _require(
                info.st_size <= MAX_FILE_BYTES and total <= MAX_TOTAL_BYTES, "runtime_size_limit"
            )
            with path.open("rb") as source:
                _require(
                    _identity(os.fstat(source.fileno())) == _identity(info), "runtime_identity"
                )
                header = source.read(18)
            if _runtime_elf(header):
                _require(info.st_nlink == 1, "runtime_hardlink")
                _require(len(elfs) < MAX_ELFS, "runtime_elf_limit")
                elfs.append(path)
    _require(bool(elfs), "runtime_no_elf")
    return elfs, identities


def _rpath(value: str, path: Path, prefix: Path) -> str:
    old_lib = f"/opt/hostedtoolcache/Python/{prefix.parent.name}/x64/lib"
    result = []
    for component in value.split(":") if value else ():
        if component == old_lib:
            result.append(str(prefix / "lib"))
            continue
        expanded = re.sub(r"\$(?:\{ORIGIN\}|ORIGIN(?=/|$))", lambda _: str(path.parent), component)
        _require(bool(expanded) and "$" not in expanded, "unrecognized_rpath")
        _require(
            Path(expanded).is_absolute()
            and not any(char.isspace() or ord(char) < 32 for char in expanded),
            "unrecognized_rpath",
        )
        _require(_inside(Path(os.path.normpath(expanded)), prefix), "unrecognized_rpath")
        resolved = Path(expanded).resolve(strict=True)
        _require(_inside(resolved, prefix) and resolved.is_dir(), "unrecognized_rpath")
        result.append(component)
    return ":".join(result)


def _exit_code_without_reaping(pid: int, deadline: float) -> int:
    """Keep the leader PID reserved until its entire process group is signalled."""
    while True:
        _remaining(deadline)
        status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if status is not None:
            _require(status.si_pid == pid, "child_identity")
            return status.si_status if status.si_code == os.CLD_EXITED else -1
        time.sleep(min(0.01, _remaining(deadline)))


def _terminate_group(child: subprocess.Popen[bytes], deadline: float) -> None:
    # No poll()/wait() may release the leader PID before killpg: a departed
    # leader can leave descendants holding the pipe or running without it.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise Refusal("child_cleanup_unknown") from error
    try:
        child.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        raise Refusal("child_cleanup_unknown") from error


def _run(
    args: list[str],
    root: Path,
    deadline: float,
    *,
    executable: str | None = None,
    pass_fds: tuple[int, ...] = (),
) -> bytes:
    child_deadline = time.monotonic() + _remaining(deadline)
    # Reserve cleanup inside the same finite child/global budget.
    execution_deadline = child_deadline - 0.25
    _remaining(execution_deadline)
    child = subprocess.Popen(
        args,
        executable=executable,
        env=CLEAN_ENV,
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    try:
        _require(child.stdout is not None, "child_output_unavailable")
        assert child.stdout is not None
        os.set_blocking(child.stdout.fileno(), False)
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                _require(execution_deadline > time.monotonic(), "child_deadline")
                if not selector.select(execution_deadline - time.monotonic()):
                    raise Refusal("child_deadline")
                chunk = os.read(child.stdout.fileno(), MAX_OUTPUT_BYTES + 1)
                if not chunk:
                    break
                output.extend(chunk)
                _require(len(output) <= MAX_OUTPUT_BYTES, "child_output_limit")
        _require(_exit_code_without_reaping(child.pid, execution_deadline) == 0, "child_failed")
        return bytes(output)
    finally:
        try:
            _terminate_group(child, child_deadline)
        finally:
            if child.stdout is not None:
                child.stdout.close()


PROBE = r"""
import bz2, ctypes, json, lzma, os, pathlib, sqlite3, ssl, sys, sysconfig
p = pathlib.Path(sys.argv[1])
inside = lambda v: pathlib.Path(v).resolve().is_relative_to(p)
assert pathlib.Path(sys.base_prefix).resolve() == p
assert pathlib.Path(sys.prefix).resolve() == p
assert inside(sysconfig.get_path('stdlib')) and inside(os.__file__)
assert all(inside(m.__file__) for m in tuple(sys.modules.values()) if getattr(m, '__file__', None))
assert pathlib.Path('/proc/self/exe').resolve() == pathlib.Path(sys.argv[2])
assert inside(sys._base_executable)
with open('/proc/self/maps', 'rb') as f:
    data = f.read(2 * 1024 * 1024 + 1)
assert len(data) <= 2 * 1024 * 1024
maps = [line.split(None, 5)[5].decode() for line in data.splitlines() if len(line.split(None, 5)) == 6]
assert not any('/opt/hostedtoolcache/' in v for v in maps)
libs = [v for v in maps if pathlib.Path(v).name.startswith('libpython')]
assert libs and all(inside(v) and pathlib.Path(v).resolve().parent == p / 'lib' for v in libs)
print('{"probe":"ok"}')
"""


def _probe(interpreter: Path, prefix: Path, root: Path, deadline: float, pinned: bool) -> None:
    canonical = interpreter.resolve(strict=True)
    _require(_inside(canonical, prefix), "probe_interpreter_escape")
    before = canonical.lstat()
    descriptor = os.open(canonical, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        _require(_identity(os.fstat(descriptor)) == _identity(before), "probe_identity")
        arguments = [str(interpreter), "-I", "-B", "-c", PROBE, str(prefix), str(canonical)]
        result = _run(
            arguments,
            root,
            deadline,
            executable=f"/proc/self/fd/{descriptor}" if pinned else None,
            pass_fds=(descriptor,) if pinned else (),
        )
        _require(result == b'{"probe":"ok"}\n', "probe_output")
        _require(_identity(canonical.lstat()) == _identity(before), "probe_identity")
    finally:
        os.close(descriptor)


def relocate() -> None:
    deadline = time.monotonic() + MAX_SECONDS
    root = _path(os.environ["AGENT_TOOLSDIRECTORY"])
    token = os.environ["BLUEFIRE_CI_PYTHON_CACHE_ID"]
    _root(root, token)
    interpreter = _path(os.environ["BLUEFIRE_CI_PYTHON_PATH"])
    prefix = _prefix(root, interpreter)
    _ancestors(PATCHELF.parent)
    tool = PATCHELF.lstat()
    _require(
        stat.S_ISREG(tool.st_mode) and tool.st_uid == 0 and not tool.st_mode & 0o022,
        "patchelf_unprotected",
    )
    elfs, identities = _inventory(prefix, deadline)
    print(json.dumps({"stage": "inventory", "entries": len(identities), "elfs": len(elfs)}))
    changed = 0
    for path in elfs:
        _root(root, token)
        _ancestors(path.parent)
        info = _check_entry(path, prefix)
        _require(_identity(info) == identities[path] and info.st_nlink == 1, "runtime_identity")
        _require(_identity(PATCHELF.lstat()) == _identity(tool), "patchelf_identity")
        old = (
            _run([str(PATCHELF), "--print-rpath", str(path)], root, deadline)
            .decode("utf-8")
            .rstrip("\n")
        )
        new = _rpath(old, path, prefix)
        if new != old:
            _require(_identity(path.lstat()) == identities[path], "runtime_identity")
            _run([str(PATCHELF), "--set-rpath", new, str(path)], root, deadline)
            info = _check_entry(path, prefix)
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "runtime_identity")
            identities[path] = _identity(info)
            actual = (
                _run([str(PATCHELF), "--print-rpath", str(path)], root, deadline)
                .decode("utf-8")
                .rstrip("\n")
            )
            _require(actual == new, "rpath_verification")
            changed += 1
    _root(root, token)
    for path, identity in identities.items():
        _require(_identity(path.lstat()) == identity, "runtime_identity")
    print(json.dumps({"stage": "normal_probe", "relocated": changed}))
    _probe(interpreter, prefix, root, deadline, pinned=False)
    print('{"stage":"descriptor_probe"}')
    _probe(interpreter, prefix, root, deadline, pinned=True)
    _root(root, token)
    _exports(
        {
            "pythonLocation": str(prefix),
            "Python_ROOT_DIR": str(prefix),
            "Python2_ROOT_DIR": str(prefix),
            "Python3_ROOT_DIR": str(prefix),
            "PKG_CONFIG_PATH": str(prefix / "lib" / "pkgconfig"),
            "LD_LIBRARY_PATH": "",
        },
        (prefix, prefix / "bin"),
    )
    print(
        json.dumps(
            {"stage": "runtime", "status": "verified", "elfs": len(elfs), "relocated": changed}
        )
    )


def main() -> int:
    stage = "arguments"
    try:
        _require(sys.platform == "linux", "linux_required")
        _require(len(sys.argv) == 2 and sys.argv[1] in ("prepare", "relocate"), "invalid_arguments")
        stage = sys.argv[1]
        (prepare if stage == "prepare" else relocate)()
        print(json.dumps({"stage": stage, "status": "ok"}))
        return 0
    except (
        OSError,
        KeyError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
        Refusal,
    ) as exc:
        code = str(exc) if isinstance(exc, Refusal) else "operation_failed"
        print(json.dumps({"stage": stage, "status": "refused", "code": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
