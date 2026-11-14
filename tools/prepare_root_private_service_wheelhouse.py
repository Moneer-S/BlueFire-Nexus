"""Fetch the five committed Linux service dependencies for a private offline install.

This producer runs as the hosted runner, never as the privileged BlueFire
controller. The root-private installer reopens every wheel against the lock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from bluefire.cross_platform_artifact_validation import linux_wheelhouse_unavailable

_LOCK = Path("bluefire/data/gate11_linux_wheelhouse.json")
_RECEIPT = "service-wheelhouse-receipt.json"
_EXPECTED = {
    "cffi": "2.1.1",
    "cryptography": "50.0.0",
    "pycparser": "3.0",
    "PyNaCl": "1.6.2",
    "PyYAML": "6.0.3",
}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_MAX_LOCK_BYTES = 64 * 1024
_MAX_WHEEL_BYTES = 32 * 1024 * 1024


class WheelhousePreparationError(ValueError):
    """The private dependency closure is unavailable or inconsistent."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WheelhousePreparationError("duplicate lock field")
        result[key] = value
    return result


def _sha256_file(path: Path, maximum: int) -> tuple[int, str]:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= maximum:
        raise WheelhousePreparationError("dependency input is not a bounded regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.lstat()
    if (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise WheelhousePreparationError("dependency input changed during inspection")
    return details.st_size, "sha256:" + digest.hexdigest()


def _lock(repository: Path, source_revision: str) -> tuple[bytes, list[dict[str, Any]]]:
    if _REVISION.fullmatch(source_revision) is None:
        raise WheelhousePreparationError("source revision is invalid")
    identity = repository / "bluefire/_source_revision.txt"
    if identity.read_text(encoding="ascii").strip() != source_revision:
        raise WheelhousePreparationError("archived source revision differs")
    path = repository / _LOCK
    size, observed_digest = _sha256_file(path, _MAX_LOCK_BYTES)
    payload = path.read_bytes()
    if len(payload) != size or "sha256:" + hashlib.sha256(payload).hexdigest() != observed_digest:
        raise WheelhousePreparationError("dependency lock changed")
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WheelhousePreparationError("dependency lock is invalid JSON") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "platform", "architecture", "python", "wheels"}
        or document["schema_version"] != "bluefire.linux-wheelhouse.v1"
        or document["platform"] != "linux"
        or document["architecture"] != "x86_64"
        or document["python"] != {"implementation": "cpython", "major": 3, "minor": 12}
        or not isinstance(document["wheels"], list)
        or len(document["wheels"]) != 5
    ):
        raise WheelhousePreparationError("dependency lock identity differs")
    rows = document["wheels"]
    if [row.get("distribution") for row in rows if isinstance(row, dict)] != list(_EXPECTED):
        raise WheelhousePreparationError("dependency distribution order differs")
    filenames: set[str] = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"distribution", "version", "filename", "size", "sha256"}
            or not isinstance(row["distribution"], str)
            or row["version"] != _EXPECTED.get(row["distribution"])
            or not isinstance(row["filename"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*\.whl", row["filename"])
            or row["filename"] in filenames
            or type(row["size"]) is not int
            or not 0 < row["size"] <= _MAX_WHEEL_BYTES
            or not isinstance(row["sha256"], str)
            or _SHA.fullmatch(row["sha256"]) is None
        ):
            raise WheelhousePreparationError("dependency lock row differs")
        filenames.add(row["filename"])
    return payload, rows


def _private_output(repository: Path, output: Path) -> Path:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise WheelhousePreparationError("runner private directory is unavailable")
    raw_parent = Path(runner_temp)
    if not raw_parent.is_absolute() or raw_parent.is_symlink():
        raise WheelhousePreparationError("runner private directory is invalid")
    parent = raw_parent.resolve(strict=True)
    if not output.is_absolute() or ".." in output.parts or output.is_symlink() or output.exists():
        raise WheelhousePreparationError("wheelhouse output must be a fresh absolute path")
    if (
        output.name != "bluefire-service-wheelhouse"
        or output.parent.resolve(strict=True) != parent
        or output.is_relative_to(repository)
    ):
        raise WheelhousePreparationError("wheelhouse output escaped runner private directory")
    return output


def _requirements(rows: list[dict[str, Any]]) -> bytes:
    return "".join(
        f"{row['distribution']}=={row['version']} --hash=sha256:{row['sha256']}\n" for row in rows
    ).encode("ascii")


def _inventory(rows: list[dict[str, Any]]) -> str:
    ordered = sorted(rows, key=lambda row: row["filename"])
    encoded = json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _platform_qualified() -> bool:
    return (
        platform.system() == "Linux"
        and platform.machine() == "x86_64"
        and platform.python_implementation() == "CPython"
        and sys.version_info[:2] == (3, 12)
    )


def prepare(repository: Path, output: Path, source_revision: str) -> Mapping[str, Any]:
    if not _platform_qualified():
        raise WheelhousePreparationError("CPython 3.12 on Linux x86_64 is required")
    if repository.is_symlink() or not repository.is_absolute():
        raise WheelhousePreparationError("source directory is invalid")
    repository = repository.resolve(strict=True)
    output = _private_output(repository, output)
    payload, rows = _lock(repository, source_revision)
    wheels = output / "wheelhouse"
    requirements = output / "requirements.txt"
    try:
        output.mkdir(mode=0o700)
        wheels.mkdir(mode=0o700)
        requirements.write_bytes(_requirements(rows))
        requirements.chmod(0o600)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "--isolated",
                "download",
                "--no-input",
                "--no-cache-dir",
                "--only-binary=:all:",
                "--require-hashes",
                "--no-deps",
                "--dest",
                str(wheels),
                "--requirement",
                str(requirements),
            ],
            check=True,
            timeout=300,
            env={
                "PATH": os.defpath,
                "HOME": str(output),
                "TMPDIR": str(output),
                "LANG": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        expected = {row["filename"]: row for row in rows}
        found = {item.name: item for item in wheels.iterdir()}
        if set(found) != set(expected):
            raise WheelhousePreparationError("downloaded dependency inventory differs")
        for name, row in expected.items():
            size, digest = _sha256_file(found[name], _MAX_WHEEL_BYTES)
            if size != row["size"] or digest != "sha256:" + row["sha256"]:
                raise WheelhousePreparationError("downloaded dependency identity differs")
        old = os.environ.get("BLUEFIRE_GATE11_LINUX_WHEELHOUSE")
        try:
            os.environ["BLUEFIRE_GATE11_LINUX_WHEELHOUSE"] = str(wheels)
            try:
                unavailable = linux_wheelhouse_unavailable(repository)
            except ValueError as exc:
                raise WheelhousePreparationError(
                    "existing Linux wheelhouse gate refused input"
                ) from exc
            if unavailable:
                raise WheelhousePreparationError("existing Linux wheelhouse gate refused input")
        finally:
            if old is None:
                os.environ.pop("BLUEFIRE_GATE11_LINUX_WHEELHOUSE", None)
            else:
                os.environ["BLUEFIRE_GATE11_LINUX_WHEELHOUSE"] = old
        receipt = {
            "schema_version": "bluefire.service-wheelhouse-receipt.v1",
            "lock_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "platform": "linux",
            "architecture": "x86_64",
            "python": "3.12",
            "wheelhouse_dir": str(wheels.resolve(strict=True)),
            "wheel_inventory_digest": _inventory(rows),
        }
        record = wheels / _RECEIPT
        descriptor = os.open(
            record,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(
                    (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode(
                        "ascii"
                    )
                )
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            requirements.unlink(missing_ok=True)
        return receipt
    except BaseException:
        requirements.unlink(missing_ok=True)
        if (
            output.is_dir()
            and not output.is_symlink()
            and output.parent.resolve(strict=True)
            == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            and (os.name != "posix" or shutil.rmtree.avoids_symlink_attacks)
        ):
            shutil.rmtree(output)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = prepare(args.repository, args.output_root, args.source_revision)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        WheelhousePreparationError,
    ):
        print("private service wheelhouse unavailable", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
