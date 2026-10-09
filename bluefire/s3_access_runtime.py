"""Explicit protected S3 SDK runtime; verification itself imports no SDK.

The enrolled manifest is authority input, not a discovered installation. Python,
stdlib, worker, SDK models and CA bytes are checked; protected host shared
libraries and kernel remain a host premise, not a complete OS attestation.
The interpreter's isolated bootstrap must already use the declared stdlib tree;
copying a system stdlib elsewhere does not retarget it or satisfy this contract.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.machinery
import json
import logging
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

SCHEMA = "bluefire.s3-sdk-runtime.v1"
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
# All 2116 files under the separately reviewed five-distribution SDK tree,
# including installer metadata. Version labels alone are not byte authority.
SDK_INVENTORY_DIGEST = "sha256:3a0b54afdb950def6428f2e0b837d254918757f3b0b145bfea376bc7ac68536b"
VERSIONS = {
    "botocore": "1.43.110",
    "jmespath": "1.1.0",
    "python-dateutil": "2.9.0.post0",
    "urllib3": "2.8.0",
    "six": "1.17.0",
}
WORKER_FILES = frozenset(
    {
        "s3_access_runtime.py",
        "s3_access_worker_entry.py",
        "s3_access_contract.py",
        "s3_access_policy.py",
        "s3_access_wire.py",
        "s3_access_sdk.py",
        "s3_access_sdk_boundary.py",
        "s3_access_sdk_transport.py",
        "s3_access_worker.py",
        "util.py",
    }
)
_FIELDS = {
    "schema_version",
    "python",
    "stdlib_root",
    "sdk_root",
    "worker_root",
    "ca_bundle",
    "distributions",
    "files",
    "worker_generation",
}


class S3RuntimeError(ValueError):
    def __init__(self):
        super().__init__("Explicit protected S3 SDK runtime is unavailable.")


def _require(value: Any) -> None:
    if not value:
        raise S3RuntimeError()


def _canonical(value: Any) -> bytes:
    # Bootstrap cannot import the worker's util until its bytes are verified.
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _pairs(rows):
    result = {}
    for key, value in rows:
        _require(key not in result)
        result[key] = value
    return result


def _absolute(value: Any) -> PurePosixPath:
    _require(
        type(value) is str and 1 < len(value) <= 512 and value.isascii() and value.isprintable()
    )
    _require(value.startswith("/") and "\\" not in value and "\0" not in value)
    path = PurePosixPath(value)
    _require(str(path) == value and all(part not in {".", ".."} for part in path.parts))
    return path


def _relative(value: Any) -> str:
    _require(
        type(value) is str and 0 < len(value) <= 512 and value.isascii() and value.isprintable()
    )
    _require("\\" not in value and "\0" not in value)
    path = PurePosixPath(value)
    _require(
        value != "."
        and not path.is_absolute()
        and str(path) == value
        and all(part not in {".", "..", "__pycache__"} for part in path.parts)
        and path.suffix not in {".pyc", ".pyo", ".pth"}
    )
    return cast(str, value)


def _file_row(row: Any, *, python: bool = False) -> dict[str, Any]:
    _require(
        type(row) is dict
        and set(row) == ({"path", "sha256", "size_bytes"} if python else {"sha256", "size_bytes"})
    )
    _require(type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]))
    _require(type(row["size_bytes"]) is int and 0 <= row["size_bytes"] <= MAX_FILE)
    if python:
        _absolute(row["path"])
        _require(row["size_bytes"] >= 64)
    return cast(dict[str, Any], row)


def parse_manifest(payload: bytes, root: Path, expected_digest: str) -> dict[str, Any]:
    """Closed structural parsing, usable without opening a runtime or SDK."""
    try:
        _require(type(payload) is bytes and 0 < len(payload) <= MAX_MANIFEST)
        row = json.loads(
            payload,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(S3RuntimeError()),
        )
        _require(type(row) is dict and set(row) == _FIELDS and row["schema_version"] == SCHEMA)
        _require(
            type(expected_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest)
        )
        _require(_digest(row) == expected_digest and row["distributions"] == VERSIONS)
        base = _absolute(str(root))
        roots = [_absolute(row[name]) for name in ("stdlib_root", "sdk_root", "worker_root")]
        _require(all(path != base and path.is_relative_to(base) for path in roots))
        _require(
            all(
                not left.is_relative_to(right) and not right.is_relative_to(left)
                for index, left in enumerate(roots)
                for right in roots[index + 1 :]
            )
        )
        _file_row(row["python"], python=True)
        _require(row["ca_bundle"] == "botocore/cacert.pem")
        files = row["files"]
        _require(type(files) is dict and 1 <= len(files) <= MAX_FILES)
        total, worker, sdk = 0, {}, {}
        for name, details in files.items():
            _relative(name)
            prefix, separator, relative = name.partition("/")
            _require(separator and prefix in {"stdlib", "sdk", "worker"})
            _relative(relative)
            _file_row(details)
            total += details["size_bytes"]
            if prefix == "worker":
                worker[relative] = details
            elif prefix == "sdk":
                sdk[relative] = details
        _require(
            total <= MAX_TOTAL
            and set(worker) == WORKER_FILES
            and all(item["size_bytes"] > 0 for item in worker.values())
        )
        _require(row["worker_generation"] == _digest(worker))
        _require(_digest(sdk) == SDK_INVENTORY_DIGEST)
        _require("sdk/" + row["ca_bundle"] in files and "stdlib/os.py" in files)
        _require(files["sdk/" + row["ca_bundle"]]["size_bytes"] > 0)
        return cast(dict[str, Any], row)
    except (TypeError, ValueError, KeyError, UnicodeError, RecursionError):
        raise S3RuntimeError() from None


def _identity(info):
    return tuple(
        getattr(info, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def _protected(path: Path, *, directory: bool = False):
    info = path.lstat()
    _require(
        info.st_uid == info.st_gid == 0 and not info.st_mode & 0o6022 and not path.is_symlink()
    )
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    if not directory:
        _require(info.st_nlink == 1)
    for parent in path.parents:
        item = parent.lstat()
        _require(
            stat.S_ISDIR(item.st_mode)
            and item.st_uid == item.st_gid == 0
            and not item.st_mode & 0o022
            and not parent.is_symlink()
        )
    return info


def _read(path: Path, maximum: int) -> bytes:
    before = _protected(path)
    _require(0 <= before.st_size <= maximum)
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        flag = getattr(os, name, None)
        _require(type(flag) is int)
        flags |= cast(int, flag)
    descriptor = os.open(path, flags)
    try:
        held = os.fstat(descriptor)
        _require(_identity(before) == _identity(held))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        _require(
            len(raw) == before.st_size
            and _identity(held) == _identity(os.fstat(descriptor)) == _identity(path.lstat())
        )
        return raw
    finally:
        os.close(descriptor)


def _tree(root: Path) -> set[str]:
    _protected(root, directory=True)
    result, entries = set(), 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            entries += 1
            _require(entries <= 32768)
            path = Path(directory) / name
            relative = _relative(path.relative_to(root).as_posix())
            _protected(path, directory=name in dirs)
            if name in files:
                result.add(relative)
                _require(len(result) <= MAX_FILES)
    return result


@dataclass(frozen=True)
class S3Runtime:
    root: Path
    python: Path
    stdlib_root: Path
    sdk_root: Path
    worker_root: Path
    runtime_digest: str
    worker_generation: str
    _canonical: bytes

    def assert_current(self) -> None:
        current = validate_runtime(self.root, self.runtime_digest)
        _require(current._canonical == self._canonical)

    def _admit_imports(self) -> None:
        _require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
        _require(not os.environ and Path(sys.executable).resolve() == self.python)
        row = json.loads(self._canonical)
        roots = {"stdlib": self.stdlib_root, "sdk": self.sdk_root, "worker": self.worker_root}
        allowed = {
            roots[name.split("/", 1)[0]] / name.split("/", 1)[1]: details
            for name, details in row["files"].items()
        }

        def verified(spec):
            _require(spec is not None)
            if spec.origin in {"built-in", "frozen"}:
                return
            _require(type(spec.origin) is str)
            path = Path(spec.origin)
            _require(path in allowed)
            raw = _read(path, MAX_FILE)
            _require(
                len(raw) == allowed[path]["size_bytes"]
                and hashlib.sha256(raw).hexdigest() == allowed[path]["sha256"]
            )

        for name, module in tuple(sys.modules.items()):
            if name in {"__main__", "bluefire"}:
                continue
            if name in {"typing.io", "typing.re"}:
                # CPython exposes these exact class aliases as module entries.
                typing = sys.modules["typing"]
                _require(module is getattr(typing, name.split(".")[1]))
                verified(typing.__spec__)
                continue
            verified(getattr(module, "__spec__", None))

        class Finder:
            @staticmethod
            def find_spec(fullname, path=None, target=None):
                spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
                if spec is not None:
                    verified(spec)
                return spec

        sys.path[:] = [
            str(self.stdlib_root),
            str(self.stdlib_root / "lib-dynload"),
            str(self.sdk_root),
        ]
        sys.meta_path[:] = [
            importlib.machinery.BuiltinImporter,
            importlib.machinery.FrozenImporter,
            Finder,
        ]
        sys.path_importer_cache.clear()
        logging.disable(logging.CRITICAL)

    def create_factory(self):
        """Entry-only import of verified official bindings, not a credential lookup."""
        self.assert_current()
        self._admit_imports()
        _require(
            not any(name == "botocore" or name.startswith("botocore.") for name in sys.modules)
        )
        metadata = importlib.import_module("importlib.metadata")
        distributions = {}
        for distribution in metadata.MetadataPathFinder.find_distributions(
            metadata.DistributionFinder.Context(path=[str(self.sdk_root)])
        ):
            name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
            _require(name not in distributions)
            distributions[name] = distribution.version
        _require(distributions == VERSIONS)
        session = importlib.import_module("botocore.session")
        config = importlib.import_module("botocore.config")
        exceptions = importlib.import_module("botocore.exceptions")
        loaders = importlib.import_module("botocore.loaders")
        credentials = importlib.import_module("botocore.credentials")
        tokens = importlib.import_module("botocore.tokens")
        history = importlib.import_module("botocore.history")
        history.get_global_history_recorder().disable()
        boundary = importlib.import_module("bluefire.s3_access_sdk_boundary")

        def fixed_session():
            _require(not os.environ)
            history.get_global_history_recorder().disable()
            value = session.Session()
            for name, setting in {
                "config_file": "/dev/null",
                "credentials_file": "/dev/null",
                "profile": None,
                "csm_enabled": False,
                "api_versions": {},
            }.items():
                value.set_config_variable(name, setting)
            value.register_component(
                "data_loader",
                loaders.Loader(
                    extra_search_paths=[str(self.sdk_root / "botocore/data")],
                    include_default_search_paths=False,
                ),
            )
            value.register_component("credential_provider", credentials.CredentialResolver([]))
            value.register_component("token_provider", tokens.TokenProviderChain([]))
            return value

        return boundary.BotocoreFactory(
            session_factory=fixed_session,
            config_factory=config.Config,
            client_error_type=exceptions.ClientError,
            ca_bundle=str(self.sdk_root / "botocore/cacert.pem"),
            assert_runtime=self.assert_current,
        )


def validate_runtime(root: Path, expected_digest: str) -> S3Runtime:
    """Read-only verification for host readiness and a repeated worker boundary."""
    try:
        _require(
            sys.platform.startswith("linux")
            and all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"))
        )
        _absolute(str(root))
        _protected(root, directory=True)
        row = parse_manifest(_read(root / "runtime.json", MAX_MANIFEST), root, expected_digest)
        python = Path(row["python"]["path"])
        executable = _read(python, MAX_FILE)
        _require(
            len(executable) == row["python"]["size_bytes"]
            and hashlib.sha256(executable).hexdigest() == row["python"]["sha256"]
            and executable[:6] == b"\x7fELF\x02\x01"
            and executable[18:20] in {b"\x3e\x00", b"\xb7\x00"}
        )
        for prefix in ("stdlib", "sdk", "worker"):
            tree = Path(row[prefix + "_root"])
            expected = {
                name.split("/", 1)[1]: details
                for name, details in row["files"].items()
                if name.startswith(prefix + "/")
            }
            _require(_tree(tree) == set(expected))
            for name, details in expected.items():
                raw = _read(tree / name, MAX_FILE)
                if prefix == "worker":
                    # Native include_bytes pins use canonical LF source bytes.
                    _require(b"\r\n" not in raw)
                _require(
                    len(raw) == details["size_bytes"]
                    and hashlib.sha256(raw).hexdigest() == details["sha256"]
                )
            _require(_tree(tree) == set(expected))
        _require(
            parse_manifest(_read(root / "runtime.json", MAX_MANIFEST), root, expected_digest) == row
        )
        return S3Runtime(
            root,
            python,
            Path(row["stdlib_root"]),
            Path(row["sdk_root"]),
            Path(row["worker_root"]),
            expected_digest,
            row["worker_generation"],
            _canonical(row),
        )
    except (OSError, TypeError, ValueError, KeyError, RecursionError):
        raise S3RuntimeError() from None
