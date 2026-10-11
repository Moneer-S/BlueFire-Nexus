"""Protected-runtime contracts with synthetic bytes and filesystem substitutes.

No SDK import, AWS request, enrollment, or installed runtime admission is tested.
"""

from __future__ import annotations

import hashlib
import io
import stat
from dataclasses import FrozenInstanceError
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from bluefire import s3_access_runtime as runtime

ROOT = PurePosixPath("/owned/runtime")
DATA = b"abc"


@pytest.fixture(autouse=True)
def synthetic_sdk_inventory(monkeypatch):
    monkeypatch.setattr(
        runtime, "SDK_INVENTORY_DIGEST", runtime._digest({"botocore/cacert.pem": details()})
    )


def details(raw=DATA):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def manifest():
    worker = {name: details() for name in runtime.WORKER_FILES}
    return {
        "schema_version": runtime.SCHEMA,
        "python": {"path": "/owned/python", **details(b"x" * 64)},
        "stdlib_root": str(ROOT / "stdlib"),
        "sdk_root": str(ROOT / "sdk"),
        "worker_root": str(ROOT / "worker"),
        "ca_bundle": "botocore/cacert.pem",
        "distributions": dict(runtime.VERSIONS),
        "files": {
            "stdlib/os.py": details(),
            "sdk/botocore/cacert.pem": details(),
            **{"worker/" + name: value for name, value in worker.items()},
        },
        "worker_generation": runtime._digest(worker),
    }


def parse(row):
    return runtime.parse_manifest(runtime._canonical(row), ROOT, runtime._digest(row))


def test_closed_manifest_and_derived_worker_generation():
    row = manifest()
    assert parse(row) == row
    row["files"]["worker/util.py"] = details(b"changed")
    with pytest.raises(runtime.S3RuntimeError):
        parse(row)


def test_matching_version_labels_do_not_admit_different_sdk_bytes():
    row = manifest()
    row["files"]["sdk/botocore/cacert.pem"] = details(b"changed")
    with pytest.raises(runtime.S3RuntimeError):
        parse(row)


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", "other"),
        ("extra", True),
        ("stdlib_root", "/outside"),
        ("sdk_root", str(ROOT / "stdlib/sub")),
        ("worker_root", str(ROOT)),
        ("worker_root", str(ROOT / "sdk")),
        ("ca_bundle", "../outside"),
        ("ca_bundle", "/etc/ssl/cert.pem"),
        ("distributions", {**runtime.VERSIONS, "extra": "1"}),
        ("distributions", {**runtime.VERSIONS, "botocore": "1.0"}),
        ("worker_generation", "sha256:" + "0" * 64),
    ],
)
def test_manifest_refuses_widening(key, value):
    row = manifest()
    row[key] = value
    with pytest.raises(runtime.S3RuntimeError):
        parse(row)


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "sdk/../escape",
        "sdk//file",
        "sdk/.",
        "sdk/file.pyc",
        "sdk/site.pth",
        "sdk/__pycache__/x",
        "sdk/x\n.py",
        "sdk\\x.py",
        "/sdk/x",
        "other/file",
        "worker/extra.py",
    ],
)
def test_inventory_paths_cannot_select_hooks_or_escape(name):
    row = manifest()
    row["files"][name] = details()
    with pytest.raises(runtime.S3RuntimeError):
        parse(row)


@pytest.mark.parametrize("value", [True, -1, 1.0, 64 * 1024 * 1024 + 1, "3"])
def test_inventory_byte_counts_are_exact_bounded_integers(value):
    row = manifest()
    row["files"]["stdlib/os.py"]["size_bytes"] = value
    with pytest.raises(runtime.S3RuntimeError):
        parse(row)


def test_duplicate_keys_changed_digest_missing_worker_and_aggregate_caps():
    row = manifest()
    raw = runtime._canonical(row)
    with pytest.raises(runtime.S3RuntimeError):
        runtime.parse_manifest(raw, ROOT, "sha256:" + "a" * 64)
    with pytest.raises(runtime.S3RuntimeError):
        runtime.parse_manifest(
            b'{"schema_version":"a","schema_version":"b"}', ROOT, runtime._digest({})
        )
    row["files"].pop("worker/util.py")
    with pytest.raises(runtime.S3RuntimeError):
        parse(row)
    row = manifest()
    for index in range(9):
        row["files"][f"sdk/data{index}"] = {**details(), "size_bytes": runtime.MAX_FILE}
    with pytest.raises(runtime.S3RuntimeError):
        parse(row)


def fake_info(**changes):
    return SimpleNamespace(
        **{
            **dict(
                st_dev=1,
                st_ino=2,
                st_mode=stat.S_IFREG | 0o644,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_size=3,
                st_mtime_ns=4,
                st_ctime_ns=5,
            ),
            **changes,
        }
    )


def test_protected_paths_require_root_regular_no_links_and_safe_ancestors():
    class Location:
        parents = ()

        def lstat(self):
            return self.info

        def is_symlink(self):
            return False

    path = Location()
    for changes in (
        {"st_uid": 1000},
        {"st_gid": 1000},
        {"st_mode": stat.S_IFREG | 0o666},
        {"st_mode": stat.S_IFLNK | 0o777},
        {"st_nlink": 2},
    ):
        path.info = fake_info(**changes)
        with pytest.raises(runtime.S3RuntimeError):
            runtime._protected(path)
    path.info = fake_info()
    assert runtime._protected(path) is path.info
    parent = Location()
    parent.info = fake_info(st_mode=stat.S_IFDIR | 0o777)
    path.parents = (parent,)
    with pytest.raises(runtime.S3RuntimeError):
        runtime._protected(path)


def test_held_read_checks_named_identity_after_read_and_closes(monkeypatch):
    closed = []
    info = fake_info()
    path = SimpleNamespace(lstat=lambda: fake_info(st_ino=99))
    monkeypatch.setattr(runtime, "_protected", lambda item: info)
    monkeypatch.setattr(
        runtime,
        "os",
        SimpleNamespace(
            O_RDONLY=1,
            O_NOFOLLOW=2,
            O_NONBLOCK=4,
            O_CLOEXEC=8,
            open=lambda p, flags: 7,
            fstat=lambda fd: info,
            fdopen=lambda *a, **k: io.BytesIO(DATA),
            close=closed.append,
        ),
    )
    with pytest.raises(runtime.S3RuntimeError):
        runtime._read(path, 10)
    assert closed == [7]


def test_full_closure_rejects_extra_file_and_hash_drift_without_sdk_import(monkeypatch):
    row = manifest()
    executable = bytearray(64)
    executable[:6], executable[18:20] = b"\x7fELF\x02\x01", b"\x3e\x00"
    row["python"] = {"path": "/owned/python", **details(bytes(executable))}
    raw, digest = runtime._canonical(row), runtime._digest(row)
    monkeypatch.setattr(runtime, "Path", PurePosixPath)
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        monkeypatch.setattr(runtime.os, name, 0, raising=False)
    monkeypatch.setattr(runtime, "_protected", lambda *a, **k: None)
    content = {ROOT / "runtime.json": raw, PurePosixPath("/owned/python"): bytes(executable)}
    for name in row["files"]:
        content[ROOT / name] = DATA
    monkeypatch.setattr(runtime, "_read", lambda path, maximum: content[path])
    extra = [False]
    monkeypatch.setattr(
        runtime,
        "_tree",
        lambda root: {
            path.relative_to(root).as_posix() for path in content if path.is_relative_to(root)
        }
        | ({"unexpected.py"} if extra[0] else set()),
    )
    monkeypatch.setattr(
        runtime.importlib, "import_module", lambda name: pytest.fail("SDK import during readiness")
    )
    verified = runtime.validate_runtime(ROOT, digest)
    assert (
        verified.runtime_digest == digest and verified.worker_generation == row["worker_generation"]
    )
    with pytest.raises(FrozenInstanceError):
        verified.worker_generation = "changed"
    extra[0] = True
    with pytest.raises(runtime.S3RuntimeError):
        runtime.validate_runtime(ROOT, digest)
    extra[0] = False
    content[ROOT / "sdk/botocore/cacert.pem"] = b"different"
    with pytest.raises(runtime.S3RuntimeError):
        runtime.validate_runtime(ROOT, digest)


@pytest.mark.parametrize("real_metadata", [False, True])
def test_fixed_factory_disables_ambient_models_tokens_history_and_credentials(
    monkeypatch, tmp_path, real_metadata
):
    row = manifest()
    value = runtime.S3Runtime(
        ROOT,
        PurePosixPath("/owned/python"),
        ROOT / "stdlib",
        tmp_path if real_metadata else ROOT / "sdk",
        ROOT / "worker",
        runtime._digest(row),
        row["worker_generation"],
        runtime._canonical(row),
    )
    monkeypatch.setattr(runtime.S3Runtime, "assert_current", lambda self: None)
    monkeypatch.setattr(runtime.S3Runtime, "_admit_imports", lambda self: None)
    monkeypatch.setattr(runtime, "os", SimpleNamespace(environ={}))
    calls = []

    class Session:
        def set_config_variable(self, name, setting):
            calls.append((name, setting))

        def register_component(self, name, component):
            calls.append((name, component))

    imported = {
        "importlib.metadata": SimpleNamespace(
            DistributionFinder=SimpleNamespace(Context=lambda **k: k),
            MetadataPathFinder=SimpleNamespace(
                find_distributions=lambda context: [
                    SimpleNamespace(metadata={"Name": name}, version=version)
                    for name, version in runtime.VERSIONS.items()
                ]
            ),
        ),
        "botocore.session": SimpleNamespace(Session=Session),
        "botocore.config": SimpleNamespace(Config=object()),
        "botocore.exceptions": SimpleNamespace(ClientError=ValueError),
        "botocore.loaders": SimpleNamespace(Loader=lambda **k: k),
        "botocore.credentials": SimpleNamespace(
            CredentialResolver=lambda values: ("no_credentials", values)
        ),
        "botocore.tokens": SimpleNamespace(TokenProviderChain=lambda values: ("no_tokens", values)),
        "botocore.history": SimpleNamespace(
            get_global_history_recorder=lambda: SimpleNamespace(
                disable=lambda: calls.append("disabled")
            )
        ),
        "bluefire.s3_access_sdk_boundary": SimpleNamespace(BotocoreFactory=lambda **k: k),
    }
    if real_metadata:
        import importlib.machinery
        import importlib.metadata
        import socket
        import sys

        for name, version in runtime.VERSIONS.items():
            directory = tmp_path / (name.replace("-", "_") + "-" + version + ".dist-info")
            directory.mkdir()
            (directory / "METADATA").write_text(
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
            )
        metadata = importlib.metadata
        assert len(list(metadata.distributions(path=[str(tmp_path)]))) == 5

        def forbidden(*args, **kwargs):
            pytest.fail("metadata discovery attempted network access")

        monkeypatch.setattr(socket, "socket", forbidden)
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)

        class Finder:
            @staticmethod
            def find_spec(fullname, path=None, target=None):
                return importlib.machinery.PathFinder.find_spec(fullname, path, target)

        def restricted_finders(self):
            # Only finder compatibility is real here, not protected runtime admission.
            monkeypatch.setattr(
                sys,
                "meta_path",
                [importlib.machinery.BuiltinImporter, importlib.machinery.FrozenImporter, Finder],
            )
            assert list(metadata.distributions(path=[str(tmp_path)])) == []

        monkeypatch.setattr(runtime.S3Runtime, "_admit_imports", restricted_finders)
        imported["importlib.metadata"] = metadata
    monkeypatch.setattr(runtime.importlib, "import_module", lambda name: imported[name])
    factory = value.create_factory()
    factory["session_factory"]()
    assert ("config_file", "/dev/null") in calls and ("credentials_file", "/dev/null") in calls
    assert ("csm_enabled", False) in calls and ("profile", None) in calls
    assert (
        "data_loader",
        {
            "extra_search_paths": [str(value.sdk_root / "botocore/data")],
            "include_default_search_paths": False,
        },
    ) in calls
    assert ("credential_provider", ("no_credentials", [])) in calls
    assert ("token_provider", ("no_tokens", [])) in calls
    assert calls.count("disabled") == 2
    assert not any(
        name == "botocore" or name.startswith("botocore.") for name in runtime.sys.modules
    )


def test_import_boundary_admits_only_pinned_origins_and_exact_typing_aliases(monkeypatch, tmp_path):
    row = manifest()
    row["files"]["stdlib/typing.py"] = details()
    alias_io, alias_re = object(), object()
    typing = SimpleNamespace(
        __spec__=SimpleNamespace(origin=str(tmp_path / "stdlib/typing.py")),
        io=alias_io,
        re=alias_re,
    )
    modules = {
        "__main__": object(),
        "bluefire": object(),
        "typing": typing,
        "typing.io": alias_io,
        "typing.re": alias_re,
    }
    fake_sys = SimpleNamespace(
        flags=SimpleNamespace(isolated=1, no_site=1),
        dont_write_bytecode=True,
        executable=__import__("sys").executable,
        modules=modules,
        path=[],
        meta_path=[],
        path_importer_cache={"old": "entry"},
    )
    value = runtime.S3Runtime(
        tmp_path,
        Path(fake_sys.executable).resolve(),
        tmp_path / "stdlib",
        tmp_path / "sdk",
        tmp_path / "worker",
        runtime._digest(row),
        row["worker_generation"],
        runtime._canonical(row),
    )
    monkeypatch.setattr(runtime, "sys", fake_sys)
    monkeypatch.setattr(runtime, "os", SimpleNamespace(environ={}))
    monkeypatch.setattr(
        runtime, "logging", SimpleNamespace(CRITICAL=50, disable=lambda level: None)
    )
    monkeypatch.setattr(runtime, "_read", lambda *a: DATA)
    value._admit_imports()
    assert fake_sys.path == [
        str(tmp_path / "stdlib"),
        str(tmp_path / "stdlib/lib-dynload"),
        str(tmp_path / "sdk"),
    ]
    assert fake_sys.path_importer_cache == {} and len(fake_sys.meta_path) == 3
    modules["typing.io"] = object()
    with pytest.raises(runtime.S3RuntimeError):
        value._admit_imports()
    modules["typing.io"] = alias_io
    modules["unexpected"] = SimpleNamespace(__spec__=None)
    with pytest.raises(runtime.S3RuntimeError):
        value._admit_imports()
    modules["unexpected"] = SimpleNamespace(__spec__=SimpleNamespace(origin="/outside/unpinned.py"))
    with pytest.raises(runtime.S3RuntimeError):
        value._admit_imports()
    modules.pop("unexpected")
    # Copying stdlib does not change a system interpreter's actual -I origins.
    typing.__spec__ = SimpleNamespace(origin="/usr/lib/python3.12/typing.py")
    with pytest.raises(runtime.S3RuntimeError):
        value._admit_imports()


def test_worker_crlf_bytes_cannot_claim_normalized_native_generation(monkeypatch):
    row = manifest()
    row["files"]["worker/util.py"] = details(b"line\r\n")
    row["worker_generation"] = runtime._digest(
        {
            name.split("/", 1)[1]: value
            for name, value in row["files"].items()
            if name.startswith("worker/")
        }
    )
    assert parse(row) == row
    # Structural parsing uses the declared raw bytes; the filesystem verifier
    # must additionally reject CRLF before returning a usable runtime.
    executable = bytearray(64)
    executable[:6], executable[18:20] = b"\x7fELF\x02\x01", b"\x3e\x00"
    row["python"] = {"path": "/owned/python", **details(bytes(executable))}
    raw, digest = runtime._canonical(row), runtime._digest(row)
    monkeypatch.setattr(runtime, "Path", PurePosixPath)
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        monkeypatch.setattr(runtime.os, name, 0, raising=False)
    monkeypatch.setattr(runtime, "_protected", lambda *a, **k: None)
    content = {ROOT / "runtime.json": raw, PurePosixPath("/owned/python"): bytes(executable)}
    content.update(
        {ROOT / name: (b"line\r\n" if name == "worker/util.py" else DATA) for name in row["files"]}
    )
    monkeypatch.setattr(runtime, "_read", lambda path, maximum: content[path])
    monkeypatch.setattr(
        runtime,
        "_tree",
        lambda root: {
            path.relative_to(root).as_posix() for path in content if path.is_relative_to(root)
        },
    )
    with pytest.raises(runtime.S3RuntimeError):
        runtime.validate_runtime(ROOT, digest)
