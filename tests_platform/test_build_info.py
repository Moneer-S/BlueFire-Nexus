from __future__ import annotations

import json
import runpy
from pathlib import Path
from unittest.mock import patch

import pytest
from setuptools.dist import Distribution

import bluefire.build_info as diagnostic
from bluefire.service import BlueFireService
from bluefire.version import __version__

REPOSITORY = Path(__file__).resolve().parents[1]


def _hook():
    with patch("setuptools.setup"):
        return runpy.run_path(str(REPOSITORY / "setup.py"))


def _package(tmp_path: Path) -> Path:
    root = tmp_path / "bluefire"
    (root / "ui").mkdir(parents=True)
    for name in ("app.js", "index.html", "styles.css"):
        (root / "ui" / name).write_bytes((name + "\n").encode())
    return root


@pytest.mark.parametrize("revision", [None, "$Format:%H$", "a" * 40])
def test_build_output_roundtrips_actual_assets_without_runtime_revision_inference(
    tmp_path, monkeypatch, revision
):
    root = _package(tmp_path)
    if revision is not None:
        (root / "_source_revision.txt").write_text(revision, encoding="ascii")
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.setenv("BLUEFIRE_SOURCE_REVISION", "c" * 40)
    _hook()["_write_build_identity"](root, root, __version__)
    monkeypatch.setattr(diagnostic, "_PACKAGE_ROOT", root)
    result = BlueFireService.build_info(object())
    assert result["product"]["version"] == __version__
    assert result["source"] == {
        "revision": revision if revision == "a" * 40 else None,
        "provenance": "git_archive" if revision == "a" * 40 else "unavailable",
    }
    assert result["build"]["metadata_status"] == "embedded"
    assert result["ui"]["matches_build"] is True
    assert [item["name"] for item in result["ui"]["files"]] == [
        "app.js",
        "index.html",
        "styles.css",
    ]
    assert str(tmp_path) not in json.dumps(result)
    original_digest = result["ui"]["digest"]
    (root / "ui" / "app.js").write_bytes(b"changed UI\n")
    changed = diagnostic.build_info()
    assert changed["ui"]["digest"] != original_digest
    assert changed["ui"]["matches_build"] is False
    assert changed["build"] == result["build"]


def test_old_install_without_build_metadata_reports_unavailable_not_a_guessed_revision(
    tmp_path, monkeypatch
):
    root = _package(tmp_path)
    monkeypatch.setattr(diagnostic, "_PACKAGE_ROOT", root)
    result = diagnostic.build_info()
    assert result["build"] == {"metadata_status": "unavailable", "digest": None}
    assert result["source"] == {"revision": None, "provenance": "unavailable"}
    assert result["ui"]["digest"]
    assert result["ui"]["matches_build"] is None


@pytest.mark.parametrize(
    "payload", [b"not JSON", b'{"schema_version":1,"schema_version":2}', b"{}", b"x" * 16385]
)
def test_invalid_metadata_is_bounded_and_does_not_echo_contents(tmp_path, monkeypatch, payload):
    root = _package(tmp_path)
    (root / "_build_info.json").write_bytes(payload)
    monkeypatch.setattr(diagnostic, "_PACKAGE_ROOT", root)
    result = diagnostic.build_info()
    assert result["build"] == {"metadata_status": "invalid", "digest": None}
    assert result["source"]["revision"] is None


@pytest.mark.parametrize("change", ["version", "revision", "inventory", "digest"])
def test_metadata_validation_refuses_wrong_version_or_unbound_asset_inventory(
    tmp_path, monkeypatch, change
):
    root = _package(tmp_path)
    _hook()["_write_build_identity"](root, root, __version__)
    path = root / "_build_info.json"
    value = json.loads(path.read_text())
    if change == "version":
        value["version"] = "0.0.0"
    elif change == "revision":
        value["source_revision"] = "a" * 40
    elif change == "inventory":
        value["ui_files"][0]["name"] = "../unrelated"
    else:
        value["ui_digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(diagnostic, "_PACKAGE_ROOT", root)
    assert diagnostic.build_info()["build"]["metadata_status"] == "invalid"


def test_unavailable_asset_is_not_a_matching_build(tmp_path, monkeypatch):
    root = _package(tmp_path)
    _hook()["_write_build_identity"](root, root, __version__)
    (root / "ui" / "app.js").unlink()
    monkeypatch.setattr(diagnostic, "_PACKAGE_ROOT", root)
    assert diagnostic.build_info()["ui"] == {"digest": None, "files": [], "matches_build": False}


def test_build_command_writes_only_output_and_includes_metadata_in_wheel_files(
    tmp_path, monkeypatch
):
    root = _package(tmp_path / "output")
    source = tmp_path / "source"
    (source / "bluefire").mkdir(parents=True)
    (source / "bluefire" / "_source_revision.txt").write_text("a" * 40)
    namespace = _hook()
    command_type = namespace["ArtifactIdentityBuild"]
    monkeypatch.setitem(command_type.run.__globals__, "_ROOT", source)
    monkeypatch.setattr(namespace["build_py"], "run", lambda _self: None)
    monkeypatch.setattr(namespace["build_py"], "get_outputs", lambda _self, **_kwargs: [])
    command = command_type(Distribution({"name": "bluefire-nexus", "version": __version__}))
    command.build_lib = str(root.parent)
    command.run()
    assert command.get_outputs() == [str(root / "_build_info.json")]
    assert not (source / "bluefire" / "_build_info.json").exists()
    assert json.loads((root / "_build_info.json").read_text())["source_revision"] == "a" * 40


def test_build_refuses_unrecognized_archive_marker(tmp_path):
    root = _package(tmp_path)
    (root / "_source_revision.txt").write_text("not a commit")
    with pytest.raises(RuntimeError, match="source revision"):
        _hook()["_write_build_identity"](root, root, __version__)
    assert not (root / "_build_info.json").exists()


@pytest.mark.parametrize("unsafe", ["directory", "oversized", "symlink"])
def test_diagnostic_read_refuses_unsafe_resources_before_open(tmp_path, monkeypatch, unsafe):
    path = tmp_path / "resource"
    if unsafe == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"x" * (33 if unsafe == "oversized" else 1))
    if unsafe == "symlink":
        monkeypatch.setattr(Path, "is_symlink", lambda _path: True)

    def no_open(*_args, **_kwargs):
        raise AssertionError("unsafe resource was opened")

    monkeypatch.setattr(diagnostic.os, "open", no_open)
    with pytest.raises(ValueError, match="unavailable"):
        diagnostic._read_regular(path, 32)
