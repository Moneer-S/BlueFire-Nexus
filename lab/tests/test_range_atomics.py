"""The published files a range carries: fetched at the spec's commit and refused, by name, unless the lock agrees."""

import json
import shutil
import urllib.request
from pathlib import Path

import pytest

from bluefire_lab.range import atomics
from bluefire_lab.range import spec as range_spec

SMALL = Path(__file__).parent / "fixtures" / "range" / "small" / "small.yaml"
RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
COMMIT = "a" * 40
PUBLISHED = {
    "LICENSE.txt": b"The MIT License, a stand-in\n",
    "atomics/T1105/src/atomic.sh": b"#!/bin/sh\necho hello\n",
    "atomics/T1110.004/src/credstuffuserpass.txt": b"root:toor\nadmin:admin\n",
}


def fetcher(published: dict[str, bytes], asked: list[str] | None = None):
    def get(url: str) -> bytes:
        if asked is not None:
            asked.append(url)
        return published[url.split(f"/{COMMIT}/", 1)[1]]

    return get


def copied(tmp_path: Path) -> Path:
    """The small spec with its files, in a folder of the test's own, so that its lock can be written."""

    folder = tmp_path / "small"
    shutil.copytree(SMALL.parent, folder)
    return folder / "small.yaml"


def test_the_fetcher_authenticates_only_github_api_requests(monkeypatch) -> None:
    asked: list[urllib.request.Request] = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *unused):
            return None

        def read(self) -> bytes:
            return b"response"

    def open_(request, timeout):
        assert timeout == atomics.FETCH_SECONDS
        asked.append(request)
        return Response()

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "a-test-token")
    monkeypatch.setattr(urllib.request, "urlopen", open_)

    assert atomics.http_get("https://api.github.com/repos/example/rules") == b"response"
    assert atomics.http_get("https://raw.githubusercontent.com/example/rules/a/file") == b"response"

    assert asked[0].get_header("Authorization") == "Bearer a-test-token"
    assert asked[1].get_header("Authorization") is None


def test_every_file_is_fetched_at_the_commit_and_checked_against_the_lock() -> None:
    asked: list[str] = []

    found = atomics.fetch(range_spec.load(SMALL), fetcher(PUBLISHED, asked))

    assert found == PUBLISHED
    assert sorted(asked) == [
        f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{COMMIT}/{path}"
        for path in sorted(PUBLISHED)
    ]


def test_a_changed_file_is_refused_by_its_name() -> None:
    changed = {**PUBLISHED, "atomics/T1105/src/atomic.sh": b"#!/bin/sh\necho changed\n"}

    with pytest.raises(range_spec.SpecError) as refused:
        atomics.fetch(range_spec.load(SMALL), fetcher(changed))

    assert str(refused.value).startswith(f"atomics/T1105/src/atomic.sh at {COMMIT} has SHA-256 ")
    assert "small.lock says bfdeaeb0" in str(refused.value)
    assert "the build stops" in str(refused.value)


def test_a_file_the_spec_needs_and_the_lock_does_not_list_is_refused(tmp_path: Path) -> None:
    path = copied(tmp_path)
    lock = path.parent / "small.lock"
    lock.write_text("\n".join(line for line in lock.read_text().splitlines() if "T1105" not in line) + "\n")

    with pytest.raises(range_spec.SpecError, match="small.lock does not list atomics/T1105/src/atomic.sh"):
        atomics.fetch(range_spec.load(path), fetcher(PUBLISHED))


def test_a_lock_for_another_commit_is_refused(tmp_path: Path) -> None:
    path = copied(tmp_path)
    lock = path.parent / "small.lock"
    lock.write_text(lock.read_text().replace(COMMIT, "b" * 40))

    with pytest.raises(range_spec.SpecError, match="is not for redcanaryco/atomic-red-team at a{40}"):
        atomics.fetch(range_spec.load(path), fetcher(PUBLISHED))


def test_a_password_that_is_not_on_the_line_the_spec_names_is_refused() -> None:
    other = {**PUBLISHED, "atomics/T1110.004/src/credstuffuserpass.txt": b"root:toor\nadmin:secret\n"}
    spec = range_spec.load(SMALL)

    with pytest.raises(range_spec.SpecError, match="line 2 of atomics/T1110.004/src/credstuffuserpass.txt"):
        atomics.check_listed(
            "admin",
            "admin",
            spec.hosts["web"].account("admin").listed,
            other["atomics/T1110.004/src/credstuffuserpass.txt"],
        )


def test_the_lock_command_lists_the_src_folders_and_writes_every_hash(tmp_path: Path) -> None:
    path = copied(tmp_path)
    (path.parent / "small.lock").unlink()
    listing = [{"type": "file", "path": "atomics/T1110.004/src/credstuffuserpass.txt"}]

    def get(url: str) -> bytes:
        if url.startswith("https://api.github.com/"):
            assert url.endswith(f"/contents/atomics/T1110.004/src?ref={COMMIT}")
            return json.dumps(listing).encode()
        return fetcher(PUBLISHED)(url)

    written = atomics.lock(range_spec.load(path), get)

    assert written.read_text() == (SMALL.parent / "small.lock").read_text()


def test_range_one_needs_the_paths_yamls_its_carried_folder_and_its_served_file() -> None:
    spec = range_spec.load(RANGE_ONE)

    assert atomics.src_folders(spec) == ["atomics/T1110.004/src"]
    singles = atomics.single_files(spec)
    assert "atomics/T1105/src/atomic.sh" in singles
    assert "atomics/T1110.004/src/credstuffuserpass.txt" in singles
    assert {path for path in singles if path.endswith(".yaml")} == {
        f"atomics/{t}/{t}.yaml"
        for t in (
            "T1110.004",
            "T1105",
            "T1082",
            "T1018",
            "T1046",
            "T1552.001",
            "T1552.004",
            "T1048",
            "T1560.001",
            "T1048.002",
        )
    }
    locked = atomics.read_lock((RANGE_ONE.parent / "range-one.lock").read_text(), spec)
    assert atomics.wanted(spec, locked) == sorted(locked)
