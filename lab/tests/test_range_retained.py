import hashlib
import json
from pathlib import Path

import pytest

from bluefire_lab.__main__ import main
from bluefire_lab.range import recording, retained

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
SURICATA_IMAGE = "registry.example/suricata:8.0.8@sha256:" + "a" * 64


def _bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_proof(root: Path, document: dict) -> None:
    (root / retained.PROVENANCE).write_bytes(_bytes(document))


def _proof(root: Path) -> dict:
    return json.loads((root / retained.PROVENANCE).read_text(encoding="utf-8"))


def held_run(tmp_path: Path) -> Path:
    root = tmp_path / "held"
    files = root / "files"
    files.mkdir(parents=True)
    spec = RANGE_ONE.read_bytes()
    manifest = {
        "range": "range-one",
        "run_id": "20261126T010203Z-abc123",
        "run_url": "https://github.com/example/bluefire/actions/runs/123456",
        "spec": {"file": "range-one.yaml"},
        "result": "sealed",
        "exit_code": 0,
        "teardown_complete": True,
        "recording_clock": {
            "started": "2026-11-26T01:02:03.000000Z",
            "ended": "2026-11-26T01:03:04.000000Z",
            "basis": "the first and last Docker event timeNano selected by the hosted workflow",
        },
    }
    payloads = {
        "files/manifest.json": ("manifest.json", "manifest", _bytes(manifest)),
        "files/range-one.yaml": ("range-one.yaml", "run spec", spec),
        "files/raw/sensor.json": ("raw/sensor.json", "sensor telemetry", b'{"event":"one"}\n'),
    }
    entries = []
    for stored_path, (run_path, role, content) in payloads.items():
        path = root / stored_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        entries.append(
            {
                "stored_path": stored_path,
                "run_path": run_path,
                "artifact_path": f"retained/{stored_path}",
                "role": role,
                "bytes": len(content),
            }
        )
    entries.sort(key=lambda entry: entry["stored_path"])
    proof = {
        "schema": retained.SCHEMA,
        "source": {
            "repository": "example/bluefire",
            "workflow": ".github/workflows/range-one.yml",
            "run_id": 123456,
            "run_attempt": 1,
            "job": "retained range",
            "head": "1" * 12,
            "run_url": manifest["run_url"],
            "artifact": "range-one-retained",
        },
        "run": {
            "id": manifest["run_id"],
            "spec": "range-one.yaml",
            "result": "sealed",
            "exit_code": 0,
        },
        "files": entries,
    }
    _write_proof(root, proof)
    return root


def source_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): _sha(path.read_bytes())
        for path in root.rglob("*")
        if path.is_file()
    }


def test_verifies_and_materializes_only_exact_identity_mapped_bytes(tmp_path):
    source = held_run(tmp_path)
    before = source_hashes(source)

    proof = retained.verify_retained(source)
    out = tmp_path / "copy"
    retained.materialize_retained(source, out)

    assert proof.run["id"] == "20261126T010203Z-abc123"
    assert (out / "manifest.json").read_bytes() == (source / "files/manifest.json").read_bytes()
    assert (out / "raw/sensor.json").read_bytes() == (source / "files/raw/sensor.json").read_bytes()
    assert (out / "range-one.yaml").read_bytes() == (source / "files/range-one.yaml").read_bytes()
    assert sorted(path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file()) == [
        "manifest.json",
        "range-one.yaml",
        "raw/sensor.json",
    ]
    assert source_hashes(source) == before


@pytest.mark.parametrize("problem", ["changed", "missing", "extra"])
def test_refuses_a_changed_or_inexact_file_closure(tmp_path, problem):
    source = held_run(tmp_path)
    sensor = source / "files/raw/sensor.json"
    if problem == "changed":
        sensor.write_bytes(sensor.read_bytes() + b"changed\n")
    elif problem == "missing":
        sensor.unlink()
    else:
        (source / "files/extra.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(retained.RetainedError):
        retained.verify_retained(source)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stored_path", "files/../outside"),
        ("stored_path", "/files/manifest.json"),
        ("run_path", "../outside"),
        ("run_path", "/manifest.json"),
    ],
)
def test_refuses_unsafe_paths(tmp_path, field, value):
    source = held_run(tmp_path)
    proof = _proof(source)
    proof["files"][0][field] = value
    _write_proof(source, proof)

    with pytest.raises(retained.RetainedError, match="normalized relative POSIX path"):
        retained.verify_retained(source)


@pytest.mark.parametrize("same", ["stored_path", "run_path", "artifact_path"])
def test_refuses_duplicate_paths(tmp_path, same):
    source = held_run(tmp_path)
    proof = _proof(source)
    proof["files"][1][same] = proof["files"][0][same]
    proof["files"].sort(key=lambda entry: entry["stored_path"])
    _write_proof(source, proof)

    with pytest.raises(retained.RetainedError, match=f"same {same}"):
        retained.verify_retained(source)


def test_refuses_a_link_anywhere_in_the_source(tmp_path):
    source = held_run(tmp_path)
    (source / "files/link.json").symlink_to(source / "files/raw/sensor.json")

    with pytest.raises(retained.RetainedError, match="is a link"):
        retained.verify_retained(source)


@pytest.mark.parametrize("relative", [retained.PROVENANCE, "files/raw/sensor.json"])
def test_refuses_a_declared_file_hard_linked_to_an_outside_file(tmp_path, relative):
    source = held_run(tmp_path)
    original = source / relative
    outside = tmp_path / f"outside-{original.name}"
    outside.write_bytes(original.read_bytes())
    original.unlink()
    original.hardlink_to(outside)

    with pytest.raises(retained.RetainedError, match="more than one hard link"):
        retained.verify_retained(source)


def test_refuses_an_unlisted_hard_link_to_an_outside_file(tmp_path):
    source = held_run(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (source / "files/unlisted.json").hardlink_to(outside)

    with pytest.raises(retained.RetainedError, match="more than one hard link"):
        retained.verify_retained(source)


def test_refuses_an_existing_or_overlapping_output(tmp_path):
    source = held_run(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()

    with pytest.raises(retained.RetainedError, match="exists"):
        retained.materialize_retained(source, existing)
    with pytest.raises(retained.RetainedError, match="must not contain"):
        retained.materialize_retained(source, source / "copy")
    assert not (source / "copy").exists()


def test_removes_its_partial_folder_when_copying_fails(tmp_path, monkeypatch):
    source = held_run(tmp_path)
    out = tmp_path / "parent/copy"
    original = retained.shutil.copyfileobj
    calls = 0

    def fail_on_second_file(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("copy stopped")
        return original(*args, **kwargs)

    monkeypatch.setattr(retained.shutil, "copyfileobj", fail_on_second_file)

    with pytest.raises(retained.RetainedError, match="copy stopped"):
        retained.materialize_retained(source, out)
    assert not out.exists()
    assert list(out.parent.iterdir()) == []


def test_rejudge_uses_only_a_copy_and_publishes_recording_and_replay(tmp_path, monkeypatch):
    source = held_run(tmp_path)
    before = source_hashes(source)
    rule_engine = tmp_path / "Zircolite"
    rule_engine.write_text("program\n", encoding="utf-8")
    template = tmp_path / "replay-template.html"
    template.write_text("template\n", encoding="utf-8")
    out = tmp_path / "rejudged"
    called = []

    def rules(spec, folder):
        called.append(("rules", spec, folder))
        return 0

    def rescore(folder, program, defenses, *, suricata_image=None):
        called.append(("score", defenses, folder, program, suricata_image))
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["spec"]["file"] == "range-one.yaml"
        assert manifest["spec"]["text"] == RANGE_ONE.read_text(encoding="utf-8")
        assert len(manifest["spec"]["sha256"]) == 64
        (folder / "recording.json").write_text('{"recording":"new"}\n', encoding="utf-8")
        return 0

    def replay(recording, page_template, page):
        called.append(("replay", recording, page_template, page))
        page.write_text("replay\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(retained.engine, "rules", rules)
    monkeypatch.setattr(retained.engine, "rescore", rescore)
    monkeypatch.setattr(retained.replay_page, "main", replay)

    assert (
        retained.rejudge(
            source,
            RANGE_ONE,
            out,
            template,
            rule_engine,
            suricata_image=SURICATA_IMAGE,
        )
        == 0
    )
    assert [entry[0] for entry in called] == ["rules", "score", "replay"]
    assert called[1][-1] == SURICATA_IMAGE
    assert (out / "recording.json").read_text(encoding="utf-8") == '{"recording":"new"}\n'
    assert (out / "replay.html").read_text(encoding="utf-8") == "replay\n"
    assert source_hashes(source) == before


def test_range_rejudge_command_passes_every_named_input(monkeypatch):
    called = []

    def rejudge(*arguments, suricata_image=None):
        called.append((arguments, suricata_image))
        return 7

    monkeypatch.setattr(retained, "rejudge", rejudge)

    assert (
        main(
            [
                "range",
                "rejudge",
                "held",
                "--defenses",
                "later.yaml",
                "--engine",
                "Zircolite",
                "--suricata-image",
                SURICATA_IMAGE,
                "--template",
                "replay-template.html",
                "--out",
                "new-evaluation",
            ]
        )
        == 7
    )
    assert called == [
        (
            (
                Path("held"),
                Path("later.yaml"),
                Path("new-evaluation"),
                Path("replay-template.html"),
                Path("Zircolite"),
            ),
            SURICATA_IMAGE,
        )
    ]


def test_range_rejudge_does_not_invent_a_suricata_image(monkeypatch):
    called = []

    def rejudge(*arguments, suricata_image=None):
        called.append(suricata_image)
        return 0

    monkeypatch.setattr(retained, "rejudge", rejudge)

    assert (
        main(
            [
                "range",
                "rejudge",
                "held",
                "--defenses",
                "later.yaml",
                "--template",
                "replay-template.html",
                "--out",
                "new-evaluation",
            ]
        )
        == 0
    )
    assert called == [None]


def test_rejudge_failure_leaves_no_output_or_partial_folder(tmp_path, monkeypatch):
    source = held_run(tmp_path)
    rule_engine = tmp_path / "Zircolite"
    rule_engine.write_text("program\n", encoding="utf-8")
    template = tmp_path / "template.html"
    template.write_text("template\n", encoding="utf-8")
    out = tmp_path / "parent/rejudged"
    monkeypatch.setattr(retained.engine, "rules", lambda *_: 1)

    assert retained.rejudge(source, RANGE_ONE, out, template, rule_engine) == 1
    assert not out.exists()
    assert list(out.parent.iterdir()) == []


def test_rejudge_discards_a_copied_recording_and_requires_a_new_one(tmp_path, monkeypatch, capsys):
    source = held_run(tmp_path)
    stale = b'{"recording":"stale"}\n'
    stored = source / "files/stale-recording.json"
    stored.write_bytes(stale)
    proof = _proof(source)
    proof["files"].append(
        {
            "stored_path": "files/stale-recording.json",
            "run_path": "recording.json",
            "artifact_path": "retained/files/stale-recording.json",
            "role": "derived recording that must not be reused",
            "bytes": len(stale),
        }
    )
    proof["files"].sort(key=lambda entry: entry["stored_path"])
    _write_proof(source, proof)
    rule_engine = tmp_path / "Zircolite"
    rule_engine.write_text("program\n", encoding="utf-8")
    template = tmp_path / "template.html"
    template.write_text("template\n", encoding="utf-8")
    out = tmp_path / "parent/rejudged"
    replayed = []
    monkeypatch.setattr(retained.engine, "rules", lambda *_: 0)

    def rescore_without_output(folder, *_, **__):
        assert not (folder / "recording.json").exists()
        return 0

    monkeypatch.setattr(retained.engine, "rescore", rescore_without_output)
    monkeypatch.setattr(retained.replay_page, "main", lambda *_: replayed.append(True) or 0)

    assert retained.rejudge(source, RANGE_ONE, out, template, rule_engine) == 2
    assert "newly generated recording.json" in capsys.readouterr().err
    assert replayed == []
    assert not out.exists()
    assert list(out.parent.iterdir()) == []


def test_rejudge_catches_a_same_size_source_edit_before_publish(tmp_path, monkeypatch):
    source = held_run(tmp_path)
    sensor = source / "files/raw/sensor.json"
    rule_engine = tmp_path / "Zircolite"
    rule_engine.write_text("program\n", encoding="utf-8")
    template = tmp_path / "template.html"
    template.write_text("template\n", encoding="utf-8")
    out = tmp_path / "parent/rejudged"
    monkeypatch.setattr(retained.engine, "rules", lambda *_: 0)

    def rescore(folder, *_, **__):
        (folder / "recording.json").write_text('{"recording":"new"}\n', encoding="utf-8")
        return 0

    def edit_source_then_replay(_, __, page):
        sensor.write_bytes(sensor.read_bytes().replace(b"one", b"two"))
        page.write_text("replay\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(retained.engine, "rescore", rescore)
    monkeypatch.setattr(retained.replay_page, "main", edit_source_then_replay)

    assert retained.rejudge(source, RANGE_ONE, out, template, rule_engine) == 2
    assert not out.exists()
    assert list(out.parent.iterdir()) == []


def test_a_retained_manifest_carries_only_the_selected_docker_clock_times(tmp_path):
    manifest = {
        "recording_clock": {
            "started": "2026-11-26T01:02:03.000000Z",
            "ended": "2026-11-26T01:03:04.000000Z",
            "basis": "the first and last Docker event timeNano selected by the hosted workflow",
        }
    }

    assert recording.run_times(tmp_path, manifest) == (
        "2026-11-26T01:02:03.000000Z",
        "2026-11-26T01:03:04.000000Z",
    )


def test_a_retained_recording_clock_must_be_ordered_and_timezone_aware(tmp_path):
    manifest = {
        "recording_clock": {
            "started": "2026-11-26T01:03:04.000000Z",
            "ended": "2026-11-26T01:02:03.000000Z",
        }
    }

    with pytest.raises(ValueError, match="ordered, timezone-aware"):
        recording.run_times(tmp_path, manifest)
