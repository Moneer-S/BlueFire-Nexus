import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from bluefire_lab.range import engine, retained, retained_secret_gate

REPOSITORY = Path(__file__).parents[2]
SPEC = REPOSITORY / "lab/range/retained-packet.yaml"
BASELINE = REPOSITORY / ".secrets.baseline"
SCRIPT = b'#!/bin/bash \necho "Hello From Atomic Red Team"'
HASHES = {name: hashlib.new(name, SCRIPT).hexdigest() for name in retained_secret_gate.HEX}
SOURCE_HEAD = "1" * 40


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


def _event(
    event: str,
    identity: str,
    *,
    path: str = "/tmp/atomic.sh",
    expected: dict[str, dict[str, str]] | None = None,
) -> dict:
    decoder, rule_id, suffixes = retained_secret_gate.EVENTS[event]
    expected = expected or {suffix: HASHES for suffix in suffixes}
    syscheck = {"path": path, "mode": "realtime", "event": event}
    for suffix, hashes in expected.items():
        for algorithm, digest in hashes.items():
            syscheck[f"{algorithm}_{suffix}"] = digest
    full_log = f"File '{path}' {event}\nMode: realtime\n"
    if event == "modified":
        full_log += "Changed attributes: md5,sha1,sha256\n"
        for algorithm in retained_secret_gate.HEX:
            full_log += f"Old {algorithm}sum was: '{expected['before'][algorithm]}'\n"
            full_log += f"New {algorithm}sum is : '{expected['after'][algorithm]}'\n"
    return {
        "timestamp": f"2026-11-27T01:02:0{identity}.000+0000",
        "rule": {
            "id": rule_id,
            "groups": ["ossec", "syscheck", f"syscheck_entry_{event}", "syscheck_file"],
        },
        "agent": {"id": "001", "name": "web"},
        "manager": {"name": "manager"},
        "id": f"archive-{identity}",
        "full_log": full_log,
        "syscheck": syscheck,
        "decoder": {"name": decoder},
        "location": "syscheck",
    }


def _ndjson(records: list[dict]) -> bytes:
    return b"".join(json.dumps(record, sort_keys=True).encode() + b"\n" for record in records)


def _write_candidate(tmp_path: Path) -> tuple[Path, Path, Path]:
    workspace = tmp_path / "workspace"
    tracked_spec = workspace / "lab/range/retained-packet.yaml"
    tracked_spec.parent.mkdir(parents=True)
    tracked_spec.write_bytes(SPEC.read_bytes())
    (tracked_spec.parent / "retained-packet.lock").write_bytes(
        (SPEC.parent / "retained-packet.lock").read_bytes()
    )
    (workspace / ".secrets.baseline").write_bytes(BASELINE.read_bytes())
    repository = tmp_path / "candidate-repository"
    root = repository / "lab/retained/packet-download"
    files = root / "files"
    files.mkdir(parents=True)
    packet = b"small genuine-packet stand-in for semantic tests"
    packet_sha = hashlib.sha256(packet).hexdigest()
    manifest = {
        "range": "retained-packet",
        "run_id": "20261127T010203Z-abc123",
        "run_url": "https://github.com/example/bluefire/actions/runs/123456",
        "spec": {"file": "retained-packet.yaml"},
        "atomic_red_team": {"commit": "".join(("a0e3f9bc", "69fed2fd", "711bd1f1", "aa87a40c", "33482fe6"))},
        "defense": {
            "fim_marks": [
                {"host": "web", "folder": "/tmp", "event": event, "made": True, "archived": True}
                for event in ("added", "modified")
            ]
        },
        "packet_capture": {
            "hosts": {
                "web": {
                    "files": {
                        "eth0.pcap": {
                            "file": "raw/hosts/web/var/log/bluefire/packets/eth0.pcap",
                            "bytes": len(packet),
                            "sha256": packet_sha,
                        }
                    }
                }
            }
        },
        "result": "sealed",
        "exit_code": 0,
        "teardown_complete": True,
        "recording_clock": {
            "started": "2026-11-27T01:02:03.000000Z",
            "ended": "2026-11-27T01:03:04.000000Z",
            "basis": "Docker event times selected by the hosted workflow",
        },
    }
    marker_path = f"/tmp/bluefire-mark-{manifest['run_id']}.txt"
    created = retained_secret_gate._payload_hashes(engine.FIM_MARK_CREATED)
    changed = retained_secret_gate._payload_hashes(engine.FIM_MARK_CHANGED)
    events = [
        _event("added", "1"),
        _event("deleted", "2"),
        _event("added", "3", path=marker_path, expected={"after": created}),
        _event("modified", "4", path=marker_path, expected={"before": created, "after": changed}),
    ]
    alerts = []
    for record in events:
        copied = json.loads(json.dumps(record))
        copied["id"] = copied["id"].replace("archive", "alert")
        alerts.append(copied)
    payloads = {
        "files/manifest.json": ("manifest.json", "minimal truthful run context", _json_bytes(manifest)),
        "files/retained-packet.yaml": ("retained-packet.yaml", "exact tracked run spec", SPEC.read_bytes()),
        "files/raw/hosts/web/var/log/bluefire/packets/eth0.pcap": (
            "raw/hosts/web/var/log/bluefire/packets/eth0.pcap",
            "raw packet capture",
            packet,
        ),
        "files/raw/hosts/manager/var/ossec/logs/archives/archives.json": (
            "raw/hosts/manager/var/ossec/logs/archives/archives.json",
            "complete raw Wazuh archive",
            _ndjson(events),
        ),
        "files/raw/hosts/manager/var/ossec/logs/alerts/alerts.json": (
            "raw/hosts/manager/var/ossec/logs/alerts/alerts.json",
            "complete raw Wazuh alerts",
            _ndjson(alerts),
        ),
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
                "artifact_path": "lab/retained/packet-download/" + stored_path,
                "role": role,
                "bytes": len(content),
            }
        )
    entries.sort(key=lambda entry: entry["stored_path"])
    proof = {
        "schema": retained.SCHEMA,
        "source": {
            "repository": "example/bluefire",
            "workflow": ".github/workflows/retained-packet.yml",
            "run_id": 123456,
            "run_attempt": 1,
            "job": "make-fixture",
            "head": SOURCE_HEAD[:12],
            "run_url": manifest["run_url"],
            "artifact": "retained-packet-run-1",
        },
        "run": {
            "id": manifest["run_id"],
            "spec": "retained-packet.yaml",
            "result": "sealed",
            "exit_code": 0,
        },
        "files": entries,
    }
    (root / "provenance.json").write_bytes(_json_bytes(proof))
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    script = workspace / "range-build/atomics/T1105/src/atomic.sh"
    script.parent.mkdir(parents=True)
    script.write_bytes(SCRIPT)
    return repository, root, script


def _rewrite(root: Path, run_path: str, content: bytes) -> None:
    proof_path = root / "provenance.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    entry = next(entry for entry in proof["files"] if entry["run_path"] == run_path)
    path = root / entry["stored_path"]
    path.write_bytes(content)
    entry["bytes"] = len(content)
    proof_path.write_bytes(_json_bytes(proof))


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def _certify(repository: Path, root: Path, script: Path):
    return retained_secret_gate.certify(repository, root, _spec_for(script), script, SOURCE_HEAD)


def _spec_for(script: Path) -> Path:
    return script.parents[4] / "lab/range/retained-packet.yaml"


def _baseline_for(script: Path) -> Path:
    return script.parents[4] / ".secrets.baseline"


def test_engine_fim_mark_constants_preserve_the_exact_written_bytes():
    assert engine.FIM_MARK_WRITES == (
        (">", r"file created\n", "file created", "added"),
        (">>", r"file changed\n", "file changed", "modified"),
    )
    assert engine.FIM_MARK_CHANGED == b"file created\nfile changed\n"


def _fake_hook(tmp_path: Path, results: dict[str, list[dict]], monkeypatch) -> Path:
    payload = tmp_path / "fake-results.json"
    payload.write_text(json.dumps(results), encoding="utf-8")
    hook = tmp_path / "detect-secrets-hook"
    hook.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('1.5.0')\n"
        "    raise SystemExit(0)\n"
        "settings = json.loads(pathlib.Path(sys.argv[3]).read_text())\n"
        "for item in settings['filters_used']:\n"
        "    if item.get('path') == 'detect_secrets.filters.common.is_baseline_file':\n"
        "        item['filename'] = sys.argv[3]\n"
        "settings['results'] = json.loads(pathlib.Path(os.environ['FAKE_RESULTS']).read_text())\n"
        "print(json.dumps(settings))\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    monkeypatch.setenv("FAKE_RESULTS", str(payload))
    return hook


def test_certifies_only_source_bound_manifest_packet_and_mirrored_fim_fingerprints(tmp_path):
    repository, root, script = _write_candidate(tmp_path)
    before = _tree_hashes(root)

    proof, certifications, tracked = _certify(repository, root, script)

    assert proof.run["id"] == "20261127T010203Z-abc123"
    assert len(certifications) == 20
    assert len({(entry.filename, entry.secret_hash) for entry in certifications}) == 20
    assert tracked == sorted(
        path.relative_to(repository).as_posix() for path in root.rglob("*") if path.is_file()
    )
    assert _tree_hashes(root) == before


@pytest.mark.parametrize("problem", ["atomic pin", "packet digest", "packet path", "FIM mark", "script"])
def test_refuses_unbound_source_fingerprints(tmp_path, problem):
    repository, root, script = _write_candidate(tmp_path)
    manifest_path = root / "files/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    packet = manifest["packet_capture"]["hosts"]["web"]["files"]["eth0.pcap"]
    if problem == "atomic pin":
        manifest["atomic_red_team"]["commit"] = "0" * 40
    elif problem == "packet digest":
        packet["sha256"] = "0" * 64
    elif problem == "packet path":
        packet["file"] = "raw/hosts/web/var/log/bluefire/packets/other.pcap"
    elif problem == "FIM mark":
        manifest["defense"]["fim_marks"][0]["archived"] = False
    else:
        script.write_bytes(SCRIPT + b"\n")
    if problem != "script":
        _rewrite(root, "manifest.json", _json_bytes(manifest))

    with pytest.raises(retained_secret_gate.CandidateSecretError):
        _certify(repository, root, script)


def test_refuses_a_candidate_from_another_source_head(tmp_path):
    repository, root, script = _write_candidate(tmp_path)

    with pytest.raises(retained_secret_gate.CandidateSecretError, match="source head"):
        retained_secret_gate.certify(repository, root, _spec_for(script), script, "2" * 40)


@pytest.mark.parametrize("run_id", ["not-a-production-run", "20260229T010203Z-abc123"])
def test_refuses_a_marker_path_derived_from_a_nonproduction_run_id(tmp_path, run_id):
    repository, root, script = _write_candidate(tmp_path)
    manifest_path = root / "files/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    original = manifest["run_id"]
    manifest["run_id"] = run_id
    _rewrite(root, "manifest.json", _json_bytes(manifest))
    for kind in ("archives", "alerts"):
        run_path = f"raw/hosts/manager/var/ossec/logs/{kind}/{kind}.json"
        path = root / "files" / run_path
        _rewrite(root, run_path, path.read_bytes().replace(original.encode(), run_id.encode()))
    proof_path = root / "provenance.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    proof["run"]["id"] = run_id
    proof_path.write_bytes(_json_bytes(proof))

    with pytest.raises(
        retained_secret_gate.CandidateSecretError,
        match="no production range run id",
    ) as caught:
        _certify(repository, root, script)
    assert run_id not in str(caught.value)


@pytest.mark.parametrize(
    "problem",
    ["missing hash", "wrong hash", "sibling copy", "full log copy", "mirror mismatch", "extra event"],
)
def test_refuses_unproved_or_unpaired_fim_fingerprints(tmp_path, problem):
    repository, root, script = _write_candidate(tmp_path)
    run_path = "raw/hosts/manager/var/ossec/logs/archives/archives.json"
    path = root / "files" / run_path
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    target = next(record for record in records if record["syscheck"]["event"] == "added")
    if problem == "missing hash":
        target["syscheck"].pop("md5_after")
    elif problem == "wrong hash":
        target["syscheck"]["md5_after"] = "0" * 32
    elif problem == "sibling copy":
        target["digest_backup"] = HASHES["md5"]
    elif problem == "full log copy":
        target["full_log"] += f"backup {HASHES['md5']}\n"
    elif problem == "mirror mismatch":
        target["timestamp"] = "2026-11-27T02:00:00.000+0000"
    else:
        records.append(json.loads(json.dumps(target)))
    _rewrite(root, run_path, _ndjson(records))

    with pytest.raises(retained_secret_gate.CandidateSecretError):
        _certify(repository, root, script)


def test_refuses_a_recursive_duplicate_key_before_any_fingerprint_allowance(tmp_path):
    repository, root, script = _write_candidate(tmp_path)
    run_path = "raw/hosts/manager/var/ossec/logs/archives/archives.json"
    path = root / "files" / run_path
    data = path.read_bytes().replace(b'"mode": "realtime"', b'"mode": "realtime", "mode": "realtime"', 1)
    _rewrite(root, run_path, data)

    with pytest.raises(retained_secret_gate.CandidateSecretError, match="duplicate JSON key"):
        _certify(repository, root, script)


@pytest.mark.parametrize("problem", ["duplicate manifest key", "unknown provenance key"])
def test_workflow_verifier_never_prints_a_candidate_controlled_json_key(tmp_path, problem):
    _, root, _ = _write_candidate(tmp_path)
    candidate_key = "".join(("private-", "candidate-", "field"))
    if problem == "duplicate manifest key":
        path = root / "files/manifest.json"
        data = path.read_bytes().replace(
            b'{\n  "range":',
            ('{\n  "' + candidate_key + '": 1,\n  "' + candidate_key + '": 2,\n  "range":').encode(),
            1,
        )
        _rewrite(root, "manifest.json", data)
    else:
        path = root / "provenance.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document[candidate_key] = "not public"
        path.write_bytes(_json_bytes(document))

    with pytest.raises(retained_secret_gate.CandidateSecretError) as caught:
        retained_secret_gate.verify_candidate(root)
    assert str(caught.value) == "the retained candidate failed its exact verifier"
    assert candidate_key not in str(caught.value)


def test_occurrence_refusal_never_prints_a_candidate_controlled_key_or_fingerprint(tmp_path):
    repository, root, script = _write_candidate(tmp_path)
    run_path = "raw/hosts/manager/var/ossec/logs/archives/archives.json"
    path = root / "files" / run_path
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    target = next(record for record in records if record["syscheck"]["path"] == "/tmp/atomic.sh")
    sensitive_key = "candidate-private-" + HASHES["md5"]
    target[sensitive_key] = "neighbor"
    _rewrite(root, run_path, _ndjson(records))

    with pytest.raises(retained_secret_gate.CandidateSecretError) as caught:
        _certify(repository, root, script)
    assert sensitive_key not in str(caught.value)
    assert HASHES["md5"] not in str(caught.value)


def test_reports_only_a_values_free_path_class_when_the_expected_fim_source_is_absent(tmp_path):
    repository, root, script = _write_candidate(tmp_path)
    run_path = "raw/hosts/manager/var/ossec/logs/archives/archives.json"
    path = root / "files" / run_path
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for record in records:
        record["syscheck"]["path"] = "/tmp/private-looking-name"
    _rewrite(root, run_path, _ndjson(records))

    with pytest.raises(retained_secret_gate.CandidateSecretError) as caught:
        _certify(repository, root, script)
    assert "tmp-other" in str(caught.value)
    assert "private-looking-name" not in str(caught.value)


def test_private_baseline_keeps_only_actual_certified_findings_and_never_changes_candidate(
    tmp_path, monkeypatch
):
    repository, root, script = _write_candidate(tmp_path)
    _, certifications, _ = _certify(repository, root, script)
    certified = certifications[0]
    finding = {
        "type": retained_secret_gate.FINDING_TYPE,
        "filename": certified.filename,
        "hashed_secret": certified.secret_hash,
        "is_verified": False,
        "line_number": min(certified.lines),
    }
    hook = _fake_hook(tmp_path, {certified.filename: [finding]}, monkeypatch)
    out = tmp_path / "candidate-baseline.json"
    before = _tree_hashes(root)

    count = retained_secret_gate.prepare_baseline(
        repository,
        root,
        _spec_for(script),
        script,
        SOURCE_HEAD,
        _baseline_for(script),
        hook,
        out,
    )

    generated = json.loads(out.read_text(encoding="utf-8"))
    tracked = json.loads(_baseline_for(script).read_text(encoding="utf-8"))
    assert count == 1
    assert generated["version"] == tracked["version"]
    assert generated["plugins_used"] == tracked["plugins_used"]
    assert generated["filters_used"] == tracked["filters_used"]
    assert generated["results"] == {certified.filename: [finding]}
    assert _tree_hashes(root) == before


def test_refuses_a_scanner_finding_that_is_not_an_independently_certified_fingerprint(tmp_path, monkeypatch):
    repository, root, script = _write_candidate(tmp_path)
    token = "".join(
        ("9e17c4a6", "2b8f31d0", "597ac46e", "28f13b7d", "40c59a28", "e6f1b35d", "7a29c48e", "15b73d60")
    )
    manifest_path = root / "files/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["neighbor_secret"] = token
    _rewrite(root, "manifest.json", _json_bytes(manifest))
    _, certifications, _ = _certify(repository, root, script)
    certified = certifications[0]
    planted_line = next(
        number
        for number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), start=1)
        if token in line
    )
    finding = {
        "type": retained_secret_gate.FINDING_TYPE,
        "filename": certified.filename,
        "hashed_secret": hashlib.sha1(token.encode()).hexdigest(),
        "is_verified": False,
        "line_number": planted_line,
    }
    hook = _fake_hook(tmp_path, {certified.filename: [finding]}, monkeypatch)
    out = tmp_path / "candidate-baseline.json"

    with pytest.raises(retained_secret_gate.CandidateSecretError, match="outside a certified fingerprint"):
        retained_secret_gate.prepare_baseline(
            repository,
            root,
            _spec_for(script),
            script,
            SOURCE_HEAD,
            _baseline_for(script),
            hook,
            out,
        )
    assert not out.exists()
