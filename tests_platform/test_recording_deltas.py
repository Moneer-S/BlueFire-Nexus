from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Iterator

import pytest

from bluefire import cli, recording_deltas, recordings
from bluefire.api import generate_browser_bootstrap_capability
from bluefire.application_errors import APIError
from bluefire.service import BlueFireService
from tests_platform.test_api import json_body, request, running_server
from tests_platform.test_recordings import SHIPPED, small_recording

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path: Path) -> Iterator[BlueFireService]:
    instance = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    try:
        yield instance
    finally:
        instance.close()


def lab_file(recording: dict[str, Any]) -> bytes:
    """A recording file as the lab writes it: indented, not canonical."""

    return (json.dumps(recording, indent=1) + "\n").encode("utf-8")


def sent(payload: bytes) -> dict[str, str]:
    return {"recording_file": base64.b64encode(payload).decode("ascii")}


def outcomes(happened: str, recorded: str, outcome: str) -> dict[str, str]:
    return {
        "happened": happened,
        "recorded": recorded,
        "outcome": outcome,
        "outcome_with_lab_rules": outcome,
    }


def small_delta(before: bytes, after: bytes) -> dict[str, Any]:
    """A delta in the shape bluefire-lab compare writes, of two small recordings: a declared
    change of a sensor's settings, one step better and one the same."""

    def side(payload: bytes) -> dict[str, Any]:
        recording = json.loads(payload)
        source = recording["source"]
        return {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "id": recording["id"],
            **{key: source[key] for key in ("run_url", "environment", "commit", "started")
               if key in source},
        }  # fmt: skip

    same = outcomes("took effect", "recorded", "alerted")
    price = "price: published rules that alerted on ordinary activity: not recorded before, not recorded after"  # noqa: E501
    return {
        "schema": "bluefire.delta/1",
        "claim": "one pair of runs",
        "before": side(before),
        "after": side(after),
        "declared_change": "sensors:sysmon",
        "comparable": True,
        "refused_because": [],
        "differences": [{"what": "sensors:sysmon", "before": "a" * 64, "after": "b" * 64}],
        "same_in_both": ["atomic_commit"],
        "lab_code": {"before": "c" * 40, "after": "c" * 40, "same": True},
        "judged": ["recorded", "outcome", "outcome_with_lab_rules"],
        "control": {"fields": ["happened"], "same": 2, "of": 2, "varied": []},
        "counts": {"paired": 2, "same": 1, "better": 1, "worse": 0, "changed": 0,
                   "not attributable": 0, "without cause": 0, "no verdict": 0, "new": 0,
                   "gone": 0},
        "unexplained": [],
        "steps": [
            {"id": "1", "role": "test", "title": "Clear Bash history (rm)", "technique": "T1070.003",
             "paired_by": "id", "before": same, "after": same, "changed": [], "underneath": [],
             "result": "same", "verdict": "no change"},
            {"id": "2", "role": "test", "title": "List running processes", "technique": "T1057",
             "paired_by": "id", "before": outcomes("took effect", "no telemetry", "unseen"),
             "after": outcomes("took effect", "recorded", "seen"),
             "changed": ["recorded", "outcome", "outcome_with_lab_rules"],
             "underneath": ["recorded now: 1 event"], "result": "better",
             "verdict": "better: no telemetry to recorded by the sensors; unseen to seen by the "
                        f"published rules; {price}; one pair of runs",
             "price": price,
             "procedures": {"better": 1, "of": 1}},
        ],
        "new": [],
        "gone": [],
        "race": {"why": "the rules ran after each run, so there is no race to compare"},
    }  # fmt: skip


def kept_pair(service: BlueFireService) -> tuple[bytes, bytes]:
    """Two finished recordings imported as the lab's files."""

    before, after = lab_file(small_recording("rec-before")), lab_file(small_recording("rec-after"))
    service.import_recording(sent(before))
    service.import_recording(sent(after))
    return before, after


def refused(service: BlueFireService, delta: Any) -> list[str]:
    """The problems of a refused import; nothing is stored."""

    with pytest.raises(APIError) as refusal:
        service.import_recording_delta({"delta": delta})
    assert refusal.value.status == 422
    assert refusal.value.code == "delta_invalid"
    assert refusal.value.message.startswith("The comparison was not imported: ")
    assert service.recording_deltas()["deltas"] == []
    assert isinstance(refusal.value.details, dict)
    return list(refusal.value.details["problems"])


def test_a_recording_file_is_kept_as_it_was_sent(service: BlueFireService) -> None:
    payload = lab_file(small_recording())

    first = service.import_recording(sent(payload))
    again = service.import_recording(sent(payload))
    digest, summary = service.recording_library.kept_file("rec-small")
    with pytest.raises(APIError) as not_base64:
        service.import_recording({"recording_file": "not base64!"})
    with pytest.raises(APIError) as reserved:
        service.import_recording(sent(lab_file(small_recording("deltas"))))

    assert first["created"] is True and again["created"] is False
    assert digest == hashlib.sha256(payload).hexdigest()
    assert summary["id"] == "rec-small"
    assert service.recording("rec-small")["recording"] == small_recording()
    assert not_base64.value.status == 422
    assert not_base64.value.details == {"problems": ["recording_file is not base64."]}
    assert reserved.value.status == 422
    assert "address of the comparisons" in reserved.value.message
    # The shipped recording's file is the packaged one.
    shipped_id = json.loads(SHIPPED.read_bytes())["id"]
    assert (
        service.recording_library.kept_file(shipped_id)[0]
        == hashlib.sha256(SHIPPED.read_bytes()).hexdigest()
    )


def test_a_delta_is_refused_for_each_reason_with_a_plain_one(service: BlueFireService) -> None:
    before, after = kept_pair(service)
    good = small_delta(before, after)

    wrong_schema = refused(service, {**good, "schema": "bluefire.delta/2"})
    shape = copy.deepcopy(good)
    shape["comparable"] = True
    shape["refused_because"] = ["the before recording has no source.setup"]
    shape["steps"][1]["result"] = "much better"
    shape["steps"][1]["after"]["recorded"] = "yes"
    del shape["race"]
    shape_problems = refused(service, shape)

    missing = copy.deepcopy(good)
    missing["after"]["id"] = "rec-none"
    missing_problems = refused(service, missing)

    other_file = copy.deepcopy(good)
    other_file["before"]["sha256"] = "0" * 64
    other_file_problems = refused(service, other_file)

    as_object = small_recording("rec-object")
    service.import_recording({"recording": as_object})
    canonical = copy.deepcopy(good)
    canonical["before"].update(
        id="rec-object", sha256=hashlib.sha256(lab_file(as_object)).hexdigest()
    )
    canonical_problems = refused(service, canonical)

    running = small_recording("rec-running")
    del running["source"]["finished"]
    running_file = lab_file(running)
    service.import_recording(sent(running_file))
    still_running = copy.deepcopy(good)
    still_running["after"].update(id="rec-running", sha256=hashlib.sha256(running_file).hexdigest())
    running_problems = refused(service, still_running)

    unknown_step = copy.deepcopy(good)
    unknown_step["steps"][1]["id"] = "9"
    unknown_step["control"]["varied"] = ["8"]
    unknown_step_problems = refused(service, unknown_step)

    assert wrong_schema == ["schema must be 'bluefire.delta/1'."]
    assert shape_problems == [
        "race is missing.",
        "comparable must be true exactly when refused_because is empty.",
        "steps[1].after.recorded must be one of: recorded, no telemetry, not known.",
        "steps[1].result must be one of: same, better, worse, changed, not attributable, "
        "without cause, no verdict.",
        "race must be an object.",
    ]
    assert missing_problems == ["the after recording 'rec-none' is not kept here: import it first."]
    assert len(other_file_problems) == 1
    assert other_file_problems[0].startswith(
        "the before recording 'rec-before' is kept here from another file than the one this "
        "comparison was made from (imported earlier): the kept file's SHA-256 is "
        f"{hashlib.sha256(before).hexdigest()}"
    )
    # The refusal names a way out that exists: a kept finished recording is never replaced.
    assert other_file_problems[0].endswith("cannot be imported while that id holds the other file.")
    # A recording imported as an object is kept as canonical JSON, not as the lab's file.
    assert canonical_problems[0].startswith(
        "the before recording 'rec-object' is kept here from another file"
    )
    assert running_problems == [
        "the after recording 'rec-running' is still running; a comparison is made of two "
        "finished runs."
    ]
    assert unknown_step_problems == [
        "steps[1].id names step '9', which the after recording does not have.",
        "steps[1] names step '9', which the before recording does not have.",
        "control.varied[0] names step '8', which the after recording does not have.",
    ]


def test_a_delta_that_disagrees_with_itself_is_refused(service: BlueFireService) -> None:
    before, after = kept_pair(service)
    good = small_delta(before, after)

    def changed(edit: Any) -> list[str]:
        delta = copy.deepcopy(good)
        edit(delta)
        return refused(service, delta)

    def no_price(delta: dict[str, Any]) -> None:
        del delta["steps"][1]["price"]

    def price_not_said(delta: dict[str, Any]) -> None:
        delta["steps"][1]["verdict"] = "better: unseen to seen; one pair of runs"

    def refused_but_better(delta: dict[str, Any]) -> None:
        delta.update(comparable=False, refused_because=["the kinds differ"])

    def declared_not_differing(delta: dict[str, Any]) -> None:
        delta["declared_change"] = "sensors:auditd"

    def miscounted(delta: dict[str, Any]) -> None:
        delta["counts"]["better"] = 40

    def better_with_nothing_moved(delta: dict[str, Any]) -> None:
        delta["steps"][1]["after"] = copy.deepcopy(delta["steps"][1]["before"])

    def empty_race(delta: dict[str, Any]) -> None:
        delta["race"] = {}

    def other_claim(delta: dict[str, Any]) -> None:
        delta["claim"] = "two pairs of runs"

    def nested(delta: dict[str, Any]) -> None:
        deep: dict[str, Any] = {}
        delta["race"] = {"before": deep, "after": {}}
        for _ in range(12):
            deep["more"] = {}
            deep = deep["more"]

    assert changed(no_price) == ["steps[1].price is missing."]
    assert changed(price_not_said) == ["steps[1].verdict must hold the step's price."]
    assert changed(refused_but_better) == [
        "steps[1].result must be same or no verdict: the comparison is refused."
    ]
    assert changed(declared_not_differing) == [
        "declared_change must be one of the differences when there is a verdict."
    ]
    assert changed(miscounted) == ["counts.better is 40, but the delta lists 1."]
    assert changed(better_with_nothing_moved) == [
        "steps[1].changed must name exactly the fields whose values differ.",
        "steps[1].result must be same exactly when no field differs.",
    ]
    assert changed(empty_race) == [
        "race.before must be an object.",
        "race.after must be an object.",
    ]
    assert changed(other_claim) == ["delta.claim must be one of: one pair of runs."]
    assert changed(nested) == ["A delta nests objects and lists at most 8 deep."]


def test_a_delta_must_copy_its_recordings_source_facts(service: BlueFireService) -> None:
    before, after = kept_pair(service)
    delta = small_delta(before, after)
    delta["before"]["run_url"] = "https://github.com/someone-else/other-repo/actions/runs/1"
    delta["after"]["started"] = "2020-01-01T00:00:00Z"

    assert refused(service, delta) == [
        "before.run_url is not the run_url of the before recording's source.",
        "after.started is not the started of the after recording's source.",
    ]


def test_a_delta_is_not_served_once_its_recording_is_another_file(
    service: BlueFireService,
) -> None:
    before, after = kept_pair(service)
    delta = small_delta(before, after)
    identifier = service.import_recording_delta({"delta": delta})["summary"]["id"]
    # A later release, or a hand edit, keeps another file under the same id.
    changed = small_recording("rec-after")
    changed["title"] = "Another run"
    (service.recording_library.root / "rec-after.json").write_bytes(lab_file(changed))

    listed = service.recording_deltas()
    with pytest.raises(APIError) as replaced:
        service.recording_delta(identifier)

    assert listed["deltas"] == [] and listed["unreadable_count"] == 1
    assert replaced.value.status == 409 and replaced.value.code == "delta_recording_replaced"


def test_a_delta_is_imported_listed_and_returned_whole(service: BlueFireService) -> None:
    before, after = kept_pair(service)
    delta = small_delta(before, after)

    imported = service.import_recording_delta({"delta": delta})
    again = service.import_recording_delta({"delta": copy.deepcopy(delta)})
    listed = service.recording_deltas()
    [entry] = listed["deltas"]
    detail = service.recording_delta(entry["id"])

    assert imported["created"] is True and again["created"] is False
    assert imported["summary"] == entry
    assert entry["id"] == recording_deltas.delta_id(delta)
    assert entry["declared_change"] == "sensors:sysmon"
    assert entry["comparable"] is True and entry["refused_because"] == []
    assert entry["counts"]["better"] == 1
    assert entry["before"] == delta["before"] and entry["after"] == delta["after"]
    # Its recordings were imported, so the pair is labelled as imported, by its weaker side.
    assert entry["origin"] == {"kind": "imported", "note": recording_deltas.IMPORTED_DELTA_NOTE}
    assert entry["recordings"]["before"]["id"] == "rec-before"
    assert entry["recordings"]["after"]["origin"]["kind"] == "imported"
    assert detail["schema_version"] == "bluefire.delta-entry.v1"
    assert detail["summary"] == entry
    assert detail["delta"] == delta
    assert listed["unreadable_count"] == 0 and listed["omitted_count"] == 0
    with pytest.raises(APIError) as missing:
        service.recording_delta("0000000000000001")
    with pytest.raises(APIError) as invalid:
        service.recording_delta("../recordings")
    assert missing.value.status == 404 and missing.value.code == "delta_not_found"
    assert invalid.value.status == 400 and invalid.value.code == "invalid_delta_id"


def test_a_shipped_delta_is_read_from_the_package_folder(
    service: BlueFireService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shipped_bytes = SHIPPED.read_bytes()
    shipped = json.loads(shipped_bytes)
    folder = tmp_path / "shipped-deltas"
    folder.mkdir()
    delta = small_delta(shipped_bytes, shipped_bytes)
    delta["steps"] = []
    delta["counts"].update(paired=0, same=0, better=0)
    delta["control"].update(same=0, of=0)
    (folder / "pair.json").write_text(json.dumps(delta, indent=1), encoding="utf-8")
    monkeypatch.setattr(recording_deltas, "_shipped_folder", lambda: folder)
    library = recording_deltas.DeltaLibrary(service.recording_library)

    [entry] = library.list()["deltas"]

    assert entry["before"]["id"] == shipped["id"] == entry["after"]["id"]
    assert entry["origin"] == {"kind": "shipped", "note": recording_deltas.SHIPPED_DELTA_NOTE}
    assert library.detail(entry["id"])["delta"] == delta
    # Imported again, the shipped delta is not stored twice.
    assert library.import_delta({"delta": delta})["created"] is False
    assert not (service.recording_library.root / "deltas").exists()


def test_a_delta_import_waits_for_the_store_lock(
    service: BlueFireService, monkeypatch: pytest.MonkeyPatch
) -> None:
    before, after = kept_pair(service)
    other = recordings.RecordingLibrary(service.recording_library.root)
    holding, release = threading.Event(), threading.Event()

    def hold() -> None:
        with other.import_lock():
            holding.set()
            release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    assert holding.wait(5)
    monkeypatch.setattr(recordings, "_LOCK_SECONDS", 0.2)
    try:
        with pytest.raises(APIError) as busy:
            service.import_recording_delta({"delta": small_delta(before, after)})
    finally:
        release.set()
        holder.join(10)
    imported = service.import_recording_delta({"delta": small_delta(before, after)})

    assert busy.value.status == 503 and busy.value.code == "recordings_busy"
    assert imported["created"] is True


def test_deltas_are_imported_and_read_through_the_http_server(service: BlueFireService) -> None:
    before, after = kept_pair(service)
    delta = small_delta(before, after)
    capability = generate_browser_bootstrap_capability()
    with running_server(
        service,  # type: ignore[arg-type]
        max_request_body=1024,
        bootstrap_capability=capability,
    ) as (server, _):
        created = request(server, "POST", "/api/v1/recordings/deltas", body={"delta": delta})
        listed = request(server, "GET", "/api/v1/recordings/deltas")
        identifier = recording_deltas.delta_id(delta)
        detail = request(server, "GET", f"/api/v1/recordings/deltas/{identifier}")
        invalid = request(server, "GET", "/api/v1/recordings/deltas/not-an-id")
        missing = request(server, "GET", "/api/v1/recordings/deltas/0000000000000001")
        refused_post = request(
            server, "POST", "/api/v1/recordings/deltas", body={"delta": {"schema": "other"}}
        )
        file_import = request(
            server, "POST", "/api/v1/recordings", body=sent(lab_file(small_recording("rec-sent")))
        )

    assert created[0] == 201, created[2]
    assert json_body(created[2])["created"] is True
    assert [item["id"] for item in json_body(listed[2])["deltas"]] == [identifier]
    assert json_body(detail[2])["delta"] == delta
    assert invalid[0] == 400 and json_body(invalid[2])["error"]["code"] == "invalid_delta_id"
    assert missing[0] == 404
    assert refused_post[0] == 422
    assert json_body(refused_post[2])["error"]["message"] == (
        "The comparison was not imported: schema must be 'bluefire.delta/1'."
    )
    # The deltas route is read as large as a recording's, as the recording import route is.
    assert file_import[0] == 201, file_import[2]


def test_the_command_line_imports_a_delta_file(
    service: BlueFireService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    before, after = lab_file(small_recording("rec-before")), lab_file(small_recording("rec-after"))
    (tmp_path / "before.json").write_bytes(before)
    (tmp_path / "after.json").write_bytes(after)
    (tmp_path / "delta.json").write_text(json.dumps(small_delta(before, after), indent=1))

    first = cli.main(["recordings", "import-delta", str(tmp_path / "delta.json")])
    first_output = json.loads(capsys.readouterr().out)
    cli.main(["recordings", "import", str(tmp_path / "before.json")])
    cli.main(["recordings", "import", str(tmp_path / "after.json")])
    capsys.readouterr()
    imported = cli.main(["recordings", "import-delta", str(tmp_path / "delta.json")])
    imported_output = json.loads(capsys.readouterr().out)

    assert first == 2
    assert first_output["error"]["code"] == "delta_invalid"
    assert "the before recording 'rec-before' is not kept here" in first_output["error"]["message"]
    assert imported == 0 and imported_output["created"] is True
    assert imported_output["summary"]["recordings"]["after"]["id"] == "rec-after"
