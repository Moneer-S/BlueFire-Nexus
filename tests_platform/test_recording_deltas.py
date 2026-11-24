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


def imported_entries(listed: Any) -> list[dict[str, Any]]:
    """The entries of a delta list that were imported, leaving out the pair shipped with the app."""

    return [entry for entry in listed["deltas"] if entry["origin"]["kind"] != "shipped"]


def refused(service: BlueFireService, delta: Any) -> list[str]:
    """The problems of a refused import; nothing is stored."""

    with pytest.raises(APIError) as refusal:
        service.import_recording_delta({"delta": delta})
    assert refusal.value.status == 422
    assert refusal.value.code == "delta_invalid"
    assert refusal.value.message.startswith("The comparison was not imported: ")
    assert imported_entries(service.recording_deltas()) == []
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
    # The refusal names the ways that exist: a kept finished recording is never replaced, and
    # another file of its id is kept only with the same source.
    assert other_file_problems[0].endswith(
        "never replaced, and another file of its id is kept beside it only with the same "
        "source: another evaluation of the same run, or the same recording in other bytes."
    )
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
        "declared_change must be one of the differences when there is a verdict.",
        "differences[0] (sensors:sysmon) differs and is neither the declared change nor named by "
        "a limit, so there can be no verdict.",
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
    assert changed(other_claim) == [
        "delta.claim must be one of: one pair of runs, one run evaluated with two rule sets."
    ]
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

    assert imported_entries(listed) == [] and listed["unreadable_count"] == 1
    assert replaced.value.status == 409 and replaced.value.code == "delta_recording_replaced"


def test_a_delta_is_imported_listed_and_returned_whole(service: BlueFireService) -> None:
    before, after = kept_pair(service)
    delta = small_delta(before, after)

    imported = service.import_recording_delta({"delta": delta})
    again = service.import_recording_delta({"delta": copy.deepcopy(delta)})
    listed = service.recording_deltas()
    [entry] = imported_entries(listed)
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
    assert [item["id"] for item in imported_entries(json_body(listed[2]))] == [identifier]
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


PAIR_DELTA = ROOT / "bluefire" / "data" / "recordings" / "deltas" / "lab-pair-history-watch.json"
PAIR_RUN = "https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45365902367"


def test_the_shipped_pair_is_listed_and_returned_whole_as_the_lab_made_it(
    service: BlueFireService,
) -> None:
    delta = json.loads(PAIR_DELTA.read_bytes())

    [entry] = [
        item for item in service.recording_deltas()["deltas"] if item["origin"].get("run_url") == PAIR_RUN
    ]
    detail = service.recording_delta(entry["id"])

    assert entry["id"] == recording_deltas.delta_id(delta)
    # Two runs side by side in one CI run, which made both recordings and this comparison.
    assert entry["origin"] == {
        "kind": "shipped",
        "run_url": PAIR_RUN,
        "note": recording_deltas.SHIPPED_PAIR_NOTE.format(run_url=PAIR_RUN),
    }
    assert entry["runners"] == 2 and entry["limit"] is None and entry["comparable"] is True
    assert entry["declared_change"] == "sensors:auditd"
    assert entry["counts"]["better"] == 1 and entry["counts"]["same"] == 90
    for side in ("before", "after"):
        assert entry["recordings"][side]["origin"]["kind"] == "shipped"
        assert entry["recordings"][side]["origin"]["run_url"] == PAIR_RUN
        assert service.recording_library.kept_file(delta[side]["id"])[0] == delta[side]["sha256"]
    assert detail["delta"] == delta


# What the audit rules of the two runs of a built pair watch, in the fixed form the lab's
# recordings write (audit_watches): the before run starts programs only, the after run also
# watches the test account's history file under the key shell-history.
STARTS = "-a always,exit -F auid!=unset -S execve"
HISTORY = "-a always,exit -F path=/home/bluefire-lab/.bash_history -F perm=aw"
WATCHES = {"before": {"": [STARTS]}, "after": {"": [STARTS], "shell-history": [HISTORY]}}


def with_auditd(recording: dict[str, Any], watches: dict[str, list[str]] | None) -> dict[str, Any]:
    """A built recording with the sensor auditd, saying what its rules watch when watches is given,
    as the lab's recordings say it; None leaves it unsaid, as a recording written before it was."""

    recording["network"]["sensors"].append(
        {
            "id": "auditd",
            "name": "auditd 3.1.2",
            "host": "target",
            "records": "program starts and file changes",
            **({"audit_watches": watches} if watches is not None else {}),
        }
    )
    return recording


def limited_delta(before: bytes, after: bytes) -> dict[str, Any]:
    """A built limited verdict, in the shape bluefire-lab compare writes today for two runners that
    differed: one step better by the change's own mark, its price not known, its key able to carry
    the mark. Made here, not by a run of the lab."""

    delta = small_delta(before, after)
    price = (
        "price not known: each run counted its ordinary activity on its own runner, and the two "
        "runners differed, so what differs between the counts is not the change's price (each "
        "run's own, published rules that alerted on ordinary activity: not recorded before, not "
        "recorded after)"
    )
    delta.update(
        declared_change="sensors:auditd",
        runners=2,
        limit={
            "why": "the two runners differed",
            "differences": ["images:target", "kernels:target"],
            "credits": "only a step that carries the change's own mark: every event the "
            "recordings hold of it is of an audit key whose every rule in that run watches a path "
            "that no rule of the other run, as written, could have recorded (none there watches "
            "that path, any other path the event names, a folder above one or a path under one, "
            "and none without a path records the same kind of event, a program start being one "
            "kind and a read, a write or a change of attributes the other; paths are compared as "
            "written, so a second name that a link gives a file is not found out), and the other "
            "run holds nothing of it",
            "credited": 1,
            "not_attributable": 0,
        },
        differences=[
            {"what": "images:target", "before": "ubuntu24 1", "after": "ubuntu24 2"},
            {"what": "kernels:target", "before": "7.0.0-1017-azure", "after": "7.0.0-1014-aws"},
            {"what": "sensors:auditd", "before": "a" * 64, "after": "b" * 64, "declared": True},
        ],
        audit_keys={
            "only_before": {},
            "only_after": {"shell-history": {"events": 1, "steps": ["2"], "mark": True}},
        },
    )
    delta["counts"]["by_mark"] = 1
    step = delta["steps"][1]
    step.update(
        records={
            "sensor": "auditd",
            "new": {"count": 1, "lines": ["openat: /home/bluefire-lab/.bash_history"]},
            "gone": {"count": 0, "lines": []},
        },
        mark={"run": "after", "keys": ["shell-history"], "events": 1},
        verdict="better by the change's own mark, on two runners that differed: no telemetry to "
        f"recorded by the sensors; {price}; it rests on 1 event of the audit key `shell-history`, "
        "whose every rule in the after run watches a path that no rule of the before run, as "
        "written, could have recorded, the only events either run holds of the step, on two "
        "runners that differed (the image of host `target`, the kernel of host `target`); one "
        "pair of runs",
        price=price,
    )
    return delta


def in_one_run(
    service: BlueFireService, prefix: str, said: bool = True
) -> tuple[bytes, bytes]:
    """Two built recordings of one CI run, kept here: the before and the after run of a pair, whose
    auditd says what its rules watch unless said is false."""

    payloads = []
    for side in ("before", "after"):
        recording = with_auditd(small_recording(f"{prefix}-{side}"), WATCHES[side] if said else None)
        recording["source"]["run_url"] = "https://github.com/example/lab/actions/runs/3"
        payload = lab_file(recording)
        service.import_recording(sent(payload))
        payloads.append(payload)
    return payloads[0], payloads[1]


def test_a_limited_verdict_is_kept_and_refused_when_its_limit_marks_and_counts_disagree(
    service: BlueFireService,
) -> None:
    good = limited_delta(*in_one_run(service, "rec"))

    def changed(edit: Any) -> list[str]:
        delta = copy.deepcopy(good)
        edit(delta)
        return refused(service, delta)

    def mark_without_limit(delta: dict[str, Any]) -> None:
        delta.update(limit=None, differences=delta["differences"][2:])

    def miscounted_marks(delta: dict[str, Any]) -> None:
        delta["counts"]["by_mark"] = 0

    def credited_without_mark(delta: dict[str, Any]) -> None:
        del delta["steps"][1]["mark"]
        delta["counts"]["by_mark"] = 0
        delta["limit"]["credited"] = 0

    def price_as_a_difference(delta: dict[str, Any]) -> None:
        step = delta["steps"][1]
        step["price"] = "price: ordinary events: 8964 before, 8804 after"
        step["verdict"] += f"; {step['price']}"

    def limit_on_one_run(delta: dict[str, Any]) -> None:
        delta["runners"] = None

    def two_ci_runs(delta: dict[str, Any]) -> None:
        delta["after"]["run_url"] = "https://github.com/example/lab/actions/runs/4"

    def limit_names_what_did_not_differ(delta: dict[str, Any]) -> None:
        delta["limit"]["differences"] = ["images:target", "kernels:target", "kernels:other"]

    def limit_names_no_runner(delta: dict[str, Any]) -> None:
        delta["differences"].insert(0, {"what": "atomic_commit", "before": "c" * 40, "after": "d" * 40})
        delta["limit"]["differences"] = ["atomic_commit", "images:target", "kernels:target"]

    def unnamed_difference(delta: dict[str, Any]) -> None:
        delta["limit"]["differences"] = ["images:target"]

    def mark_on_the_wrong_run(delta: dict[str, Any]) -> None:
        delta["steps"][1]["mark"]["run"] = "before"

    def verdict_without_the_lead(delta: dict[str, Any]) -> None:
        step = delta["steps"][1]
        step["verdict"] = step["verdict"].replace(" by the change's own mark, on two runners that differed", "")

    def verdict_without_the_key(delta: dict[str, Any]) -> None:
        step = delta["steps"][1]
        step["verdict"] = step["verdict"].replace("`shell-history`", "of its own")

    def key_that_gives_no_mark(delta: dict[str, Any]) -> None:
        delta["audit_keys"]["only_after"]["shell-history"].update(
            mark=False, no_mark="the before run's rule `-a always,exit -F path=/home` watches `/home`"
        )

    def key_that_does_not_say(delta: dict[str, Any]) -> None:
        del delta["audit_keys"]["only_after"]["shell-history"]["mark"]

    def no_mark_without_why(delta: dict[str, Any]) -> None:
        delta["audit_keys"]["only_after"]["shell-history"]["mark"] = False

    def why_beside_a_mark(delta: dict[str, Any]) -> None:
        delta["audit_keys"]["only_after"]["shell-history"]["no_mark"] = "it has no rule"

    def key_of_the_other_run(delta: dict[str, Any]) -> None:
        delta["audit_keys"]["only_before"]["shell-history"] = {
            "events": 1, "steps": ["2"], "mark": True
        }  # fmt: skip

    def key_without_the_step(delta: dict[str, Any]) -> None:
        delta["audit_keys"]["only_after"]["shell-history"]["steps"] = []

    def key_without_events(delta: dict[str, Any]) -> None:
        delta["audit_keys"]["only_after"]["shell-history"]["events"] = 0

    def mark_without_records(delta: dict[str, Any]) -> None:
        del delta["steps"][1]["records"]

    def mark_of_no_events(delta: dict[str, Any]) -> None:
        delta["steps"][1]["mark"]["events"] = 0

    def mark_of_no_keys(delta: dict[str, Any]) -> None:
        delta["steps"][1]["mark"]["keys"] = []

    def no_audit_keys(delta: dict[str, Any]) -> None:
        delta["audit_keys"] = None

    def refused_with_a_limit(delta: dict[str, Any]) -> None:
        delta.update(comparable=False, refused_because=["the lab's code differed"])
        delta["steps"][1].update(result="no verdict", verdict="no verdict: the comparison is refused")
        delta["steps"][1].pop("price")
        delta["counts"].update(better=0)
        delta["counts"]["no verdict"] = 1

    def limit_of_another_change(delta: dict[str, Any]) -> None:
        delta["differences"][2]["what"] = "sensors:sysmon"
        delta["declared_change"] = "sensors:sysmon"
        delta["steps"][1]["records"]["sensor"] = "sysmon"

    def miscredited(delta: dict[str, Any]) -> None:
        delta["limit"].update(credited=2, not_attributable=1)

    def records_of_another_sensor(delta: dict[str, Any]) -> None:
        delta["steps"][1]["records"]["sensor"] = "sysmon"

    def records_on_an_unchanged_step(delta: dict[str, Any]) -> None:
        delta["steps"][0]["records"] = copy.deepcopy(delta["steps"][1]["records"])

    def declared_not_true(delta: dict[str, Any]) -> None:
        delta["differences"][2]["declared"] = False

    def runner_value_the_same(delta: dict[str, Any]) -> None:
        delta["differences"][0]["after"] = delta["differences"][0]["before"]

    def difference_not_text(delta: dict[str, Any]) -> None:
        delta["differences"].append({"what": ["x"], "before": "a", "after": "b"})

    service.import_recording_delta({"delta": copy.deepcopy(good)})
    [entry] = imported_entries(service.recording_deltas())

    assert entry["limit"] == good["limit"] and entry["runners"] == 2
    assert entry["counts"]["by_mark"] == 1
    # A pair whose recordings were imported is labelled as imported, however its runs were made.
    assert entry["origin"] == {"kind": "imported", "note": recording_deltas.IMPORTED_DELTA_NOTE}
    assert service.recording_delta(entry["id"])["delta"] == good

    # The refusals below are each checked against a store that keeps no imported delta.
    (service.recording_library.root / "deltas" / f"{entry['id']}.json").unlink()
    assert changed(mark_without_limit) == [
        "audit_keys.only_after.shell-history.mark is given only under a limit: whether a key can "
        "carry the change's own mark is asked only on two runners that differed.",
        "steps[1].mark is given only under a limit: a step is credited by the change's own mark "
        "only on two runners that differed.",
    ]
    assert "counts.by_mark is 0, but the delta lists 1 steps with a mark." in changed(miscounted_marks)
    assert changed(credited_without_mark) == [
        "steps[1].result is better under a limit without the change's own mark: on two runners "
        "that differed only a step that carries it is credited."
    ]
    assert changed(price_as_a_difference) == [
        "steps[1].price must be 'price not known' under a limit: each run counted its ordinary "
        "activity on a runner of its own."
    ]
    assert changed(limit_on_one_run) == [
        "limit is given only for two runs side by side on two runners (runners 2)."
    ]
    assert changed(two_ci_runs)[0] == (
        "runners is 2 only when both recordings name the same CI run (run_url): two runs side by "
        "side in one CI run."
    )
    assert changed(limit_names_what_did_not_differ) == [
        "limit.differences names 'kernels:other', which is not among the differences."
    ]
    assert changed(limit_names_no_runner) == [
        "limit.differences names 'atomic_commit', which is not a runner's image or kernel."
    ]
    assert changed(unnamed_difference) == [
        "differences[1] (kernels:target) differs and is neither the declared change nor named by "
        "a limit, so there can be no verdict."
    ]
    assert changed(mark_on_the_wrong_run) == [
        "steps[1].mark says the before run carries the mark, so the after side must be no "
        "telemetry and the before side not.",
        "steps[1].mark.keys names 'shell-history', which audit_keys lists among the keys only "
        "the after run's events carry.",
        "steps[1].mark.events must be the number of events the step's records give for the run "
        "that carries the mark.",
    ]
    assert (
        "steps[1].verdict must start with \"better by the change's own mark, on two runners that "
        "differed\": the step is credited by the change's own mark."
    ) in changed(verdict_without_the_lead)
    assert changed(verdict_without_the_key) == [
        "steps[1].verdict must name the audit key 'shell-history' its mark rests on."
    ]
    assert changed(key_that_gives_no_mark) == [
        "steps[1].mark.keys names 'shell-history', which audit_keys says can carry no mark of the "
        "change's own."
    ]
    assert changed(key_that_does_not_say) == ["audit_keys.only_after.shell-history.mark is missing."]
    assert changed(no_mark_without_why) == [
        "audit_keys.only_after.shell-history.no_mark is missing.",
        "steps[1].mark.keys names 'shell-history', which audit_keys says can carry no mark of the "
        "change's own.",
    ]
    assert changed(why_beside_a_mark) == [
        "audit_keys.only_after.shell-history.no_mark is given only when mark is false."
    ]
    assert changed(key_of_the_other_run) == [
        "steps[1].mark.keys names 'shell-history', which audit_keys lists among the keys only "
        "the before run's events carry."
    ]
    assert changed(key_without_the_step) == [
        "steps[1].mark.keys names 'shell-history', whose entry in audit_keys.only_after does not "
        "list the step."
    ]
    assert changed(key_without_events) == [
        "steps[1].mark.events is 1, but audit_keys gives its keys only 0 events in the after run."
    ]
    assert changed(mark_without_records) == [
        "steps[1].records is missing: a step credited by the change's own mark says what the "
        "sensor recorded of it."
    ]
    assert (
        "steps[1].mark.events must be at least 1: a mark is events of the change's own."
        in changed(mark_of_no_events)
    )
    assert "steps[1].mark.keys must name the audit keys of the mark." in changed(mark_of_no_keys)
    assert changed(no_audit_keys) == [
        "steps[1].mark needs audit_keys.only_after, the keys only its run's events carry."
    ]
    assert "limit is given only with a verdict: comparable must be true." in changed(refused_with_a_limit)
    assert (
        "limit is given only for a declared change that leaves a mark of its own: sensors:auditd."
        in changed(limit_of_another_change)
    )
    assert changed(miscredited) == [
        "limit.credited is 2, but the delta lists 1 steps with a mark.",
        "limit.not_attributable is 1, but the delta lists 0 steps not attributable.",
    ]
    assert changed(records_of_another_sensor) == [
        "steps[1].records.sensor must be the sensor of the declared change."
    ]
    assert changed(records_on_an_unchanged_step) == [
        "steps[0].records is given only on a step that changed."
    ]
    assert "differences[2].declared must be true, or left out." in changed(declared_not_true)
    assert changed(runner_value_the_same) == [
        "limit.differences names 'images:target', which is the same in both runs."
    ]
    assert "differences[3].what must be non-empty text." in changed(difference_not_text)


def test_a_limited_verdict_rests_on_what_the_rules_watch_and_not_on_the_lab_s_wording(
    service: BlueFireService,
) -> None:
    good = limited_delta(*in_one_run(service, "rec"))
    unsaid = limited_delta(*in_one_run(service, "old", said=False))

    def imported(delta: dict[str, Any]) -> dict[str, Any]:
        entry: dict[str, Any] = service.import_recording_delta({"delta": delta})["summary"]
        (service.recording_library.root / "deltas" / f"{entry['id']}.json").unlink()
        return entry

    # The lab improves its sentences: the store holds the structure, not the words around it.
    reworded = copy.deepcopy(good)
    reworded["limit"]["credits"] = "only a step that carries the change's own mark, in other words"
    step = reworded["steps"][1]
    step["verdict"] = step["verdict"].replace("whose every rule in the after run", "every rule of which")
    # A key that can carry the mark and whose name the other run's events carry too is not
    # listed in audit_keys; the after recording's rules have it.
    unlisted = copy.deepcopy(good)
    unlisted["audit_keys"]["only_after"] = {}
    # A key not on any rule of its run, and a credited key that is not either.
    no_rule = copy.deepcopy(unlisted)
    no_rule["steps"][1]["mark"]["keys"] = ["history"]
    no_rule["steps"][1]["verdict"] = no_rule["steps"][1]["verdict"].replace("shell-history", "history")
    listed_without_rule = copy.deepcopy(good)
    listed_without_rule["audit_keys"]["only_after"]["home"] = {"events": 2, "steps": ["1"], "mark": True}

    assert imported(reworded)["limit"] == reworded["limit"]
    assert imported(unlisted)["counts"]["by_mark"] == 1
    assert refused(service, no_rule) == [
        "steps[1].mark.keys says the audit key 'history' can carry the change's own mark, but the "
        "after recording's audit rules have no rule under it."
    ]
    assert refused(service, listed_without_rule) == [
        "audit_keys.only_after.home.mark says the audit key 'home' can carry the change's own "
        "mark, but the after recording's audit rules have no rule under it."
    ]
    # Recordings that name no rules a mark could rest on, as those written before they said, give
    # no limited verdict: a key's name alone is no mark.
    assert refused(service, unsaid) == [
        f"the {side} recording does not say what its audit rules watch under each audit key "
        "(audit_watches on its sensor auditd), so no step can carry the change's own mark: a key's "
        "name alone is no mark. The recording is written again from its run's folder by "
        "bluefire-lab recording, or the pair is run again."
        for side in ("before", "after")
    ]


# One run evaluated with two sets of the lab's rules: the real pair of CI run 45395673682.
RULE_FOLDER = ROOT / "bluefire" / "data" / "recordings"
RULE_BASE = RULE_FOLDER / "lab-rule-history-truncated-base.json"
RULE_HEAD = RULE_FOLDER / "lab-rule-history-truncated-head.json"
RULE_DELTA = RULE_FOLDER / "deltas" / "lab-rule-history-truncated.json"
RULE_RUN = "https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682"


def test_the_shipped_run_evaluated_twice_is_listed_and_both_its_files_are_returned(
    service: BlueFireService,
) -> None:
    delta = json.loads(RULE_DELTA.read_bytes())

    [entry] = [item for item in service.recording_deltas()["deltas"] if item["one_run"]]
    detail = service.recording_delta(entry["id"])
    with running_server(service, bootstrap_capability=generate_browser_bootstrap_capability()) as (  # type: ignore[arg-type]
        server,
        _,
    ):
        files = [
            request(server, "GET", f"/api/v1/recordings/{delta[side]['id']}/files/{delta[side]['sha256']}")
            for side in ("before", "after")
        ]
        malformed = request(server, "GET", f"/api/v1/recordings/{delta['after']['id']}/files/abc")
        posted = request(server, "POST", f"/api/v1/recordings/{delta['after']['id']}/files/{'0' * 64}", body={})

    assert entry["id"] == recording_deltas.delta_id(delta) and detail["delta"] == delta
    assert entry["claim"] == "one run evaluated with two rule sets" and entry["runners"] is None
    # The list run once, its telemetry evaluated twice and compared, all in one CI run.
    assert entry["origin"] == {
        "kind": "shipped",
        "run_url": RULE_RUN,
        "note": recording_deltas.SHIPPED_ONE_RUN_NOTE.format(run_url=RULE_RUN),
    }
    assert [row["title"] for row in entry["lab_rules"]] == ["Shell History File Truncated In Place"]
    assert [(step["title"], step["role"], step["result"]) for step in entry["moved"]] == [
        ("Clear Bash history (echo)", "test", "better"),
        ("Clear Bash history (cat dev/null)", "test", "better"),
        ("Clear Bash history (echo)", "variant", "better"),
        ("Clear Bash history (cat dev/null)", "variant", "better"),
    ]
    for side, path, (status, _, body) in zip(("before", "after"), (RULE_BASE, RULE_HEAD), files, strict=True):
        assert status == 200
        whole = json_body(body)
        assert whole["sha256"] == delta[side]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert whole["recording"] == json.loads(path.read_bytes())
        assert entry["recordings"][side]["origin"]["kind"] == "shipped"
    assert malformed[0] == 400 and json_body(malformed[2])["error"]["code"] == "invalid_recording_file"
    assert posted[0] == 405


@pytest.fixture
def unshipped(service: BlueFireService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BlueFireService:
    """The service with nothing shipped, so that the real files of one run are imported."""

    empty = tmp_path / "no-deltas"
    empty.mkdir()
    monkeypatch.setattr(service.recording_library, "_shipped_entries", {})
    monkeypatch.setattr(recording_deltas, "_shipped_folder", lambda: empty)
    return service


def evaluation(service: BlueFireService, recording: dict[str, Any], delta: dict[str, Any]) -> None:
    """Import an altered after recording as another evaluation, and point the delta at it."""

    payload = json.dumps(recording, indent=1).encode("utf-8")
    service.import_recording(sent(payload))
    delta["after"]["sha256"] = hashlib.sha256(payload).hexdigest()


def test_one_run_evaluated_twice_is_imported_with_its_two_files_of_one_id(unshipped: BlueFireService) -> None:
    service = unshipped
    first = service.import_recording(sent(RULE_BASE.read_bytes()))
    second = service.import_recording(sent(RULE_HEAD.read_bytes()))
    delta = json.loads(RULE_DELTA.read_bytes())

    imported = service.import_recording_delta({"delta": delta})

    assert first["another_evaluation"] is False and second["another_evaluation"] is True
    assert imported["created"] is True
    summary = imported["summary"]
    assert summary["one_run"] is True and summary["comparable"] is True
    assert summary["origin"] == {"kind": "imported", "note": recording_deltas.IMPORTED_DELTA_NOTE}
    assert summary["recordings"]["before"]["id"] == summary["recordings"]["after"]["id"] == "b2666c50"
    assert summary["recordings"]["after"]["score"]["alerted_with_lab_rules"] == 19
    assert summary["recordings"]["before"]["score"]["alerted_with_lab_rules"] == 17
    # One run is one entry of the list of recordings, by its first file.
    assert [item["id"] for item in service.recordings()["recordings"]].count("b2666c50") == 1


@pytest.mark.parametrize("object_first", [True, False], ids=["object first", "file first"])
def test_a_delta_naming_the_lab_s_files_is_imported_after_its_recordings_came_as_objects_too(
    unshipped: BlueFireService, object_first: bool
) -> None:
    service = unshipped
    for path in (RULE_BASE, RULE_HEAD):
        as_object = {"recording": json.loads(path.read_bytes())}
        as_file = sent(path.read_bytes())
        for import_request in (as_object, as_file) if object_first else (as_file, as_object):
            answer = service.import_recording(import_request)
            assert service.recording_file("b2666c50", answer["sha256"])["sha256"] == answer["sha256"]

    imported = service.import_recording_delta({"delta": json.loads(RULE_DELTA.read_bytes())})

    assert imported["created"] is True
    # Both lab files and both canonical copies are kept under the run's one id.
    assert len(service.recording_library.kept_files("b2666c50")) == 4
    for path in (RULE_BASE, RULE_HEAD):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest in service.recording_library.kept_files("b2666c50")


def test_a_delta_that_claims_one_run_and_does_not_hold_one_is_refused_with_why(
    unshipped: BlueFireService,
) -> None:
    service = unshipped
    service.import_recording(sent(RULE_BASE.read_bytes()))
    service.import_recording(sent(RULE_HEAD.read_bytes()))
    good = json.loads(RULE_DELTA.read_bytes())
    head = json.loads(RULE_HEAD.read_bytes())
    lead = "one run evaluated twice: "

    def edited(edit: Any) -> list[str]:
        delta = copy.deepcopy(good)
        edit(delta)
        return refused(service, delta)

    def recording_edited(edit: Any) -> list[str]:
        recording, delta = copy.deepcopy(head), copy.deepcopy(good)
        edit(recording)
        evaluation(service, recording, delta)
        return refused(service, delta)

    def a_step_ended_otherwise(recording: dict[str, Any]) -> None:
        step = next(item for item in recording["steps"] if item["id"] == "test:cccb070c")
        step["ended"] = step["started"]

    def an_event_missing(recording: dict[str, Any]) -> None:
        step = next(item for item in recording["steps"] if item["id"] == "test:d2b95631")
        step["visibility"]["kept"] -= 1
        recording["events"] = [event for event in recording["events"] if event["id"] != "29-300"]

    def a_published_alert_on_one_side(recording: dict[str, Any]) -> None:
        recording["alerts"] = [alert for alert in recording["alerts"] if alert["id"] != "alert-2"]

    def other_ordinary_activity(recording: dict[str, Any]) -> None:
        recording["ordinary"]["events"] += 1

    def the_new_rule_not_accepted(recording: dict[str, Any]) -> None:
        [lab] = [item for item in recording["network"]["detectors"] if item["id"] == "lab"]
        [verdict] = [item for item in lab["verdicts"] if item["title"] == "Shell History File Truncated In Place"]
        verdict.update(accepted=False, reason="it matched ordinary activity")

    def an_unchanged_rule_judged_otherwise(recording: dict[str, Any]) -> None:
        [lab] = [item for item in recording["network"]["detectors"] if item["id"] == "lab"]
        [verdict] = [item for item in lab["verdicts"] if item["title"] == "Shell History File Emptied"]
        verdict["reason"] = "another reason"

    def two_ci_runs(delta: dict[str, Any]) -> None:
        delta["after"]["run_url"] = "https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/1"

    def the_claim_of_a_pair(delta: dict[str, Any]) -> None:
        delta["claim"] = "one pair of runs"

    def a_pair_that_claims_one_run(delta: dict[str, Any]) -> None:
        delta["one_run"] = False

    def one_run_left_out(delta: dict[str, Any]) -> None:
        del delta["one_run"]

    def two_runners(delta: dict[str, Any]) -> None:
        delta["runners"] = 2

    def two_ids(delta: dict[str, Any]) -> None:
        delta["after"]["id"] = "f9f91ac9"

    def no_rule_listed(delta: dict[str, Any]) -> None:
        delta["lab_rules"] = []

    def a_rule_said_to_be_there_before(delta: dict[str, Any]) -> None:
        delta["lab_rules"][0].update(change="changed", before={"accepted": True, "reason": "x"})

    def a_same_step_said_alerted(delta: dict[str, Any]) -> None:
        step = next(item for item in delta["steps"] if item["id"] == "test:cccb070c")
        step["before"]["outcome_with_lab_rules"] = step["after"]["outcome_with_lab_rules"] = "alerted"

    def the_rules_commit_of_another(delta: dict[str, Any]) -> None:
        delta["before"]["lab_rules_commit"] = delta["after"]["lab_rules_commit"]

    assert recording_edited(a_step_ended_otherwise) == [f"{lead}step 'test:cccb070c' differs in ended."]
    assert recording_edited(an_event_missing) == [
        f"{lead}the events differ: 0 held by both differ, and 1 held by one only are not kept for "
        "an alert of the lab's rules."
    ]
    assert recording_edited(a_published_alert_on_one_side) == [f"{lead}the published rules' alerts differ."]
    assert recording_edited(other_ordinary_activity) == [
        f"{lead}the ordinary activity, or what the published rules matched in it, differs."
    ]
    assert recording_edited(the_new_rule_not_accepted) == [
        f"{lead}lab_rules[0].after.accepted is True, but the after recording says False.",
        f"{lead}lab_rules[0].after.reason is 'it alerted on every run with changed input arguments "
        "and on no ordinary activity', but the after recording says 'it matched ordinary activity'.",
    ]
    assert recording_edited(an_unchanged_rule_judged_otherwise) == [
        f"{lead}the lab's rule 'Shell History File Emptied' is the same file in both recordings and "
        "was judged differently."
    ]
    assert edited(two_ci_runs) == [
        "after.run_url must name the CI run the before recording names: one run was made in one CI run.",
    ]
    assert edited(the_claim_of_a_pair) == [
        "claim must be 'one run evaluated with two rule sets' exactly when one_run is true, and "
        "'one pair of runs' otherwise.",
    ]
    assert "claim must be 'one run evaluated with two rule sets' exactly when one_run is true, and " \
        "'one pair of runs' otherwise." in edited(a_pair_that_claims_one_run)
    # Without one_run the delta reads as a pair, so the one run's checks would not run.
    assert "claim must be 'one run evaluated with two rule sets' exactly when one_run is true, and " \
        "'one pair of runs' otherwise." in edited(one_run_left_out)
    assert edited(two_runners)[0] == (
        "runners is not given for one run evaluated twice: it ran on one runner, with one set of "
        "audit rules."
    )
    assert edited(two_ids)[0] == "after.id must be the before recording's id: one run has one id."
    assert edited(no_rule_listed) == [
        f"{lead}the lab's rule 'Shell History File Truncated In Place' differs between the two "
        "recordings and lab_rules does not list it.",
        *[
            f"{lead}steps[{index}] is better, but no rule that lab_rules lists matched it in one "
            "evaluation only."
            for index, step in enumerate(good["steps"])
            if step["result"] == "better"
        ],
    ]
    assert edited(a_rule_said_to_be_there_before) == [
        f"{lead}lab_rules[0].before says the rule is in the before evaluation, but the before "
        "recording does not have it."
    ]
    assert edited(a_same_step_said_alerted) == [
        f"steps[{index}].{side}.outcome_with_lab_rules is 'alerted', but the {side} recording's step "
        "'test:cccb070c' says 'seen'."
        for index, step in enumerate(good["steps"])
        if step["id"] == "test:cccb070c"
        for side in ("before", "after")
    ]
    assert edited(the_rules_commit_of_another) == [
        "before.lab_rules_commit is not the commit of the before recording's detector lab."
    ]
