"""One-shot correction supervision over fake child/Job/control boundaries only."""

from __future__ import annotations

import io
import json
import struct
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_correction_child as child
from bluefire import windows_file_access_correction_control_process as process
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_correction_credential import correction as correction
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_pair_observation import pair_observed as pair_observed
from tests_platform.test_windows_file_access_setup_binding import supervision
from tests_platform.test_windows_file_access_setup_process import FakeContainment, FakeProcess

AFTER = "sha256:" + "e" * 64


def frame(row):
    raw = canonical_json_bytes(row)
    return struct.pack("<I", len(raw)) + raw


def terminal(binding):
    return {
        "schema_version": child.RESULT_SCHEMA,
        "binding_digest": content_hash(binding),
        "result": {
            "before_descriptor_sha256": binding["previous_descriptor_sha256"],
            "after_descriptor_sha256": AFTER,
            "target": "metadata_only",
            "file_identity": binding["target_resource"]["file_identity"],
            "preserved_sha256": binding["target_resource"]["sha256"],
            "fresh_owner_read": True,
            "read_handles_closed": True,
        },
    }


@pytest.fixture
def control_child(correction, monkeypatch):
    c = correction
    c.state["resource_state"] = "readable"
    monkeypatch.setattr(child.time, "monotonic_ns", lambda: int(c.state["mono"] * 1_000_000_000))
    request = {
        "schema_version": child.REQUEST_SCHEMA,
        "original_record": c.record,
        "original_receipt": json.loads(c.checked_setup._receipt),
        "binding": c.binding,
        "original_deadline_ns": 14_000_000_000,
        "supervision": supervision(),
    }
    events = []
    flags = SimpleNamespace(fault=None, effects=0)

    @contextmanager
    def handoff(value):
        assert value == supervision()
        events.append("actual-handoff")
        if flags.fault == "handoff":
            raise RuntimeError("synthetic creator refusal")
        yield
        if flags.fault == "handoff-close":
            raise RuntimeError("synthetic closure refusal")

    def transition(value, *, admit, before_apply):
        events.append("transition")
        value.validate()
        assert value.target == "metadata_only" and value.resource.state == "readable"
        assert value.previous_descriptor_sha256 == c.binding["previous_descriptor_sha256"]
        assert value.resource.record_count == child.setup._CONTENT.count(b"\n")
        if flags.fault == "late-admit":
            c.state["mono"] = 14.0
        admit()
        events.append("admitted")
        if flags.fault == "twice-admit":
            admit()
        if flags.fault == "late-before-apply":
            c.state["mono"] = 14.0
        before_apply()
        flags.effects += 1
        if flags.fault == "setter":
            raise RuntimeError("synthetic uncertain effect")
        if flags.fault == "late-result":
            c.state["mono"] = 14.0
        result = terminal(c.binding)["result"]
        return SimpleNamespace(**{**result, "file_identity": value.resource.file_identity})

    monkeypatch.setattr(child.supervision, "require_child_handoff", handoff)
    monkeypatch.setattr(child, "transition_windows_file_access", transition)

    @contextmanager
    def capability(*args, **kwargs):
        yield lambda: None

    monkeypatch.setattr(child, "held_correction_capability", capability)
    return SimpleNamespace(c=c, request=request, events=events, flags=flags)


def test_child_requires_concrete_readable_setup_and_actual_handoff_once(control_child):
    v = control_child
    output = io.BytesIO()
    assert child._run(io.BytesIO(frame(v.request)), output) == 0
    row = child.validate_terminal(output.getvalue()[4:], v.c.binding, 0)
    assert row == terminal(v.c.binding)
    assert v.events == ["actual-handoff", "transition", "admitted"]
    assert v.c.checked_setup._raw == canonical_json_bytes(v.c.record)


@pytest.mark.parametrize(
    "fault",
    [
        "handoff",
        "handoff-close",
        "late-admit",
        "late-before-apply",
        "twice-admit",
        "setter",
        "late-result",
    ],
)
def test_child_partial_or_missing_proof_stays_unknown(control_child, fault):
    v = control_child
    v.flags.fault = fault
    output = io.BytesIO()
    assert child._run(io.BytesIO(frame(v.request)), output) == 4
    result = json.loads(output.getvalue()[4:])
    assert result["result"] is None
    assert "synthetic" not in str(result)
    if fault == "handoff":
        assert v.events == ["actual-handoff"]
    if fault in ("late-admit", "late-before-apply", "twice-admit"):
        assert v.flags.effects == 0
    assert v.events.count("transition") <= 1


@pytest.mark.parametrize(
    "fault",
    ["record", "receipt", "binding", "descriptor", "expiry", "deadline", "trailing", "extra"],
)
def test_child_rejects_wrong_or_stale_context_without_effect(control_child, fault):
    v = control_child
    if fault == "record":
        v.request["original_record"] = {**v.c.record, "setup_receipt_digest": "sha256:" + "0" * 64}
    elif fault == "receipt":
        v.request["original_receipt"] = {**v.request["original_receipt"], "generation": "0" * 32}
    elif fault == "binding":
        v.request["binding"] = {**v.c.binding, "enrollment_digest": "sha256:" + "0" * 64}
    elif fault == "descriptor":
        v.request["binding"] = {**v.c.binding, "previous_descriptor_sha256": "invalid"}
    elif fault == "expiry":
        v.c.state["wall"] = v.c.binding["expires_at_ms"]
    elif fault == "deadline":
        v.request["original_deadline_ns"] = 10_000_000_000
    elif fault == "extra":
        v.request["path"] = "caller-selected"
    output = io.BytesIO()
    assert (
        child._run(io.BytesIO(frame(v.request) + (b"x" if fault == "trailing" else b"")), output)
        == 4
    )
    assert json.loads(output.getvalue()[4:])["result"] is None
    assert "transition" not in v.events


@pytest.fixture
def supervisor(correction, monkeypatch):
    c = correction
    monkeypatch.setattr(process.time, "monotonic_ns", lambda: int(c.state["mono"] * 1_000_000_000))
    fake = FakeProcess()
    fake.stdout = io.BytesIO(frame(terminal(c.binding)))
    events, retained = [], []
    flags = SimpleNamespace(fault=None)
    monkeypatch.setattr(process.shared, "WindowsJobContainment", FakeContainment)
    monkeypatch.setattr(process.shared.sys, "platform", "win32")

    def before_dispatch():
        events.append("durable-journal")
        if flags.fault == "journal":
            raise RuntimeError("synthetic journal refusal")

    def launch(owner):
        events.append("suspended-child")
        owner.job, owner.process, owner.handle, owner.pid = 200, fake, fake._handle, fake.pid
        owner.containment.adopt_retained_job(200, fake)
        owner.adopted = True
        owner.containment.assign_retained(200, fake)
        owner.current()
        owner._before_resume()
        if flags.fault == "after-journal":
            raise RuntimeError("synthetic ambiguous continuation")
        owner.current()
        owner.resumed = True
        events.append("resume")
        owner.containment.resume_retained(fake, 200, object())

    monkeypatch.setattr(process.CorrectionControlCleanupOwner, "_launch", launch)

    def run():
        return process.run_correction_control_process(
            c.checked_setup,
            canonical_json_bytes(c.binding),
            original_monotonic_deadline=14.0,
            before_dispatch=before_dispatch,
            cancellation_event=threading.Event(),
            retain_cleanup_owner=retained.append,
        )

    return SimpleNamespace(**locals())


def test_supervisor_journals_before_resume_and_receipt_requires_physical_closure(supervisor):
    v = supervisor
    result = v.run()
    assert v.events == ["suspended-child", "durable-journal", "resume"]
    assert result.process_cleanup == "verified" and result.dispatch == "attempted"
    receipt = result.cleanup_receipt
    assert type(receipt) is process.OwnedCorrectionControlReceipt
    assert receipt.document()["terminal"] == terminal(v.c.binding)
    assert result.cleanup_owner is None and result.settled is False
    assert v.fake._handle.closed and all(
        stream.closed for stream in (v.fake.stdin, v.fake.stdout, v.fake.stderr)
    )
    with pytest.raises(TypeError):
        process.OwnedCorrectionControlReceipt()
    with pytest.raises(process.contract.NativeWireError):
        v.retained[0]._before_resume()


@pytest.mark.parametrize(
    "fault,dispatch", [("journal", "not_started"), ("after-journal", "unknown")]
)
def test_dispatch_allowance_never_reused_after_journal_or_continuation_refusal(
    supervisor, fault, dispatch
):
    v = supervisor
    v.flags.fault = fault
    result = v.run()
    assert result.dispatch == dispatch and result.terminal is None
    assert result.cleanup_receipt.document()["terminal"] is None
    assert "resume" not in v.events
    before = list(v.events)
    assert v.retained[0].retry_cleanup()
    assert v.events == before


@pytest.mark.parametrize("fault", ["job", "start", "handle", "pins", "pipe", "exit"])
def test_unknown_closure_retains_exact_owner_and_retry_does_not_redispatch(supervisor, fault):
    v = supervisor
    fake_launch = process.CorrectionControlCleanupOwner._launch

    def launch(owner):
        fake_launch(owner)
        if fault == "job":
            owner.containment.fail_finish = True
        elif fault == "start":
            owner.containment.fail_start = True
        elif fault == "handle":
            owner.handle.fail = True
        elif fault == "pins":
            owner.pins.callback(lambda: (_ for _ in ()).throw(RuntimeError("synthetic pins")))
        elif fault == "pipe":
            owner.ambiguous_pipes.add("stdout")
        elif fault == "exit":
            v.fake.refuse_exit = True
            v.c.state["mono"] = 14.0

    process.CorrectionControlCleanupOwner._launch = launch
    try:
        result = v.run()
        assert result.process_cleanup == "unknown" and result.cleanup_receipt is None
        owner = result.cleanup_owner
        assert owner is v.retained[0] and owner.process is v.fake
        assert owner.cleanup_receipt is None
        before = list(v.events)
        owner.containment.fail_finish = owner.containment.fail_start = False
        v.fake.refuse_exit = False
        clean = owner.retry_cleanup()
        assert v.events == before
        if fault in ("job", "start", "exit"):
            assert clean and type(owner.cleanup_receipt) is process.OwnedCorrectionControlReceipt
        else:
            assert not clean and owner.cleanup_receipt is None
    finally:
        process.CorrectionControlCleanupOwner._launch = fake_launch


def test_closed_process_with_unknown_terminal_proves_only_closure(supervisor):
    v = supervisor
    row = terminal(v.c.binding)
    row["result"] = None
    v.fake.returncode = 4
    v.fake.stdout = io.BytesIO(frame(row))
    result = v.run()
    assert result.dispatch == "unknown" and result.process_cleanup == "verified"
    assert result.cleanup_receipt.document()["terminal"]["result"] is None
    historical = process.validate_retained_control_receipt(
        result.cleanup_receipt.document(), v.c.binding
    )
    assert type(historical) is dict and historical["settled"] is False
    with pytest.raises(process.contract.NativeWireError):
        process.validate_retained_control_receipt(
            {**historical, "process_cleanup": "unknown"}, v.c.binding
        )


@pytest.mark.parametrize("fault", ["platform", "isolation", "module", "arguments", "path"])
def test_correction_main_refuses_nonfixed_entry_before_input(monkeypatch, fault):
    fake_sys = SimpleNamespace(
        platform="win32", flags=SimpleNamespace(isolated=1), argv=[child.__file__]
    )
    monkeypatch.setattr(child, "sys", fake_sys)
    monkeypatch.setattr(child, "__package__", "")
    if fault == "platform":
        fake_sys.platform = "linux"
    elif fault == "isolation":
        fake_sys.flags.isolated = 0
    elif fault == "module":
        monkeypatch.setattr(child, "__package__", "bluefire")
    elif fault == "arguments":
        fake_sys.argv.append("caller-command")
    else:
        fake_sys.argv = ["other.py"]
    monkeypatch.setattr(
        child, "_run", lambda *args: pytest.fail("Invalid entry must not read input")
    )
    assert child.main() == 4


def test_fixed_correction_launch_cannot_allocate_or_resume_twice(correction, monkeypatch):
    monkeypatch.setattr(process.shared, "WindowsJobContainment", FakeContainment)
    monkeypatch.setattr(
        process.time, "monotonic_ns", lambda: int(correction.state["mono"] * 1_000_000_000)
    )
    calls = []
    monkeypatch.setattr(
        process.shared.SetupCleanupOwner, "_launch", lambda self: calls.append("launch-once")
    )
    owner = process.CorrectionControlCleanupOwner(
        correction.checked_setup,
        canonical_json_bytes(correction.binding),
        original_monotonic_deadline=14.0,
        before_dispatch=lambda: None,
        cancellation_event=threading.Event(),
    )
    path, arguments = owner._entry_spec()
    assert path.name == "windows_file_access_correction_child.py" and arguments == ()
    owner._launch()
    with pytest.raises(process.contract.NativeWireError):
        owner._launch()
    assert calls == ["launch-once"]
    assert owner.retry_cleanup()


@pytest.mark.parametrize("kind", ["correction", "setup"])
def test_unseen_child_creation_cannot_mint_closure_or_be_retried(
    correction, monkeypatch, tmp_path, kind
):
    c = correction
    monkeypatch.setattr(process.time, "monotonic_ns", lambda: int(c.state["mono"] * 1_000_000_000))
    runtime = tmp_path / "python.exe"
    for name in (
        "python.exe",
        "windows_file_access_setup_process.py",
        "windows_file_access_setup_child.py",
        "windows_file_access_correction_control_process.py",
        "windows_file_access_correction_child.py",
    ):
        (tmp_path / name).write_bytes(b"synthetic test source, never executed")
    shared = process.shared
    monkeypatch.setattr(shared, "WindowsJobContainment", FakeContainment)
    monkeypatch.setattr(
        FakeContainment,
        "system_directory",
        lambda self: tmp_path / "Windows" / "System32",
        raising=False,
    )
    monkeypatch.setattr(shared.sys, "platform", "win32")
    monkeypatch.setattr(shared.sys, "_base_executable", str(runtime))
    monkeypatch.setattr(shared, "__file__", str(tmp_path / "windows_file_access_setup_process.py"))
    monkeypatch.setattr(
        process, "__file__", str(tmp_path / "windows_file_access_correction_control_process.py")
    )
    monkeypatch.setattr(shared.entry, "_managed_root", lambda: tmp_path)
    monkeypatch.setattr(
        shared, "_PinnedDirectory", lambda *args, **kwargs: __import__("contextlib").nullcontext()
    )
    monkeypatch.setattr(shared, "_is_link_or_reparse", lambda path: False)
    descriptors = iter(range(10, 16))
    monkeypatch.setattr(
        shared,
        "os",
        SimpleNamespace(
            pipe=lambda: (next(descriptors), next(descriptors)),
            fdopen=lambda descriptor, mode, buffering: io.BytesIO(),
            close=lambda descriptor: None,
        ),
    )

    @contextmanager
    def pinned(path, digest):
        yield str(path), ()

    monkeypatch.setattr(shared, "_pinned_launch_file", pinned)
    creations, journals, retained = [], [], []

    def unseen_popen(argv, **kwargs):
        assert kwargs["creationflags"] & 4
        creations.append("unseen suspended child")
        raise OSError("synthetic failure after native creation")

    monkeypatch.setattr(shared.subprocess, "Popen", unseen_popen)
    if kind == "correction":
        result = process.run_correction_control_process(
            c.checked_setup,
            canonical_json_bytes(c.binding),
            original_monotonic_deadline=14.0,
            before_dispatch=lambda: journals.append("journal"),
            cancellation_event=threading.Event(),
            retain_cleanup_owner=retained.append,
        )
        assert result.cleanup_receipt is None
    else:
        result = shared.run_setup_process("existing-source", cancellation_event=threading.Event())
    assert result.dispatch == result.process_cleanup == "unknown"
    owner = result.cleanup_owner
    assert owner is not None and owner.process is None
    assert owner.creation_started and owner.creation_unknown and not owner.verified
    assert creations == ["unseen suspended child"] and journals == []
    assert not owner.retry_cleanup()
    assert creations == ["unseen suspended child"]
    if kind == "correction":
        assert owner is retained[0] and owner.cleanup_receipt is None


@pytest.mark.parametrize("late_stage", ["facts", "dacl", "setter"])
def test_real_primitive_checks_original_deadline_after_metadata_and_late_setter_stays_unknown(
    control_child, monkeypatch, late_stage
):
    from bluefire import windows_file_access_control as primitive
    from bluefire.windows_file_access_handles import WindowsFileFacts
    from tests_platform.test_windows_file_access_control import FakeController

    v = control_child

    class Controller(FakeController):
        request = None
        advanced = False

        def principal(self):
            return v.c.backend.owner

        def advance(self, stage):
            if self.admissions and not self.advanced and late_stage == stage:
                self.advanced = True
                v.c.state["mono"] = 14.0

        def facts(self, descriptor, *, directory):
            self.advance("facts")
            resource = self.request.resource
            index = min(descriptor, 5) - 1
            identity = resource.directory_identities[index] if index < 4 else resource.file_identity
            path, actual_directory, _ = self.paths[descriptor - 1]
            assert directory is actual_directory
            return WindowsFileFacts(
                identity,
                "\\\\?\\" + path,
                directory,
                0 if directory else resource.size,
                1,
                16 if directory else 32,
                1,
                2,
                4 if self.applied and not directory else 3,
            )

        def dacl(self, descriptor, policy, state):
            self.advance("dacl")
            assert policy == self.request.resource.policy
            return (
                "sha256:" + "a" * 64
                if state == "directory"
                else (AFTER if self.applied else self.request.previous_descriptor_sha256)
            )

        def read(self, descriptor, maximum):
            start = self.positions[descriptor]
            value = child.setup._CONTENT[start : start + maximum]
            self.positions[descriptor] += len(value)
            return value

        def apply(self, descriptor, policy, target):
            assert (
                descriptor == 5 and policy == self.request.resource.policy and self.admissions == 1
            )
            self.applied += 1
            self.target = target
            self.advance("setter")

    controller = Controller()
    monkeypatch.setattr(primitive, "_Controller", lambda: controller)

    def transition(request, *, admit, before_apply):
        controller.request = request

        def admitted():
            admit()
            controller.admissions += 1

        return primitive.transition_windows_file_access(
            request, admit=admitted, before_apply=before_apply
        )

    monkeypatch.setattr(child, "transition_windows_file_access", transition)
    output = io.BytesIO()
    assert child._run(io.BytesIO(frame(v.request)), output) == 4
    assert json.loads(output.getvalue()[4:])["result"] is None
    assert controller.closed and controller.admissions == 1
    assert controller.applied == (1 if late_stage == "setter" else 0)
