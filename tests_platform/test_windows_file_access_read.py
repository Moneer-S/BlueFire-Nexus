from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from bluefire import windows_file_access_read as reader
from bluefire.windows_file_access_handles import (
    WindowsDataOpenDenied,
    WindowsFileFacts,
    WindowsFileHandleError,
)
from bluefire.windows_file_access_policy import WindowsFileAccessPolicy
from bluefire.windows_session_facts import WindowsPrincipalFacts

PAYLOAD = b'{"record":1}\n'
PRINCIPAL = WindowsPrincipalFacts(41, 123456, "S-1-5-21-101-202-303-1002", 10, 20, 30, 2, False)
RESOURCE = reader.WindowsResourceExpectation(
    "a" * 32,
    WindowsFileAccessPolicy("S-1-5-21-101-202-303-1001", PRINCIPAL.user_sid),
    ((1, 1), (1, 2), (1, 3), (1, 4)),
    (1, 5),
    len(PAYLOAD),
    "sha256:" + hashlib.sha256(PAYLOAD).hexdigest(),
    1,
    "readable",
)
EXPECTATION = reader.WindowsReadExpectation(RESOURCE, PRINCIPAL)


def _with_resource(**values):
    return replace(EXPECTATION, resource=replace(RESOURCE, **values))


class FakeReader:
    def __init__(self):
        self.opened = []
        self.facts_by_handle = {}
        self.expected = RESOURCE
        self.identity = PRINCIPAL
        self.principal_calls = 0
        self.principal_change = False
        self.metadata_error = False
        self.denied = False
        self.data_error = False
        self.payload = PAYLOAD
        self.closed = False
        self.close_error = False
        self.changed_handle = None
        self.substituted_data = False
        self.fact_calls = {}
        self.dacl_calls = 0
        self.dacl_changed = False
        self.read_calls = 0

    def principal(self):
        self.principal_calls += 1
        return (
            replace(self.identity, modified_id=31)
            if self.principal_change and self.principal_calls > 1
            else self.identity
        )

    def open(self, path, *, directory, data=False):
        if self.metadata_error and not directory and not data:
            raise WindowsFileHandleError("metadata denied")
        if data and self.denied:
            raise WindowsDataOpenDenied("data denied")
        if data and self.data_error:
            raise WindowsFileHandleError("data unavailable")
        self.opened.append((path, directory, data))
        descriptor = len(self.opened)
        index = min(descriptor, 5)
        self.facts_by_handle[descriptor] = WindowsFileFacts(
            (1, index),
            "\\\\?\\" + path,
            directory,
            0 if directory else self.expected.size,
            1,
            16 if directory else 32,
            1,
            2,
            3,
        )
        if data and self.substituted_data:
            self.facts_by_handle[descriptor] = replace(
                self.facts_by_handle[descriptor], identity=(1, 99)
            )
        return descriptor

    def facts(self, descriptor, *, directory):
        self.fact_calls[descriptor] = self.fact_calls.get(descriptor, 0) + 1
        facts = self.facts_by_handle[descriptor]
        if descriptor == self.changed_handle and self.fact_calls[descriptor] > 1:
            return replace(facts, changed=4)
        return facts

    def dacl(self, descriptor, policy, state):
        self.dacl_calls += 1
        suffix = "b" if self.dacl_changed and self.dacl_calls > 2 else "a"
        return "sha256:" + suffix * 64

    def read(self, descriptor, maximum):
        self.read_calls += 1
        chunk, self.payload = self.payload[:maximum], self.payload[maximum:]
        return chunk

    def close(self):
        self.closed = True
        if self.close_error:
            raise reader.WindowsFileReadError("cleanup unknown")


@pytest.fixture
def backend(monkeypatch):
    result = FakeReader()
    monkeypatch.setattr(reader, "_Reader", lambda: result)
    return result


def test_fixed_fresh_read_verifies_identity_dacl_complete_contents_and_cleanup(backend):
    result = reader.fresh_windows_read(EXPECTATION)
    assert result.outcome == "allowed"
    assert result.sha256 == RESOURCE.sha256
    assert result.record_count == 1 and result.observed_size == len(PAYLOAD)
    assert result.file_identity == (1, 5)
    assert result.read_handles_closed and backend.closed
    assert backend.opened == [
        ("C:\\", True, False),
        ("C:\\BlueFire", True, False),
        ("C:\\BlueFire\\EndpointAccess", True, False),
        ("C:\\BlueFire\\EndpointAccess\\" + "a" * 32, True, False),
        ("C:\\BlueFire\\EndpointAccess\\" + "a" * 32 + "\\records.jsonl", False, False),
        ("C:\\BlueFire\\EndpointAccess\\" + "a" * 32 + "\\records.jsonl", False, True),
    ]
    assert backend.principal_calls == 2 and backend.dacl_calls == 4


def test_explicit_final_file_denial_has_no_invented_digest_or_records(backend):
    backend.denied = True
    result = reader.fresh_windows_read(_with_resource(state="metadata_only"))
    assert result.outcome == "permission_denied"
    assert result.sha256 is None and result.record_count is None
    assert result.observed_size == RESOURCE.size
    assert backend.read_calls == 0 and backend.closed


def test_readable_result_under_metadata_only_policy_does_not_claim_prevention(backend):
    result = reader.fresh_windows_read(_with_resource(state="metadata_only"))
    assert result.outcome == "allowed"


@pytest.mark.parametrize(
    "field",
    [
        "metadata_error",
        "data_error",
        "substituted_data",
        "dacl_changed",
        "principal_change",
        "close_error",
    ],
)
def test_unavailable_changed_or_unclosed_observation_never_counts_as_denial(backend, field):
    setattr(backend, field, True)
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(EXPECTATION)
    assert backend.closed


@pytest.mark.parametrize("descriptor", [1, 2, 3, 4, 5, 6])
def test_any_held_object_change_invalidates_result(backend, descriptor):
    backend.changed_handle = descriptor
    with pytest.raises(reader.WindowsFileReadError, match="changed"):
        reader.fresh_windows_read(EXPECTATION)
    assert backend.closed


@pytest.mark.parametrize(
    "field,value",
    [
        ("process_id", 42),
        ("process_created_filetime", 123457),
        ("user_sid", "S-1-5-21-101-202-303-1001"),
        ("token_id", 11),
        ("authentication_id", 21),
        ("modified_id", 31),
        ("session_id", 3),
        ("elevated", True),
    ],
)
def test_different_actual_principal_never_opens_a_resource(backend, field, value):
    backend.identity = replace(PRINCIPAL, **{field: value})
    with pytest.raises(reader.WindowsFileReadError, match="principal differs"):
        reader.fresh_windows_read(EXPECTATION)
    assert backend.opened == [] and backend.closed


@pytest.mark.parametrize("payload", [b"", PAYLOAD[:-1], PAYLOAD + b"x", b"x" * len(PAYLOAD)])
def test_truncated_grown_or_changed_bytes_refuse(backend, payload):
    backend.payload = payload
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(EXPECTATION)
    assert backend.closed


@pytest.mark.parametrize(
    "payload",
    [
        b"[]\n",
        b"not json\n",
        b"\xff\n",
        b'{"record":NaN}\n',
        b'{"record":1e999}\n',
        b'{"record":{"nested":[-1e999]}}\n',
        b'{"record":1,"record":2}\n',
        b'{"record":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}\n",
    ],
)
def test_matching_digest_does_not_accept_nonrecord_content(backend, payload):
    expectation = _with_resource(
        size=len(payload), sha256="sha256:" + hashlib.sha256(payload).hexdigest()
    )
    backend.expected, backend.payload = expectation.resource, payload
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(expectation)
    assert backend.closed


@pytest.mark.parametrize("depth,allowed", [(31, True), (32, False), (1100, False)])
@pytest.mark.parametrize("container", ["array", "object"])
def test_record_nesting_has_an_explicit_bound(backend, depth, allowed, container):
    opening, closing = (b"[", b"]") if container == "array" else (b'{"value":', b"}")
    payload = b'{"record":' + opening * depth + b"0" + closing * depth + b"}\n"
    expectation = _with_resource(
        size=len(payload), sha256="sha256:" + hashlib.sha256(payload).hexdigest(), record_count=1
    )
    backend.expected, backend.payload = expectation.resource, payload
    if allowed:
        observed = reader.fresh_windows_read(expectation)
        assert observed.outcome == "allowed" and observed.record_count == 1
    else:
        with pytest.raises(reader.WindowsFileReadError):
            reader.fresh_windows_read(expectation)
    assert backend.closed


def test_record_string_delimiters_do_not_count_as_nesting(backend):
    payload = b'{"record":"' + b"[{" * 1100 + b']}","value":1}\n'
    expectation = _with_resource(
        size=len(payload), sha256="sha256:" + hashlib.sha256(payload).hexdigest(), record_count=1
    )
    backend.expected, backend.payload = expectation.resource, payload
    assert reader.fresh_windows_read(expectation).record_count == 1
    assert backend.closed


def test_finite_exponent_record_is_accepted(backend):
    payload = b'{"record":{"nested":[1e3,-2.5e-8]}}\n'
    expectation = _with_resource(
        size=len(payload), sha256="sha256:" + hashlib.sha256(payload).hexdigest(), record_count=1
    )
    backend.expected, backend.payload = expectation.resource, payload
    assert reader.fresh_windows_read(expectation).record_count == 1
    assert backend.closed


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", "../outside"),
        ("generation", "A" * 32),
        ("state", "0600"),
        ("size", 0),
        ("size", 1048577),
        ("record_count", True),
        ("sha256", "a" * 64),
        ("file_identity", (1, 4)),
        ("file_identity", (2, 5)),
        ("file_identity", (True, 5)),
        ("directory_identities", ((1, 1),)),
    ],
)
def test_invalid_or_cross_volume_expectations_never_open_a_resource(backend, field, value):
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(_with_resource(**{field: value}))
    assert backend.opened == []


def test_malformed_private_principal_expectation_never_opens_a_resource(backend):
    expectation = replace(EXPECTATION, principal=replace(PRINCIPAL, token_id=True))
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(expectation)
    assert backend.opened == []


@pytest.mark.parametrize("resource", [None, {}, PRINCIPAL])
def test_nonresource_enrollment_never_opens_a_resource(backend, resource):
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(replace(EXPECTATION, resource=resource))
    assert backend.opened == []


@pytest.mark.parametrize("principal", [None, {}, replace(PRINCIPAL, elevated=True)])
def test_primary_read_still_requires_a_valid_nonelevated_principal(backend, principal):
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(replace(EXPECTATION, principal=principal))
    assert backend.opened == []


def test_resource_can_be_bound_to_a_fresh_primary_process_without_changing_enrollment(backend):
    principal = replace(PRINCIPAL, process_id=57, process_created_filetime=123457, token_id=11)
    backend.identity = principal
    expectation = reader.WindowsReadExpectation(RESOURCE, principal)
    result = reader.fresh_windows_read(expectation)
    assert result.principal == principal and result.outcome == "allowed"
    assert expectation.resource is RESOURCE and backend.closed


def test_expired_cooperative_deadline_refuses_before_first_open(backend, monkeypatch):
    ticks = iter([10.0, 15.0])
    monkeypatch.setattr(reader.time, "monotonic", lambda: next(ticks))
    with pytest.raises(reader.WindowsFileReadError, match="deadline exceeded"):
        reader.fresh_windows_read(EXPECTATION)
    assert backend.opened == [] and backend.closed


@pytest.mark.parametrize(
    "failure", ["dacl_changed", "principal_change", "metadata_changed", "close_error"]
)
def test_denial_is_not_accepted_with_changed_metadata_identity_or_unknown_cleanup(backend, failure):
    backend.denied = True
    if failure == "metadata_changed":
        backend.changed_handle = 5
    else:
        setattr(backend, failure, True)
    with pytest.raises(reader.WindowsFileReadError):
        reader.fresh_windows_read(_with_resource(state="metadata_only"))
    assert backend.closed


def test_actual_final_path_mismatch_stops_before_any_content_read(backend, monkeypatch):
    original = backend.facts

    def wrong_path(descriptor, *, directory):
        facts = original(descriptor, directory=directory)
        return replace(facts, final_path="\\\\?\\C:\\other") if descriptor == 4 else facts

    monkeypatch.setattr(backend, "facts", wrong_path)
    with pytest.raises(reader.WindowsFileReadError, match="path or identity changed"):
        reader.fresh_windows_read(EXPECTATION)
    assert backend.read_calls == 0 and backend.closed


def test_late_native_read_cannot_return_a_success(backend, monkeypatch):
    monkeypatch.setattr(reader.time, "monotonic", lambda: 16.0 if backend.read_calls else 10.0)
    with pytest.raises(reader.WindowsFileReadError, match="deadline exceeded"):
        reader.fresh_windows_read(EXPECTATION)
    assert backend.closed
