import json

import pytest

from tools.verify_macos_file_access_protocol import EXPECTED, validate_capability


def _payload():
    return json.dumps(EXPECTED, separators=(",", ":")).encode("utf-8") + b"\n"


def test_installed_protocol_capability_is_support_only():
    value = validate_capability(_payload(), b"", 0)

    assert value == EXPECTED
    assert value["native_backend_available"] is True
    assert value["live_ready"] is False
    assert value["scope"] == "protocol_support_only"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra=True),
        lambda value: value.pop("live_ready"),
        lambda value: value.update(live_ready=True),
        lambda value: value.update(native_backend_available=False),
        lambda value: value.update(max_requests=True),
    ],
)
def test_installed_protocol_capability_rejects_schema_or_type_drift(mutate):
    value = dict(EXPECTED)
    mutate(value)

    with pytest.raises(RuntimeError):
        validate_capability(json.dumps(value).encode("utf-8") + b"\n", b"", 0)


def test_installed_protocol_capability_rejects_duplicates_and_process_noise():
    payload = _payload()
    duplicate = payload[:-2] + b',"live_ready":false}\n'

    with pytest.raises(ValueError, match="duplicate JSON key"):
        validate_capability(duplicate, b"", 0)
    with pytest.raises(RuntimeError):
        validate_capability(payload, b"diagnostic", 0)
    with pytest.raises(RuntimeError):
        validate_capability(payload, b"", 1)
    with pytest.raises(RuntimeError):
        validate_capability(payload.rstrip(), b"", 0)
    with pytest.raises(RuntimeError):
        validate_capability(payload.replace(b"{", b"{\n", 1), b"", 0)


@pytest.mark.parametrize("raw", [b"{}\n\n", b" {}\n", b"x" * 4096 + b"\n"])
def test_installed_protocol_capability_rejects_unbounded_or_noncanonical_frame(raw):
    with pytest.raises(RuntimeError):
        validate_capability(raw, b"", 0)
