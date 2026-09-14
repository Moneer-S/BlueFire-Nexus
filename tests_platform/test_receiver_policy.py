from __future__ import annotations

import hashlib
import json

import pytest

from bluefire.receiver_policy import (
    REDACTED_ONLY_POLICY,
    REVIEWED_RECORDS_POLICY,
    ReceiverContentPolicy,
)


def public_records(*, redacted=False, empty=False, count=4):
    return b"".join(
        (
            json.dumps(
                {
                    "record_id": f"synthetic-{n:03}",
                    "synthetic": True,
                    "template": "empty" if empty else "telemetry-seed",
                    "value": (
                        "synthetic-redacted"
                        if redacted
                        else ("" if empty else f"telemetry-value-{n:03}")
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        for n in range(1, count + 1)
    )


@pytest.mark.parametrize(
    "redacted,empty,expected",
    [
        (False, False, "policy_refused"),
        (False, True, "policy_refused"),
        (True, False, "accepted"),
        (True, True, "accepted"),
    ],
)
def test_real_public_bytes_change_target_decision_without_changing_authentication(
    redacted, empty, expected
):
    payload = public_records(redacted=redacted, empty=empty)
    baseline = ReceiverContentPolicy(REVIEWED_RECORDS_POLICY).inspect(payload)
    revised = ReceiverContentPolicy(REDACTED_ONLY_POLICY).inspect(payload)
    assert baseline["decision"] == "accepted"
    assert revised["decision"] == expected
    assert baseline["sha256"] == revised["sha256"] == hashlib.sha256(payload).hexdigest()
    assert revised["bytes_received"] == len(payload)
    assert baseline["policy_digest"] != revised["policy_digest"]
    assert "value" not in json.dumps(revised)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"{}\n",
        b"[]\n",
        public_records()[:-1],
        public_records().replace(b"telemetry-value-001", b"arbitrary-value"),
        public_records(count=101),
        b"x" * (1024 * 1024 + 1),
    ],
    ids=["empty", "object", "array", "truncated", "unreviewed", "too-many-rows", "oversized"],
)
@pytest.mark.parametrize("policy_id", [REVIEWED_RECORDS_POLICY, REDACTED_ONLY_POLICY])
def test_malformed_content_never_becomes_a_content_policy_success(payload, policy_id):
    result = ReceiverContentPolicy(policy_id).inspect(payload)
    assert result["decision"] == "invalid_content"
    assert result["semantics"] is None
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()


def test_policy_identity_is_fixed_and_unknown_predicates_are_refused():
    policy = ReceiverContentPolicy(REDACTED_ONLY_POLICY)
    assert policy.digest == ReceiverContentPolicy(REDACTED_ONLY_POLICY).digest
    assert policy.to_dict()["authentication"] == "managed_task_hmac_sha256"
    with pytest.raises(ValueError):
        ReceiverContentPolicy("allow-anything")
