import json
from collections import Counter
from pathlib import Path, PurePosixPath

import pytest

from bluefire_lab.range import retained_occurrences

MANIFEST = PurePosixPath("files/manifest.json")
ALERTS = PurePosixPath("files/raw/manager/var/ossec/logs/alerts/alerts.json")
CERTIFIED = "copper-river"
OTHER_CERTIFIED = "winter-orbit"
SOURCES = {MANIFEST: "document", ALERTS: "ndjson"}


def write_sources(tmp_path: Path, manifest: object, alerts: list[object]) -> None:
    manifest_path = tmp_path.joinpath(*MANIFEST.parts)
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    alerts_path = tmp_path.joinpath(*ALERTS.parts)
    alerts_path.parent.mkdir(parents=True)
    alerts_path.write_text("".join(f"{json.dumps(record)}\n" for record in alerts), encoding="utf-8")


def approved() -> list[retained_occurrences.CertifiedOccurrence]:
    return [
        retained_occurrences.CertifiedOccurrence(MANIFEST, "/capture/sha256", CERTIFIED),
        retained_occurrences.CertifiedOccurrence(
            ALERTS,
            "/0/data/syscheck/sha256_after",
            OTHER_CERTIFIED,
        ),
    ]


def exact_manifest() -> dict:
    return {"capture": {"sha256": CERTIFIED}}


def exact_alert() -> dict:
    return {"data": {"syscheck": {"sha256_after": OTHER_CERTIFIED}}}


def audit(tmp_path: Path) -> None:
    retained_occurrences.audit_json_occurrences(
        tmp_path,
        sources=SOURCES,
        certified=approved(),
    )


def test_exact_approved_occurrence_multiset_is_accepted(tmp_path: Path) -> None:
    write_sources(tmp_path, exact_manifest(), [exact_alert()])

    audit(tmp_path)


@pytest.mark.parametrize(
    ("manifest", "alerts"),
    [
        (
            {"capture": {"sha256": CERTIFIED, "sibling": CERTIFIED}},
            [exact_alert()],
        ),
        (
            exact_manifest(),
            [
                {
                    "data": {"syscheck": {"sha256_after": OTHER_CERTIFIED}},
                    "full_log": OTHER_CERTIFIED,
                }
            ],
        ),
    ],
    ids=("sibling", "full-log"),
)
def test_copy_to_a_sibling_or_full_log_is_refused(
    tmp_path: Path,
    manifest: dict,
    alerts: list[dict],
) -> None:
    write_sources(tmp_path, manifest, alerts)

    with pytest.raises(
        retained_occurrences.RetainedOccurrenceError,
        match="outside the approved locations",
    ):
        audit(tmp_path)


def test_certified_plaintext_copied_into_a_key_is_refused(tmp_path: Path) -> None:
    manifest = {**exact_manifest(), f"unapproved-{CERTIFIED}-key": "ordinary"}
    write_sources(tmp_path, manifest, [exact_alert()])

    with pytest.raises(
        retained_occurrences.RetainedOccurrenceError,
        match=r"outside the approved locations \(1 key\)",
    ):
        audit(tmp_path)


def test_duplicate_json_key_is_refused_before_occurrence_audit(tmp_path: Path) -> None:
    write_sources(tmp_path, exact_manifest(), [exact_alert()])
    manifest_path = tmp_path.joinpath(*MANIFEST.parts)
    manifest_path.write_text(
        '{"capture":{"sha256":"copper-river","sha256":"copper-river"}}',
        encoding="utf-8",
    )

    with pytest.raises(retained_occurrences.RetainedOccurrenceError, match="duplicate JSON key"):
        audit(tmp_path)


def test_right_value_at_the_wrong_pointer_is_refused(tmp_path: Path) -> None:
    write_sources(tmp_path, exact_manifest(), [exact_alert()])
    certifications = approved()
    certifications[0] = retained_occurrences.CertifiedOccurrence(
        MANIFEST,
        "/capture/sha1",
        CERTIFIED,
    )

    with pytest.raises(
        retained_occurrences.RetainedOccurrenceError,
        match=r"missing 1 approved occurrence.*outside the approved locations",
    ):
        retained_occurrences.audit_json_occurrences(
            tmp_path,
            sources=SOURCES,
            certified=certifications,
        )


def test_extra_ndjson_record_with_a_certified_value_is_refused(tmp_path: Path) -> None:
    write_sources(tmp_path, exact_manifest(), [exact_alert(), exact_alert()])

    with pytest.raises(
        retained_occurrences.RetainedOccurrenceError,
        match="outside the approved locations",
    ):
        audit(tmp_path)


def test_certified_value_as_a_substring_of_longer_text_is_refused(tmp_path: Path) -> None:
    manifest = {"capture": {"sha256": f"prefix-{CERTIFIED}-suffix"}}
    write_sources(tmp_path, manifest, [exact_alert()])

    with pytest.raises(
        retained_occurrences.RetainedOccurrenceError,
        match=r"missing 1 approved occurrence",
    ):
        audit(tmp_path)


def test_overlapping_substrings_and_pointer_escaping_are_counted() -> None:
    assert retained_occurrences.occurrence_locations(
        {"a/b~c": "aaaa"},
        "aa",
    ) == Counter({("string", "/a~1b~0c"): 3})


def test_duplicate_key_in_a_later_ndjson_record_is_refused_without_echoing_it() -> None:
    data = b'{"ok":1}\n{"sensitive-field":1,"sensitive-field":2}\n'

    with pytest.raises(retained_occurrences.RetainedOccurrenceError) as raised:
        retained_occurrences.loads_ndjson_objects(data, "Wazuh alerts")

    assert "duplicate JSON key" in str(raised.value)
    assert "sensitive-field" not in str(raised.value)
