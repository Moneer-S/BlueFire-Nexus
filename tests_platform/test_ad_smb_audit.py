"""Synthetic XML only: no audit collection, domain access or identity changes."""

from xml.etree import ElementTree as ET

import pytest

from bluefire.ad_smb_audit import MAX_EVENT_BYTES, NS, normalize_events
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from tests_platform.test_ad_smb_contract import pin, scope_row


def event(
    event_id=5145,
    *,
    record_id=None,
    outcome="success",
    version=None,
    when=None,
    fields=None,
    computer="member.lab.example",
):
    scope = scope_row()
    root = ET.Element(NS + "Event")
    system = ET.SubElement(root, NS + "System")
    ET.SubElement(
        system,
        NS + "Provider",
        Name="Microsoft-Windows-Security-Auditing",
        Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}",
    )
    values = {
        "EventID": str(event_id),
        "Version": str(version) if version is not None else ("0" if event_id == 5145 else "2"),
        "Keywords": "0x8020000000000000" if outcome == "success" else "0x8010000000000000",
        "EventRecordID": str(
            record_id if record_id is not None else (20 if event_id == 5145 else 10)
        ),
        "Channel": "Security",
        "Computer": computer,
    }
    for key, value in values.items():
        ET.SubElement(system, NS + key).text = value
    ET.SubElement(
        system,
        NS + "TimeCreated",
        SystemTime=when
        or ("2026-10-09T00:01:02.1234567Z" if event_id == 5145 else "2026-10-09T00:01:01.1234567Z"),
    )
    data = ET.SubElement(root, NS + "EventData")
    values = {"IpAddress": "10.44.0.3"}
    if event_id == 5145:
        values.update(
            SubjectUserSid=scope["principals"]["probe"]["sid"],
            SubjectLogonId="0x1234",
            ObjectType="File",
            ShareName="\\\\*\\" + scope["share"]["name"],
            ShareLocalPath="\\??\\" + scope["share"]["local_root"],
            RelativeTargetName="records.jsonl",
            AccessMask="0x120089",
        )
    else:
        values.update(
            TargetUserSid=scope["principals"]["probe"]["sid"],
            TargetLogonId="0x1234",
            LogonType="3",
            AuthenticationPackageName="Kerberos",
        )
    values.update(fields or {})
    for key, value in values.items():
        if value is not None:
            ET.SubElement(data, NS + "Data", Name=key).text = value
    return ET.tostring(root, encoding="utf-8")


def normalize(rows, **kwargs):
    options = {
        "source_host_id": pin("2"),
        "source_receipt_digest": pin("a"),
        "capture_batch_digest": pin("b"),
        "window_start": "2026-10-09T00:00:00Z",
        "window_end": "2026-10-09T00:30:00Z",
    }
    options.update(kwargs)
    return normalize_events(AdSmbScope.from_mapping(scope_row()), rows, **options)


def test_out_of_order_join_is_narrow_and_never_authenticates_imports():
    result = normalize([event(), event(4624)], completeness="complete")
    row = result["events"][0]
    assert row["binding"] == "matched"
    assert row["share_check"] == "granted"
    assert row["requests_file_data"] is True
    assert row["server_logon"] == "kerberos_network"
    assert row["logon_record_id"] == "10"
    assert row["client_ip"] == "10.44.0.3"
    assert row["observed_at"] == "2026-10-09T00:01:02.1234567Z"
    assert result["schema_version"] == "bluefire.ad-smb-audit-observation.v2"
    assert result["capture_batch_digest"] == pin("b")
    assert result["log_continuity_verified"] is False
    assert result["reported_completeness"] == "complete"
    for key in (
        "source_authenticity_verified",
        "independent_observation",
        "effective_access_claim",
        "fresh_session_claim",
        "file_content_read_claim",
    ):
        assert result[key] is False


def test_share_denial_is_not_ntfs_denial_and_absence_is_not_prevention():
    row = normalize([event(outcome="failure")])["events"][0]
    assert row["share_check"] == "denied" and row["server_logon"] == "missing"
    result = normalize([], completeness="complete")
    assert result["events"] == [] and result["effective_access_claim"] is False


@pytest.mark.parametrize(
    "fields",
    [
        {"SubjectUserSid": scope_row()["principals"]["controller"]["sid"]},
        {"SubjectUserSid": "S-1-5-21-9-8-7-1002"},
        {"IpAddress": "10.44.0.99"},
        {"ShareName": "\\\\*\\other"},
        {"ShareLocalPath": "\\??\\C:\\other"},
        {"RelativeTargetName": "..\\records.jsonl"},
        {"RelativeTargetName": "records.jsonl:stream"},
        {"RelativeTargetName": "sub\\records.jsonl"},
        {"ObjectType": "Directory"},
        {"SubjectLogonId": "0x0"},
    ],
)
def test_other_targets_do_not_match(fields):
    assert normalize([event(fields=fields)])["events"][0]["binding"] == "outside_scope"


@pytest.mark.parametrize(
    "field",
    [
        "SubjectUserSid",
        "SubjectLogonId",
        "IpAddress",
        "ShareName",
        "ShareLocalPath",
        "RelativeTargetName",
        "AccessMask",
        "ObjectType",
    ],
)
def test_missing_fields_are_incomplete_not_success(field):
    row = normalize([event(fields={field: None})])["events"][0]
    assert row["binding"] == "incomplete" and "share_check" not in row


@pytest.mark.parametrize(
    "fields",
    [
        {"LogonType": "9"},
        {"LogonType": "2"},
        {"AuthenticationPackageName": "Negotiate"},
        {"AuthenticationPackageName": "NTLM"},
    ],
)
def test_local_new_credentials_and_negotiate_are_not_server_kerberos(fields):
    row = normalize([event(4624, fields=fields), event()])["events"][1]
    assert row["server_logon"] == "not_verified_kerberos"


def test_duplicate_idempotence_and_conflict():
    raw = event()
    result = normalize([raw, raw])
    assert len(result["events"]) == 1 and result["duplicate_events"] == 1
    with pytest.raises(AdSmbError, match="conflicts"):
        normalize([raw, event(outcome="failure")])


def test_v2_record_identifiers_are_lossless_canonical_uint64_strings():
    maximum = 2**64 - 1
    result = normalize([event(4624, record_id=maximum - 1), event(record_id=maximum)])
    logon, share = result["events"]
    assert logon["record_id"] == str(maximum - 1)
    assert share["record_id"] == str(maximum)
    assert share["logon_record_id"] == str(maximum - 1)


@pytest.mark.parametrize("record_id", [0, 2**64])
def test_native_record_identifier_rejects_zero_and_uint64_overflow(record_id):
    with pytest.raises(AdSmbError):
        normalize([event(record_id=record_id)])


def test_reused_logon_identifier_and_late_logon_are_ambiguous():
    rows = [event(4624), event(4624, record_id=11), event()]
    assert normalize(rows)["events"][2]["server_logon"] == "ambiguous"
    assert (
        normalize([event(4624, when="2026-10-09T00:01:02.1234568Z"), event()])["events"][1][
            "server_logon"
        ]
        == "ambiguous"
    )
    assert (
        normalize([event(4624, record_id=21), event()])["events"][1]["server_logon"] == "ambiguous"
    )


def test_different_principal_with_same_logon_does_not_correlate():
    fields = {"TargetUserSid": scope_row()["principals"]["legitimate"]["sid"]}
    assert (
        normalize([event(4624, fields=fields), event()])["events"][1]["server_logon"] == "ambiguous"
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"fields": {"AuthenticationPackageName": None}},
        {"fields": {"TargetUserSid": None}},
        {"fields": {"IpAddress": None}},
        {"fields": {"LogonType": None}},
        {"fields": {"IpAddress": "10.44.0.99"}},
        {"fields": {"TargetUserSid": "S-1-5-21-9-8-7-1002"}},
        {"when": "2026-10-08T23:59:59Z"},
        {"when": "2026-10-09T00:30:00.0000001Z"},
    ],
)
def test_incomplete_and_outside_logon_collisions_remain_ambiguous(kwargs):
    rows = [event(4624), event(4624, record_id=11, **kwargs), event()]
    assert normalize(rows)["events"][2]["server_logon"] == "ambiguous"


def test_exact_windows_case_and_ipv4_mapped_representation():
    raw = event(
        computer="MEMBER.LAB.EXAMPLE",
        fields={"IpAddress": "::ffff:10.44.0.3", "RelativeTargetName": "RECORDS.JSONL"},
    )
    assert normalize([raw])["events"][0]["binding"] == "matched"


def test_preserves_non_data_access_without_claiming_read():
    row = normalize([event(fields={"AccessMask": "0x80"})])["events"][0]
    assert row["requests_file_data"] is False and row["share_check"] == "granted"


def test_outside_window_including_100ns_boundary():
    raw = event(when="2026-10-09T00:30:00.0000001Z")
    assert normalize([raw])["events"][0]["binding"] == "outside_scope"


@pytest.mark.parametrize("zeros", ["0", "00"])
def test_windows_extended_timestamp_spelling_preserves_exact_ticks(zeros):
    rows = [
        event(4624, when="2026-10-09T00:01:01.1234567" + zeros + "Z"),
        event(when="2026-10-09T00:01:02.1234567" + zeros + "Z"),
    ]
    assert normalize(rows)["events"][1]["server_logon"] == "kerberos_network"


@pytest.mark.parametrize("fraction", ["12345671", "123456701", "1234567000"])
def test_sub_100ns_or_excess_timestamp_precision_is_not_rounded(fraction):
    with pytest.raises(AdSmbError):
        normalize([event(when="2026-10-09T00:01:02." + fraction + "Z")])


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"<Event/>",
        b"\xff",
        b"x" * (MAX_EVENT_BYTES + 1),
        b'<!DOCTYPE Event [<!ENTITY x "secret">]><Event>&x;</Event>',
        b"<?evil instruction?><Event/>",
        b"<x>" * 10 + b"</x>" * 10,
    ],
    ids=["empty", "root", "encoding", "oversize", "doctype", "instruction", "depth"],
)
def test_untrusted_xml_is_bounded_and_dtd_free(raw):
    with pytest.raises(AdSmbError):
        normalize([raw])


@pytest.mark.parametrize(
    "raw",
    [
        b'<!DOCTYPE Event SYSTEM "https://example.invalid/events.dtd"><Event/>',
        b'<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///not-an-event">]><Event>&x;</Event>',
        b'<!DOCTYPE Event [<!ENTITY a "x"><!ENTITY b "&a;&a;">]><Event>&b;</Event>',
        b'<!DOCTYPE Event [<!ENTITY % x SYSTEM "https://example.invalid/entity">%x;]><Event/>',
        b'<?xml version="1.0"?><!DOCTYPE Event><Event/>',
        b"\xef\xbb\xbf<!DOCTYPE Event><Event/>",
        b"<!-- unsupported markup --><Event/>",
        b"<Event><![CDATA[unsupported content]]></Event>",
        "<!DOCTYPE Event><Event/>".encode("utf-16"),
    ],
    ids=[
        "external-dtd",
        "external-entity",
        "nested-entity",
        "parameter-entity",
        "xml-declaration",
        "utf8-bom",
        "comment",
        "cdata",
        "utf16",
    ],
)
def test_declarations_and_other_encodings_never_reach_xml_parser(raw, monkeypatch):
    def refused_parser(*args, **kwargs):
        pytest.fail("Unsupported markup reached XML parser construction")

    monkeypatch.setattr("bluefire.ad_smb_audit.ET.XMLParser", refused_parser)
    with pytest.raises(AdSmbError):
        normalize([raw])


def test_escaped_declaration_like_event_text_remains_plain_data():
    raw = event(fields={"SubjectUserName": "application <! unchanged"})
    assert b"&lt;!" in raw
    assert len(normalize([raw])["events"]) == 1


@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be", "utf-32le", "utf-32be"])
@pytest.mark.parametrize("declaration", ["", "<!DOCTYPE Event>"])
def test_bomless_wide_encodings_never_reach_parser(encoding, declaration, monkeypatch):
    raw = (declaration + event().decode("utf-8")).encode(encoding)

    def refused_parser(*args, **kwargs):
        pytest.fail("BOM-less wide encoding reached XML parser construction")

    monkeypatch.setattr("bluefire.ad_smb_audit.ET.XMLParser", refused_parser)
    with pytest.raises(AdSmbError):
        normalize([raw])


@pytest.mark.parametrize(
    "declaration",
    [
        b'<?xml version="1.0"?>',
        b'<?xml version="1.0" encoding="iso-8859-1"?>',
        b'<?xml version="1.0" encoding="UTF-8"?>',
    ],
)
def test_standalone_xml_declaration_never_reaches_parser(declaration, monkeypatch):
    raw = declaration + event()

    def refused_parser(*args, **kwargs):
        pytest.fail("XML declaration reached parser construction")

    monkeypatch.setattr("bluefire.ad_smb_audit.ET.XMLParser", refused_parser)
    with pytest.raises(AdSmbError):
        normalize([raw])


@pytest.mark.parametrize(
    "target,value",
    [
        ("EventID", "9999"),
        ("Version", "3"),
        ("Channel", "System"),
        ("EventRecordID", "0"),
        ("Keywords", "0x10000000000000000"),
        ("Computer", "client.lab.example"),
    ],
)
def test_source_and_system_bindings(target, value):
    root = ET.fromstring(event())
    root.find(NS + "System").find(NS + target).text = value
    with pytest.raises(AdSmbError):
        normalize([ET.tostring(root)])


def test_duplicate_named_fields_and_system_fields_refused():
    root = ET.fromstring(event())
    data = root.find(NS + "EventData")
    ET.SubElement(data, NS + "Data", Name="SubjectLogonId").text = "0x999"
    with pytest.raises(AdSmbError):
        normalize([ET.tostring(root)])
    root = ET.fromstring(event())
    ET.SubElement(root.find(NS + "System"), NS + "Channel").text = "Security"
    with pytest.raises(AdSmbError):
        normalize([ET.tostring(root)])


@pytest.mark.parametrize(
    "fields",
    [
        {"AccessMask": "0x100000000"},
        {"AccessMask": "-1"},
        {"SubjectLogonId": "0x10000000000000000"},
        {"SubjectUserSid": "S-1-5-21-01-2-3-1000"},
        {"IpAddress": "not-an-ip"},
    ],
)
def test_malformed_identity_and_access_fields_refused(fields):
    with pytest.raises(AdSmbError):
        normalize([event(fields=fields)])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"source_host_id": pin("3")},
        {"source_receipt_digest": "unbound"},
        {"capture_batch_digest": "unbound"},
        {"completeness": "verified"},
        {"window_start": "2026-10-08T23:59:59Z"},
        {"window_end": "2026-10-09T01:00:00Z"},
    ],
)
def test_collection_envelope_requires_exact_scope(kwargs):
    with pytest.raises(AdSmbError):
        normalize([], **kwargs)


def test_event_and_aggregate_byte_limits():
    with pytest.raises(AdSmbError):
        normalize([event()] * 1001)
    with pytest.raises(AdSmbError):
        normalize([b"x" * 65536] * 65)


def test_unneeded_identity_text_is_not_projected():
    raw = event(fields={"SubjectUserName": "private-user", "AccessReason": "untrusted-message"})
    result = normalize([raw])
    assert "private-user" not in str(result) and "untrusted-message" not in str(result)
    assert result["events"][0]["raw_sha256"].startswith("sha256:")


def test_unmatched_rows_do_not_expose_untrusted_client_address():
    row = normalize([event(fields={"IpAddress": "10.44.0.99"})])["events"][0]
    assert row["binding"] == "outside_scope"
    assert "client_ip" not in row


def test_correct_principal_on_out_of_scope_share_stays_unprojected():
    row = normalize([event(fields={"ShareName": "\\\\*\\other"})])["events"][0]
    assert row["binding"] == "outside_scope"
    assert not {"principal_role", "principal_sid", "client_ip"} & set(row)
