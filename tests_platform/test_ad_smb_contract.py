"""Synthetic AD scope tests, with no domain, identity or network effects."""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from bluefire.ad_smb_contract import (
    LIMIT_CEILINGS,
    AdSmbError,
    AdSmbReadTarget,
    AdSmbScope,
    document,
    sid,
    volume_serial_from_native,
)

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)
DOMAIN = "S-1-5-21-111-222-333"


def pin(char="a"):
    return "sha256:" + char * 64


def scope_row():
    identifier = "a" * 32
    return {
        "schema_version": "bluefire.ad-smb-scope.v1",
        "scope_id": identifier,
        "domain": {"dns": "lab.example", "sid": DOMAIN},
        "hosts": {
            role: {
                "host_id": pin(str(index)),
                "fqdn": role + ".lab.example",
                "ipv4": "10.44.0." + str(index),
                "os_product": "windows_client" if role == "client" else "windows_server_2022",
                "os_build": "10.0.22631.1000" if role == "client" else "10.0.20348.1000",
                "architecture": "x86_64",
                "identity_receipt_digest": pin("f"),
            }
            for index, role in enumerate(("dc", "member", "client"), 1)
        },
        "principals": {
            role: {
                "sid": DOMAIN + "-" + str(1000 + index),
                "kind": "domain_user",
                "credential_handle": "credential-" + str(index) * 32,
                "group_sids": [DOMAIN + "-513"],
                "sid_history": [],
                "identity_receipt_digest": pin("b"),
            }
            for index, role in enumerate(("controller", "probe", "legitimate"), 1)
        },
        "share": {
            "name": "bf_" + identifier,
            "local_root": "C:\\BlueFire\\AD\\" + identifier,
            "unc": "\\\\member.lab.example\\bf_" + identifier,
            "identity_digest": pin("c"),
            "root_file_id": "1" * 32,
            "volume_serial": "f123456789abcdef",
            "root_ntfs_digest": pin("d"),
            "baseline_descriptor_digest": pin("e"),
            "dfs": False,
            "administrative": False,
        },
        "files": [
            {
                "purpose": purpose,
                "name": name,
                "file_id": str(index + 2) * 32,
                "volume_serial": "f123456789abcdef",
                "sha256": pin(str(index + 4)),
                "size_bytes": 128,
                "records": 1,
                "ntfs_digest": pin(str(index + 6)),
            }
            for index, (purpose, name) in enumerate(
                (("primary", "records.jsonl"), ("health", "health.jsonl"))
            )
        ],
        "authentication": {
            "package": "Kerberos",
            "spn": "cifs/member.lab.example",
            "signing_required": True,
            "encryption_required": True,
            "ntlm_fallback": False,
            "mutual_authentication_required": True,
            "hardened_unc_receipt_digest": pin("a"),
        },
        "network": {
            "flows": [
                flow("client", "member", "tcp", 445),
                flow("client", "dc", "udp", 53),
                flow("client", "dc", "tcp", 88),
            ],
            "policy_receipt_digest": pin("a"),
            "kernel_traffic_metered": False,
        },
        "limits": dict(LIMIT_CEILINGS),
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=55)).isoformat(),
        "ownership_receipt_digest": pin("a"),
        "readiness_receipt_digest": pin("b"),
        "exclusive_writer_receipt_digest": pin("c"),
        "native_parser_digest": pin("d"),
    }


def flow(source, destination, transport, port, end=None):
    return {
        "source": source,
        "destination": destination,
        "transport": transport,
        "port_from": port,
        "port_through": port if end is None else end,
    }


def test_scope_roundtrip_canonical_detached_and_current():
    row = scope_row()
    original = copy.deepcopy(row)
    scope = AdSmbScope.from_mapping(row)
    assert row == original
    assert AdSmbScope.from_mapping(scope.to_dict()).digest == scope.digest
    row["share"]["name"] = "changed"
    assert scope.to_dict()["share"]["name"].startswith("bf_")
    scope.assert_current(lambda: NOW)
    reordered = original
    reordered["network"]["flows"].reverse()
    assert AdSmbScope.from_mapping(reordered).digest == scope.digest


@pytest.mark.parametrize("field", list(scope_row()))
def test_all_top_level_fields_required(field):
    row = scope_row()
    del row[field]
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize(
    "path,value",
    [
        (("domain", "sid"), "S-1-5-32-544"),
        (("domain", "dns"), "LAB.example"),
        (("hosts", "member", "fqdn"), "foreign.example"),
        (("hosts", "client", "ipv4"), "127.0.0.1"),
        (("hosts", "client", "ipv4"), "8.8.8.8"),
        (("hosts", "client", "ipv4"), "10.044.0.1"),
        (("hosts", "client", "ipv4"), "::1"),
        (("hosts", "dc", "os_build"), "10.0.17763.1000"),
        (("hosts", "dc", "architecture"), "arm64"),
        (("principals", "probe", "sid"), DOMAIN + "-500"),
        (("principals", "probe", "sid"), "S-1-5-21-999-222-333-1002"),
        (("principals", "probe", "kind"), "group"),
        (("principals", "probe", "credential_handle"), "plaintext-password"),
        (("principals", "probe", "group_sids"), [DOMAIN + "-512"]),
        (("principals", "probe", "group_sids"), ["S-1-5-32-544"]),
        (("principals", "probe", "sid_history"), [DOMAIN + "-500"]),
        (("principals", "probe", "group_sids"), [DOMAIN + "-513", DOMAIN + "-513"]),
        (("share", "name"), "C$"),
        (("share", "local_root"), "C:\\BlueFire\\AD\\..\\other"),
        (("share", "unc"), "\\\\other.lab.example\\share"),
        (("share", "dfs"), True),
        (("share", "administrative"), 0),
        (("authentication", "package"), "NTLM"),
        (("authentication", "spn"), "cifs/other.lab.example"),
        (("authentication", "ntlm_fallback"), True),
        (("authentication", "signing_required"), 1),
        (("authentication", "encryption_required"), False),
        (("network", "kernel_traffic_metered"), True),
    ],
)
def test_scope_widening_aliases_secrets_and_unknown_context_refused(path, value):
    row = scope_row()
    target = row
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize("field", ["host_id", "fqdn", "ipv4"])
def test_three_hosts_cannot_alias(field):
    row = scope_row()
    row["hosts"]["client"][field] = row["hosts"]["member"][field]
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize("field", ["sid", "credential_handle"])
def test_principals_and_credentials_cannot_alias(field):
    row = scope_row()
    row["principals"]["probe"][field] = row["principals"]["legitimate"][field]
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize("name", list(LIMIT_CEILINGS))
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1"])
def test_limits_are_positive_exact_integers(name, value):
    row = scope_row()
    row["limits"][name] = value
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize("name", list(LIMIT_CEILINGS))
def test_no_ceiling_can_be_raised(name):
    row = scope_row()
    row["limits"][name] += 1
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize(
    "extra",
    [
        flow("client", "member", "tcp", 5985),
        flow("member", "client", "tcp", 445),
        flow("client", "dc", "tcp", 1, 65535),
        flow("client", "dc", "tcp", 49152, 49408),
        flow("client", "dc", "udp", 636),
    ],
)
def test_network_is_not_remote_management_or_broad_port_authority(extra):
    row = scope_row()
    row["network"]["flows"].append(extra)
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


def test_bounded_explicit_rpc_allowed_but_overlap_missing_or_duplicate_refused():
    row = scope_row()
    row["network"]["flows"].append(flow("member", "dc", "tcp", 49152, 49200))
    AdSmbScope.from_mapping(row)
    row["network"]["flows"].append(flow("member", "dc", "tcp", 49190, 49210))
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)
    row = scope_row()
    row["network"]["flows"].append(row["network"]["flows"][0])
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)
    row = scope_row()
    row["network"]["flows"].pop()
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "../records.jsonl"),
        ("purpose", "other"),
        ("records", 33),
        ("size_bytes", 65536),
        ("size_bytes", True),
        ("file_id", "1" * 32),
        ("ntfs_digest", "unknown"),
    ],
)
def test_generated_files_remain_exact_and_bounded(field, value):
    row = scope_row()
    row["files"][0][field] = value
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize("offset", [-1, 3300, 3301])
def test_scope_expiry_and_not_before(offset):
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(scope_row()).assert_current(lambda: NOW + timedelta(seconds=offset))


@pytest.mark.parametrize(
    "value",
    ["S-1-5-21-01", "S-1-5-4294967296", "S-1-281474976710656-1", "BA", "S-1-5", "S-2-5-32-544"],
)
def test_numeric_sid_bounds_no_aliases(value):
    with pytest.raises(AdSmbError):
        sid(value)


@pytest.mark.parametrize(
    "value",
    [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b"\xff", b"[]", b"{", {"a": float("inf")}],
)
def test_strict_json_parser(value):
    with pytest.raises(AdSmbError):
        document(value)


def test_unknown_fields_and_raw_dataclass_bypass_are_not_admitted():
    row = scope_row()
    row["password"] = "SYNTHETIC-NOT-A-REAL-CREDENTIAL"
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("mutual_authentication_required", False),
        ("mutual_authentication_required", 1),
        ("hardened_unc_receipt_digest", None),
    ],
)
def test_kerberos_only_requires_explicit_hardened_unc_premise(field, value):
    row = scope_row()
    row["authentication"][field] = value
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


def test_phase_limits_and_peer_group_alias_are_refused():
    row = scope_row()
    row["limits"]["business_seconds"] = 30
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)
    row = scope_row()
    row["principals"]["controller"]["group_sids"] = [row["principals"]["probe"]["sid"]]
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)
    with pytest.raises(AdSmbError):
        AdSmbScope(b"{}").assert_current(lambda: NOW)
    row = scope_row()
    row["expires_at"] = (NOW + timedelta(hours=24)).isoformat()
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        42,
        -1,
        2**64,
        None,
        "",
        "0",
        "a" * 15,
        "a" * 17,
        "F123456789abcdef",
        "0xf123456789abcdef",
        "g" * 16,
    ],
)
@pytest.mark.parametrize("place", ["share", "primary", "health"])
def test_volume_serial_is_exact_browser_safe_u64_hex(place, value):
    row = scope_row()
    target = row["share"] if place == "share" else row["files"][place == "health"]
    target["volume_serial"] = value
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize("place", ["share", "primary", "health"])
def test_missing_volume_or_other_volume_never_infers_identity(place):
    row = scope_row()
    target = row["share"] if place == "share" else row["files"][place == "health"]
    del target["volume_serial"]
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)
    target["volume_serial"] = "0000000000000001"
    with pytest.raises(AdSmbError):
        AdSmbScope.from_mapping(row)


@pytest.mark.parametrize("volume", ["0000000000000000", "0020000000000001", "ffffffffffffffff"])
@pytest.mark.parametrize(
    "reader,purpose", [("probe", "primary"), ("legitimate", "primary"), ("legitimate", "health")]
)
def test_read_target_preserves_full_volume_and_never_fabricates_remote_or_local_identity(
    volume, reader, purpose
):
    row = scope_row()
    for target in [row["share"], *row["files"]]:
        target["volume_serial"] = volume
    scope = AdSmbScope.from_mapping(row)
    target = AdSmbReadTarget.from_scope(scope, reader=reader, purpose=purpose)
    projection = target.to_dict()
    native = target.native_target_arguments()
    assert projection["scope_digest"] == scope.digest
    assert projection["file"]["volume_serial"] == volume
    assert native == (
        "member.lab.example",
        "a" * 32,
        purpose,
        projection["file"]["file_id"],
        int(volume, 16),
        projection["file"]["sha256"],
        128,
    )
    assert projection["expected_remote_sid"] == row["principals"][reader]["sid"]
    assert not {
        "local_token_user_sid",
        "authentication_id",
        "credential_handle",
        "password",
    }.intersection(projection)
    assert projection["admission_verified"] is False
    assert projection["authenticated_remote_reader"] is False
    assert projection["effective_access_claim"] is False
    projection["file"]["volume_serial"] = "0000000000000000"
    assert target.to_dict()["file"]["volume_serial"] == volume


@pytest.mark.parametrize(
    "reader,purpose",
    [
        ("controller", "primary"),
        ("probe", "health"),
        ("legitimate", "../health.jsonl"),
        (None, "primary"),
    ],
)
def test_read_projection_refuses_other_recipes_and_revalidates_direct_construction(reader, purpose):
    scope = AdSmbScope.from_mapping(scope_row())
    with pytest.raises(AdSmbError):
        AdSmbReadTarget.from_scope(scope, reader=reader, purpose=purpose)
    with pytest.raises(AdSmbError):
        AdSmbReadTarget(scope, reader, purpose).native_target_arguments()


def test_read_projection_revalidates_scope_even_after_raw_dataclass_construction():
    with pytest.raises(AdSmbError):
        AdSmbReadTarget(AdSmbScope(b"{}"), "probe", "primary").native_target_arguments()


def test_volume_identity_changes_scope_and_projection_even_with_same_paths_ids_and_content():
    row = scope_row()
    first = AdSmbScope.from_mapping(row)
    for resource in [row["share"], *row["files"]]:
        resource["volume_serial"] = "f123456789abcdee"
    second = AdSmbScope.from_mapping(row)
    assert first.digest != second.digest
    left = AdSmbReadTarget.from_scope(first, reader="probe", purpose="primary")
    right = AdSmbReadTarget.from_scope(second, reader="probe", purpose="primary")
    assert left.native_target_arguments()[4] != right.native_target_arguments()[4]


@pytest.mark.parametrize("value", [0, 2**53 + 1, 2**63, 2**64 - 1])
def test_native_json_volume_normalizes_before_any_browser_roundtrip(value):
    parsed = document(b'{"volume_serial":' + str(value).encode("ascii") + b"}")
    safe = volume_serial_from_native(parsed["volume_serial"])
    assert safe == f"{value:016x}"
    assert int(safe, 16) == value


@pytest.mark.parametrize("value", [True, False, -1, 2**64, 1.0, "42", "000000000000002a", None])
def test_native_volume_normalizer_refuses_coercion_and_overflow(value):
    with pytest.raises(AdSmbError):
        volume_serial_from_native(value)
