"""Bounded Security-event normalization; imported XML is not independent evidence."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, NoReturn

from .ad_smb_contract import AdSmbError, AdSmbScope, digest, sid, timestamp

SCHEMA = "bluefire.ad-smb-audit-observation.v2"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
PROVIDER = "Microsoft-Windows-Security-Auditing"
PROVIDER_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
MAX_EVENT_BYTES = 65536
_SUCCESS = 0x0020000000000000
_FAILURE = 0x0010000000000000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class _Tree(ET.TreeBuilder):
    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.nodes = 0

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self.depth += 1
        self.nodes += 1
        if self.depth > 5 or self.nodes > 160 or len(attrs) > 8:
            raise AdSmbError("event XML exceeds structural bounds")
        return super().start(tag, attrs)

    def end(self, tag: str) -> ET.Element:
        self.depth -= 1
        return super().end(tag)

    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise AdSmbError("event XML document types are unsupported")

    def pi(self, target: str, text: str | None = None) -> NoReturn:
        raise AdSmbError("event XML processing instructions are unsupported")


def _children(element: ET.Element) -> dict[str, ET.Element]:
    if (element.text or "").strip():
        raise AdSmbError("event container contains unexpected text")
    result: dict[str, ET.Element] = {}
    for child in element:
        if not child.tag.startswith(NS) or (child.tail or "").strip():
            raise AdSmbError("event XML namespace or framing is unsupported")
        name = child.tag[len(NS) :]
        if name in result:
            raise AdSmbError("event XML contains duplicate fields")
        result[name] = child
    return result


def _text(element: ET.Element) -> str:
    if len(element) or element.attrib:
        raise AdSmbError("event field is not a plain leaf")
    result = element.text or ""
    if len(result) > 8192:
        raise AdSmbError("event field exceeds its bound")
    return result


def _uint(value: str, bits: int, *, hexadecimal: bool = False) -> int:
    pattern = r"0x[0-9a-fA-F]{1,16}" if hexadecimal else r"[0-9]{1,20}"
    if not re.fullmatch(pattern, value):
        raise AdSmbError("event integer is invalid")
    result = int(value, 16 if hexadecimal else 10)
    if result >= 2**bits:
        raise AdSmbError("event integer exceeds its bound")
    return result


def _ticks(value: datetime) -> int:
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 10000000 + delta.microseconds * 10


def _event_time(value: str) -> int:
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    if match is None:
        raise AdSmbError("event requires an exact UTC Windows timestamp")
    fraction = match[2] or ""
    if any(char != "0" for char in fraction[7:]):
        raise AdSmbError("event timestamp exceeds Windows 100ns precision")
    return _ticks(timestamp(match[1] + "Z")) + int(fraction[:7].ljust(7, "0"))


def _parse(raw: bytes) -> tuple[dict[str, Any], dict[str, str]]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_EVENT_BYTES:
        raise AdSmbError("event must be bounded UTF-8 XML bytes")
    try:
        text = raw.decode("utf-8-sig", errors="strict")
        # NULs can disguise BOM-less UTF-16/32 from the UTF-8 decode and markup checks.
        if "\x00" in text or "<!" in text or "<?" in text:
            raise AdSmbError("event XML encoding or declarations are unsupported")
        # Strict UTF-8, declaration refusal and the bounded target constrain both calls.
        parser = ET.XMLParser(target=_Tree())  # nosec B314
        root = ET.fromstring(text, parser=parser)  # nosec B314
    except (UnicodeError, ET.ParseError, RecursionError, ValueError):
        raise AdSmbError("event is not supported bounded XML") from None
    if root.tag != NS + "Event" or root.attrib:
        raise AdSmbError("event root is unsupported")
    children = _children(root)
    if set(children) != {"System", "EventData"}:
        raise AdSmbError("event requires System and EventData only")
    if children["System"].attrib or children["EventData"].attrib:
        raise AdSmbError("event container attributes are unsupported")
    system = _children(children["System"])
    required = {
        "Provider",
        "EventID",
        "Version",
        "Keywords",
        "TimeCreated",
        "EventRecordID",
        "Channel",
        "Computer",
    }
    if (
        not required
        <= set(system)
        <= required | {"Level", "Task", "Opcode", "Correlation", "Execution", "Security"}
    ):
        raise AdSmbError("event system fields are unsupported")
    provider = system["Provider"]
    if (
        len(provider)
        or (provider.text or "").strip()
        or set(provider.attrib) != {"Name", "Guid"}
        or provider.get("Name") != PROVIDER
        or provider.get("Guid", "").lower() != PROVIDER_GUID
        or _text(system["Channel"]) != "Security"
    ):
        raise AdSmbError("event is not from the Security auditing provider")
    event_id = _uint(_text(system["EventID"]), 16)
    version = _uint(_text(system["Version"]), 8)
    if (
        (event_id == 5145 and version != 0)
        or (event_id == 4624 and version not in (0, 1, 2))
        or event_id not in (5145, 4624)
    ):
        raise AdSmbError("event ID or version is unsupported")
    created = system["TimeCreated"]
    if len(created) or (created.text or "").strip() or set(created.attrib) != {"SystemTime"}:
        raise AdSmbError("event timestamp framing is invalid")
    observed = created.attrib["SystemTime"]
    keywords = _uint(_text(system["Keywords"]), 64, hexadecimal=True)
    outcome = {_SUCCESS: "success", _FAILURE: "failure"}.get(
        keywords & (_SUCCESS | _FAILURE), "unknown"
    )
    record = {
        "event_id": event_id,
        "version": version,
        "record_id": _uint(_text(system["EventRecordID"]), 64),
        "computer": _text(system["Computer"]),
        "observed_at": observed,
        "time_ticks": _event_time(observed),
        "audit_outcome": outcome,
        "raw_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }
    if record["record_id"] == 0:
        raise AdSmbError("event record ID must be positive")
    data: dict[str, str] = {}
    for child in children["EventData"]:
        if (
            child.tag != NS + "Data"
            or len(child)
            or set(child.attrib) != {"Name"}
            or (child.tail or "").strip()
        ):
            raise AdSmbError("event data field framing is invalid")
        name, value = child.attrib["Name"], child.text or ""
        if (
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", name)
            or name in data
            or len(value) > 8192
        ):
            raise AdSmbError("event data field is invalid or duplicated")
        data[name] = value
    if (children["EventData"].text or "").strip():
        raise AdSmbError("event data container contains unexpected text")
    return record, data


def _ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address)
    except ValueError:
        raise AdSmbError("event client address is invalid") from None


def _bind(
    row: dict[str, Any], data: dict[str, str], scope: dict[str, Any], start: int, end: int
) -> None:
    event_id = row["event_id"]
    sid_key, logon_key = (
        ("TargetUserSid", "TargetLogonId")
        if event_id == 4624
        else ("SubjectUserSid", "SubjectLogonId")
    )
    # Incomplete or out-of-window records can still contradict a source-local ID.
    if logon_key in data:
        row["logon_id"] = hex(_uint(data[logon_key], 64, hexadecimal=True))
    row["binding"] = "outside_scope"
    if not start <= row["time_ticks"] <= end:
        return
    required = {sid_key, logon_key, "IpAddress"}
    required |= (
        {"LogonType", "AuthenticationPackageName"}
        if event_id == 4624
        else {"ObjectType", "ShareName", "ShareLocalPath", "RelativeTargetName", "AccessMask"}
    )
    if not required <= data.keys():
        row["binding"] = "incomplete"
        return
    principal = sid(data[sid_key])
    role = next(
        (name for name, entry in scope["principals"].items() if entry["sid"] == principal), None
    )
    logon_id = _uint(data[logon_key], 64, hexadecimal=True)
    if role not in ("probe", "legitimate"):
        return
    # Windows uses this exact placeholder when no remote client address exists.
    if data["IpAddress"] == "-":
        return
    if _ip(data["IpAddress"]) != scope["hosts"]["client"]["ipv4"] or not logon_id:
        return
    if event_id == 4624:
        package = data["AuthenticationPackageName"]
        row.update(
            principal_role=role,
            principal_sid=principal,
            logon_id=hex(logon_id),
            client_ip=scope["hosts"]["client"]["ipv4"],
            logon_type=_uint(data["LogonType"], 32),
            authentication_package=(
                package if package in ("Kerberos", "NTLM", "Negotiate") else "other"
            ),
        )
        row["binding"] = "matched"
        row["kerberos_network_logon"] = (
            row["logon_type"] == 3
            and data["AuthenticationPackageName"] == "Kerberos"
            and row["audit_outcome"] == "success"
        )
        return
    share = scope["share"]
    if (
        data["ObjectType"] != "File"
        or data["ShareName"].casefold() != ("\\\\*\\" + share["name"]).casefold()
        or data["ShareLocalPath"].casefold() != ("\\??\\" + share["local_root"]).casefold()
    ):
        return
    target = next(
        (
            entry
            for entry in scope["files"]
            if entry["name"].casefold() == data["RelativeTargetName"].casefold()
        ),
        None,
    )
    if target is None:
        return
    mask = _uint(data["AccessMask"], 32, hexadecimal=True)
    row.update(
        binding="matched",
        principal_role=role,
        principal_sid=principal,
        logon_id=hex(logon_id),
        client_ip=scope["hosts"]["client"]["ipv4"],
        file_purpose=target["purpose"],
        relative_target=target["name"],
        access_mask=hex(mask),
        requests_file_data=bool(mask & 1),
    )
    row["share_check"] = {"success": "granted", "failure": "denied"}.get(
        row["audit_outcome"], "unknown"
    )


def normalize_events(
    scope: AdSmbScope,
    raw_events: list[bytes],
    *,
    source_host_id: str,
    source_receipt_digest: str,
    capture_batch_digest: str,
    window_start: str,
    window_end: str,
    completeness: str = "unknown",
) -> dict[str, Any]:
    """Join source-local logon IDs without claiming collection authenticity or reads."""
    scope = AdSmbScope.from_mapping(scope.to_dict())
    value = scope.to_dict()
    digest(source_receipt_digest)
    digest(capture_batch_digest)
    if source_host_id != value["hosts"]["member"]["host_id"]:
        raise AdSmbError("audit source must identify the exact member host")
    if completeness not in ("complete", "truncated", "incomplete", "unknown"):
        raise AdSmbError("audit completeness is unsupported")
    start, end = _ticks(timestamp(window_start)), _ticks(timestamp(window_end))
    if (
        not _ticks(timestamp(value["created_at"]))
        <= start
        < end
        <= _ticks(timestamp(value["expires_at"]))
    ):
        raise AdSmbError("audit window is outside the scoped lifetime")
    limits = value["limits"]
    if (
        not isinstance(raw_events, list)
        or len(raw_events) > limits["audit_events"]
        or any(type(raw) is not bytes for raw in raw_events)
    ):
        raise AdSmbError("audit input exceeds the finite event bound")
    if sum(len(raw) for raw in raw_events) > limits["audit_bytes"]:
        raise AdSmbError("audit input exceeds the aggregate byte bound")
    rows: list[dict[str, Any]] = []
    seen: dict[int, str] = {}
    duplicates = 0
    for raw in raw_events:
        row, data = _parse(raw)
        if row["computer"].casefold() != value["hosts"]["member"]["fqdn"].casefold():
            raise AdSmbError("audit event does not identify the exact member computer")
        if row["record_id"] in seen:
            if seen[row["record_id"]] != row["raw_sha256"]:
                raise AdSmbError("audit record ID conflicts inside the captured batch")
            duplicates += 1
            continue
        seen[row["record_id"]] = row["raw_sha256"]
        _bind(row, data, value, start, end)
        rows.append(row)
    for row in rows:
        if row["event_id"] != 5145 or row["binding"] != "matched":
            continue
        candidates = [
            entry
            for entry in rows
            if entry["event_id"] == 4624 and entry.get("logon_id") == row["logon_id"]
        ]
        row["server_logon"] = "missing" if not candidates else "ambiguous"
        if len(candidates) == 1:
            logon = candidates[0]
            if (
                logon["binding"] == "matched"
                and logon["principal_sid"] == row["principal_sid"]
                and logon["time_ticks"] <= row["time_ticks"]
                and logon["record_id"] < row["record_id"]
            ):
                row["server_logon"] = (
                    "kerberos_network"
                    if logon["kerberos_network_logon"]
                    else "not_verified_kerberos"
                )
                row["logon_record_id"] = logon["record_id"]
    for row in rows:
        row.pop("time_ticks")
        row["record_id"] = str(row["record_id"])
        if "logon_record_id" in row:
            row["logon_record_id"] = str(row["logon_record_id"])
    return {
        "schema_version": SCHEMA,
        "scope_digest": scope.digest,
        "source_host_id": source_host_id,
        "source_receipt_digest": source_receipt_digest,
        "capture_batch_digest": capture_batch_digest,
        "window_start": window_start,
        "window_end": window_end,
        "reported_completeness": completeness,
        "source_authenticity_verified": False,
        "log_continuity_verified": False,
        "independent_observation": False,
        "effective_access_claim": False,
        "fresh_session_claim": False,
        "file_content_read_claim": False,
        "input_events": len(raw_events),
        "input_bytes": sum(len(raw) for raw in raw_events),
        "duplicate_events": duplicates,
        "events": rows,
        "limitations": [
            "Source receipts and completeness are caller assertions until an enrolled collector verifies them.",
            "A 5145 success is a share access check, not proof of a successful NTFS read or returned bytes.",
            "A 5145 failure describes share-level denial; missing events cannot establish NTFS denial or prevention.",
            "A matching server logon does not bind an execution attempt or prove a newly created client session.",
        ],
    }
