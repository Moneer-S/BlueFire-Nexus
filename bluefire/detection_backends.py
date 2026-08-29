"""Authoritative and bounded execution adapters for detection candidates."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from dataclasses import dataclass, replace
from enum import Enum
from importlib import metadata
from time import monotonic
from typing import Any, Iterable, Mapping, Sequence

from .detection_backend_health import PYSIGMA_PIN as _PYSIGMA_PIN
from .detection_backend_health import (
    SQLITE_BACKEND_DISTRIBUTION as _SQLITE_BACKEND_DISTRIBUTION,
)
from .detection_backend_health import SQLITE_BACKEND_PIN as _SQLITE_BACKEND_PIN
from .detection_backend_health import YARA_PIN as _YARA_PIN
from .detection_backend_health import detection_backend_health
from .evidence import EvidenceProvenance


class DetectionError(ValueError):
    pass


class DetectionState(str, Enum):
    HYPOTHESIS = "hypothesis"
    PARSED = "parsed"
    FIXTURE_EXERCISED = "fixture_exercised"
    OBSERVED_EXERCISED = "observed_exercised"
    BENIGN_EVALUATED = "benign_evaluated"
    REJECTED = "rejected"


class DetectionBackendError(ValueError):
    """A bounded backend rejected a rule, query, fixture, or result."""


class DetectionBackendUnavailable(DetectionBackendError):
    pass


_MAX_QUERY_BYTES = 32 * 1024
_MAX_FIXTURES = 128
_MAX_TOTAL_FIXTURE_BYTES = 1024 * 1024
_MAX_FIELD_BYTES = 16 * 1024
_MAX_RESULT_ROWS = 128
_MAX_RESULT_FIELDS = 64
_MAX_RESULT_BYTES = 256 * 1024
_MAX_VM_STEPS = 250_000
_PROGRESS_GRANULARITY = 100
_QUERY_DEADLINE_SECONDS = 0.5
_FIXTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
# fmt: off
_EXECUTION_LIMITS = {
    "fixtures": _MAX_FIXTURES, "fixture_bytes": _MAX_TOTAL_FIXTURE_BYTES,
    "query_bytes": _MAX_QUERY_BYTES, "result_rows": _MAX_RESULT_ROWS,
    "result_fields": _MAX_RESULT_FIELDS, "result_bytes": _MAX_RESULT_BYTES,
    "vm_steps": _MAX_VM_STEPS, "deadline_ms": int(_QUERY_DEADLINE_SECONDS * 1000),
}
_SQLITE_LIMITS = ((sqlite3.SQLITE_LIMIT_LENGTH, _MAX_RESULT_BYTES), (sqlite3.SQLITE_LIMIT_SQL_LENGTH, _MAX_QUERY_BYTES),
    (sqlite3.SQLITE_LIMIT_COLUMN, _MAX_RESULT_FIELDS), (sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 32), (sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 1), (sqlite3.SQLITE_LIMIT_VDBE_OP, _MAX_VM_STEPS), (sqlite3.SQLITE_LIMIT_FUNCTION_ARG, 16), (sqlite3.SQLITE_LIMIT_ATTACHED, 0), (sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 4096), (sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 0))
SQLITE_LOG_FIELDS = tuple("""fixture_id timestamp EventID Channel Provider_Name Computer User Image OriginalFileName CommandLine
    ParentImage ParentCommandLine CurrentDirectory IntegrityLevel Hashes ProcessId ParentProcessId TargetFilename CreationUtcTime
    SourceIp SourcePort DestinationIp DestinationPort Protocol QueryName QueryStatus EventType TargetObject Details SubjectUserName
    TargetUserName LogonId Host Message artifact_type path content process.executable process.command_line process.parent.executable
    process.parent.command_line user.name host.name event.code event.category file.path source.ip source.port destination.ip
    destination.port network.transport registry.path registry.value""".split())
_FIELD_INDEX = {field.casefold(): field for field in SQLITE_LOG_FIELDS}
_QUOTED_FIELDS = ", ".join(f'"{field}"' for field in SQLITE_LOG_FIELDS)
_CREATE_LOGS_SQL = "CREATE TABLE logs (" + ", ".join(
    '"fixture_id" TEXT NOT NULL PRIMARY KEY' if field == "fixture_id" else f'"{field}"' for field in SQLITE_LOG_FIELDS
) + ") WITHOUT ROWID"
# Identifiers are fixed module constants; every record value uses a placeholder.
_INSERT_LOG_SQL = f"INSERT INTO logs ({_QUOTED_FIELDS}) VALUES (" + ", ".join("?" for _ in SQLITE_LOG_FIELDS) + ")"  # nosec B608
_SQL_KEYWORDS = frozenset("""all and as asc between blob by case cast collate desc distinct else end escape false from glob group
    having in integer is like limit not null numeric offset or order real select text then true when where""".split())
_FORBIDDEN_SQL = frozenset("""alter analyze attach begin commit create delete detach drop except insert intersect into join
    load_extension pragma reindex release replace returning rollback savepoint trigger union update vacuum view virtual with""".split())
_ALLOWED_FUNCTIONS = frozenset("abs avg coalesce count glob ifnull instr length like lower max min nullif round substr sum total upper".split())
# fmt: on


@dataclass(frozen=True, slots=True)
class _SQLToken:
    kind: str
    value: str


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _package_version(distribution: str, pin: str) -> str:
    try:
        version = metadata.version(distribution)
    except metadata.PackageNotFoundError as exc:
        raise DetectionBackendUnavailable(
            f"{distribution} is unavailable; install {distribution}=={pin}"
        ) from exc
    if version != pin:
        raise DetectionBackendUnavailable(
            f"{distribution} version {version} is not reviewed; install {distribution}=={pin}"
        )
    return version


def _scan_sql(query: str) -> list[_SQLToken]:
    tokens: list[_SQLToken] = []
    index = 0
    while index < len(query):
        character = query[index]
        if character.isspace():
            index += 1
            continue
        if query.startswith("--", index) or query.startswith("/*", index):
            raise DetectionBackendError("SQLite comments are not allowed")
        if character in {"'", '"', "`", "["}:
            closing = "]" if character == "[" else character
            kind = "literal" if character == "'" else "identifier"
            index += 1
            value: list[str] = []
            while index < len(query):
                current = query[index]
                if current == closing:
                    if index + 1 < len(query) and query[index + 1] == closing:
                        value.append(closing)
                        index += 2
                        continue
                    index += 1
                    break
                if ord(current) < 32:
                    raise DetectionBackendError("SQLite query contains a control character")
                value.append(current)
                index += 1
            else:
                raise DetectionBackendError("SQLite query contains an unterminated quoted value")
            if kind == "identifier" and not value:
                raise DetectionBackendError("SQLite query contains an empty identifier")
            tokens.append(_SQLToken(kind, "".join(value)))
            continue
        if character.isascii() and (character.isalpha() or character == "_"):
            start = index
            index += 1
            while (
                index < len(query)
                and query[index].isascii()
                and (query[index].isalnum() or query[index] in {"_", "$"})
            ):
                index += 1
            tokens.append(_SQLToken("word", query[start:index]))
            continue
        if character.isascii() and character.isdigit():
            start = index
            index += 1
            while (
                index < len(query)
                and query[index].isascii()
                and (query[index].isdigit() or query[index] in {".", "e", "E"})
            ):
                index += 1
            tokens.append(_SQLToken("number", query[start:index]))
            continue
        if character in "(),.*=<>!+-/%|&~;":
            tokens.append(_SQLToken("symbol", character))
            index += 1
            continue
        raise DetectionBackendError("SQLite query contains an unsupported token")
    return tokens


def inspect_sqlite_query(query: str) -> Mapping[str, Any]:
    if not isinstance(query, str) or not query.strip():
        raise DetectionBackendError("SQLite query is required")
    if "\x00" in query or len(query.encode("utf-8")) > _MAX_QUERY_BYTES:
        raise DetectionBackendError("SQLite query is invalid or exceeds the byte limit")
    tokens = _scan_sql(query)
    semicolons = [index for index, token in enumerate(tokens) if token.value == ";"]
    if semicolons:
        if len(semicolons) != 1 or semicolons[0] != len(tokens) - 1:
            raise DetectionBackendError("exactly one SQLite SELECT statement is required")
        tokens = tokens[:-1]
    words = [token.value.casefold() for token in tokens if token.kind == "word"]
    if not tokens or tokens[0].kind != "word" or tokens[0].value.casefold() != "select":
        raise DetectionBackendError("SQLite source must be exactly one SELECT")
    if words.count("select") != 1:
        raise DetectionBackendError("exactly one SQLite SELECT statement is required")
    forbidden = sorted(set(words) & _FORBIDDEN_SQL)
    if forbidden:
        raise DetectionBackendError("SQLite query contains forbidden SQL: " + forbidden[0])
    from_indexes = [
        index
        for index, token in enumerate(tokens)
        if token.kind == "word" and token.value.casefold() == "from"
    ]
    if len(from_indexes) != 1 or from_indexes[0] + 1 >= len(tokens):
        raise DetectionBackendError("SQLite query must read the fixed logs table")
    table = tokens[from_indexes[0] + 1]
    if table.kind not in {"word", "identifier"} or table.value.casefold() != "logs":
        raise DetectionBackendError("SQLite query must read the fixed logs table")
    # fmt: off
    projection = tokens[1:from_indexes[0]]
    if not (len(projection) == 1 and projection[0].value == "*"):
        if not projection or len(projection) % 2 == 0 or any(token.value != "," for token in projection[1::2]):
            raise DetectionBackendError("SQLite SELECT projection must contain bare fields")
        projected_fields = [_FIELD_INDEX.get(token.value.casefold()) if token.kind in {"word", "identifier"} else None for token in projection[::2]]
        if None in projected_fields or len(set(projected_fields)) != len(projected_fields):
            raise DetectionBackendError("SQLite SELECT projection fields are invalid")
        if projected_fields.count("fixture_id") != 1:
            raise DetectionBackendError("SQLite SELECT must output fixture_id exactly once")
    # fmt: on
    following_index = from_indexes[0] + 2
    if following_index < len(tokens):
        following = tokens[following_index]
        if following.kind != "word" or following.value.casefold() not in {
            "where",
            "group",
            "having",
            "order",
            "limit",
        }:
            raise DetectionBackendError("SQLite table aliases and joins are not allowed")
    mapped: set[str] = set()
    unsupported: set[str] = set()
    for index, token in enumerate(tokens):
        if token.kind not in {"word", "identifier"}:
            continue
        lowered = token.value.casefold()
        previous = tokens[index - 1].value.casefold() if index else ""
        following = tokens[index + 1].value if index + 1 < len(tokens) else ""
        if (
            lowered in _SQL_KEYWORDS
            or lowered == "logs"
            or previous in {"as", "collate"}
            or following == "("
        ):
            continue
        canonical = _FIELD_INDEX.get(lowered)
        if canonical is None:
            unsupported.add(token.value)
        else:
            mapped.add(canonical)
    for index, token in enumerate(tokens[:-1]):
        if token.kind in {"word", "identifier"} and tokens[index + 1].value == "(":
            function = token.value.casefold()
            if function not in _ALLOWED_FUNCTIONS and function not in _SQL_KEYWORDS:
                raise DetectionBackendError("SQLite function is not allowed: " + token.value)
    stable_query = query.strip()
    mapped_fields = sorted(mapped)
    return {
        "query": stable_query,
        "query_sha256": _sha256_text(stable_query),
        "mapped_fields": mapped_fields,
        "field_mapping": {field: field for field in mapped_fields},
        "unsupported_fields": sorted(unsupported),
    }


def convert_sigma_to_sqlite(source: str) -> Mapping[str, Any]:
    """Parse one Sigma rule and convert it through the real SQLite backend."""

    pysigma_version = _package_version("pysigma", _PYSIGMA_PIN)
    backend_version = _package_version(_SQLITE_BACKEND_DISTRIBUTION, _SQLITE_BACKEND_PIN)
    try:
        from sigma.backends.sqlite import sqliteBackend
        from sigma.collection import SigmaCollection
    except ImportError as exc:
        raise DetectionBackendUnavailable(
            "pySigma SQLite backend is unavailable; install "
            f"{_SQLITE_BACKEND_DISTRIBUTION}=={_SQLITE_BACKEND_PIN}"
        ) from exc
    try:
        collection = SigmaCollection.from_yaml(source, collect_errors=True)
    except Exception as exc:
        raise DetectionBackendError(f"pySigma rejected the rule: {type(exc).__name__}") from exc
    errors = [str(error)[:300] for error in collection.errors]
    for rule in collection.rules:
        errors.extend(str(error)[:300] for error in rule.errors)
    if errors or len(collection.rules) != 1:
        reason = errors[0] if errors else "exactly one Sigma rule is required"
        raise DetectionBackendError("pySigma rejected the rule: " + reason)
    try:
        backend = sqliteBackend()
        backend.table = "logs"
        queries = backend.convert(collection, output_format="default")
    except Exception as exc:
        raise DetectionBackendError(
            f"pySigma SQLite conversion failed: {type(exc).__name__}"
        ) from exc
    if not isinstance(queries, Sequence) or isinstance(queries, (str, bytes)) or len(queries) != 1:
        raise DetectionBackendError("pySigma SQLite backend must emit exactly one query")
    if not isinstance(queries[0], str):
        raise DetectionBackendError("pySigma SQLite backend emitted a non-text query")
    inspection = inspect_sqlite_query(queries[0])
    return {
        "backend": "pySigma",
        "version": pysigma_version,
        "conversion_backend": "pySigma SQLite",
        "conversion_backend_version": backend_version,
        "conversion_table": "logs",
        "rule_count": 1,
        "errors": [],
        "source_sha256": _sha256_text(source),
        "converted_query": inspection["query"],
        **{key: value for key, value in inspection.items() if key != "query"},
    }


def _flatten_fixture(
    value: Mapping[str, Any],
    *,
    prefix: str = "",
    depth: int = 0,
) -> list[tuple[str, Any]]:
    if depth > 4 or len(value) > 256:
        raise DetectionBackendError("SQLite fixture nesting or field count exceeds its limit")
    rows: list[tuple[str, Any]] = []
    for raw_key, item in value.items():
        if not isinstance(raw_key, str) or not raw_key or len(raw_key) > 200 or "\x00" in raw_key:
            raise DetectionBackendError("SQLite fixture contains an invalid field name")
        key = f"{prefix}.{raw_key}" if prefix else raw_key
        if isinstance(item, Mapping):
            rows.extend(_flatten_fixture(item, prefix=key, depth=depth + 1))
        else:
            rows.append((key, item))
    return rows


def _sqlite_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise DetectionBackendError("SQLite fixture integer exceeds the signed 64-bit range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DetectionBackendError("SQLite fixture numbers must be finite")
        return value
    if isinstance(value, str):
        if "\x00" in value or len(value.encode("utf-8")) > _MAX_FIELD_BYTES:
            raise DetectionBackendError("SQLite fixture field exceeds its byte limit")
        return value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        try:
            encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError) as exc:
            raise DetectionBackendError("SQLite fixture arrays must contain finite JSON") from exc
        if len(encoded.encode("utf-8")) > _MAX_FIELD_BYTES:
            raise DetectionBackendError("SQLite fixture field exceeds its byte limit")
        return encoded
    raise DetectionBackendError("SQLite fixtures support only scalar or array field values")


def _prepare_fixtures(
    fixtures: Sequence[Mapping[str, Any]],
) -> tuple[list[str], list[tuple[Any, ...]], list[str], list[str]]:
    if isinstance(fixtures, (str, bytes)) or not isinstance(fixtures, Sequence):
        raise DetectionBackendError("SQLite fixtures must be a sequence")
    if len(fixtures) > _MAX_FIXTURES:
        raise DetectionBackendError("SQLite fixture count exceeds its limit")
    fixture_ids: list[str] = []
    inserts: list[tuple[Any, ...]] = []
    mapped_fields: set[str] = set()
    unsupported_fields: set[str] = set()
    total_bytes = 0
    for fixture in fixtures:
        if not isinstance(fixture, Mapping):
            raise DetectionBackendError("each SQLite fixture must be an object")
        raw_id = fixture.get("fixture_id")
        if not isinstance(raw_id, str) or _FIXTURE_ID.fullmatch(raw_id) is None:
            raise DetectionBackendError("each SQLite fixture requires a valid fixture_id")
        if raw_id in fixture_ids:
            raise DetectionBackendError("SQLite fixture IDs must be unique")
        values: dict[str, Any] = {"fixture_id": raw_id}
        for raw_field, raw_value in _flatten_fixture(fixture):
            if raw_field == "fixture_id":
                continue
            canonical = _FIELD_INDEX.get(raw_field.casefold())
            if canonical is None:
                unsupported_fields.add(raw_field)
                continue
            if canonical in values:
                raise DetectionBackendError("SQLite fixture maps more than once to a field")
            values[canonical] = _sqlite_value(raw_value)
            mapped_fields.add(canonical)
        row = tuple(values.get(field) for field in SQLITE_LOG_FIELDS)
        total_bytes += sum(
            len(item.encode("utf-8")) if isinstance(item, str) else 16
            for item in row
            if item is not None
        )
        if total_bytes > _MAX_TOTAL_FIXTURE_BYTES:
            raise DetectionBackendError("SQLite fixtures exceed the total byte limit")
        fixture_ids.append(raw_id)
        inserts.append(row)
    return fixture_ids, inserts, sorted(mapped_fields), sorted(unsupported_fields)


def _configure_limits(connection: sqlite3.Connection) -> None:
    for category, limit in _SQLITE_LIMITS:
        connection.setlimit(category, limit)


def _sqlite_authorizer(
    action: int,
    first: str | None,
    second: str | None,
    _database: str | None,
    _trigger: str | None,
) -> int:
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        if first == "logs" and (not second or second.casefold() in _FIELD_INDEX):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        function = (second or first or "").casefold()
        return sqlite3.SQLITE_OK if function in _ALLOWED_FUNCTIONS else sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY


def execute_sqlite_query(
    query: str,
    fixtures: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Execute one reviewed SELECT against a fresh, bounded in-memory database."""

    inspection = inspect_sqlite_query(query)
    if inspection["unsupported_fields"]:
        raise DetectionBackendError(
            "SQLite query references unsupported fields: "
            + ", ".join(inspection["unsupported_fields"])
        )
    fixture_ids, inserts, mapped_fixture_fields, unsupported_fixture_fields = _prepare_fixtures(
        fixtures
    )
    connection = sqlite3.connect(":memory:", isolation_level=None, timeout=0.0)
    progress_calls = 0
    deadline = monotonic() + _QUERY_DEADLINE_SECONDS

    def progress() -> int:
        nonlocal progress_calls
        progress_calls += 1
        if progress_calls * _PROGRESS_GRANULARITY > _MAX_VM_STEPS:
            return 1
        return int(monotonic() > deadline)

    try:
        connection.enable_load_extension(False)
        connection.execute(_CREATE_LOGS_SQL)
        connection.executemany(_INSERT_LOG_SQL, inserts)
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        _configure_limits(connection)
        connection.set_authorizer(_sqlite_authorizer)
        connection.set_progress_handler(progress, _PROGRESS_GRANULARITY)
        try:
            cursor = connection.execute(str(inspection["query"]))
            description = cursor.description or ()
            if not 1 <= len(description) <= _MAX_RESULT_FIELDS:
                raise DetectionBackendError("SQLite result field count exceeds its limit")
            result_fields = [str(column[0]) for column in description]
            fixture_columns = [
                index
                for index, field in enumerate(result_fields)
                if field.casefold() == "fixture_id"
            ]
            if len(fixture_columns) != 1:
                raise DetectionBackendError("SQLite SELECT must output fixture_id exactly once")
            rows = cursor.fetchmany(_MAX_RESULT_ROWS + 1)
        except sqlite3.DatabaseError as exc:
            message = str(exc).casefold()
            if "interrupted" in message:
                raise DetectionBackendError("SQLite query exceeded its execution budget") from exc
            if "authorized" in message:
                raise DetectionBackendError("SQLite authorizer denied the query") from exc
            raise DetectionBackendError("SQLite query failed: " + str(exc)[:200]) from exc
        if len(rows) > _MAX_RESULT_ROWS:
            raise DetectionBackendError("SQLite result row count exceeds its limit")
        known_ids = set(fixture_ids)
        matched_ids: list[str] = []
        result_bytes = sum(len(field.encode("utf-8")) for field in result_fields)
        fixture_column = fixture_columns[0]
        for row in rows:
            result_bytes += sum(
                len(value) if isinstance(value, bytes) else len(str(value).encode("utf-8"))
                for value in row
                if value is not None
            )
            if result_bytes > _MAX_RESULT_BYTES:
                raise DetectionBackendError("SQLite result bytes exceed the limit")
            fixture_id = row[fixture_column]
            if not isinstance(fixture_id, str) or fixture_id not in known_ids:
                raise DetectionBackendError("SQLite result contains an unknown fixture_id")
            if fixture_id in matched_ids:
                raise DetectionBackendError("SQLite result contains a duplicate fixture_id")
            matched_ids.append(fixture_id)
        return {
            "fixture_ids": fixture_ids,
            "matched_fixture_ids": matched_ids,
            "query_sha256": inspection["query_sha256"],
            "mapped_fields": list(inspection["mapped_fields"]),
            "mapped_fixture_fields": mapped_fixture_fields,
            "unsupported_fixture_fields": unsupported_fixture_fields,
            "result_fields": result_fields,
            "row_count": len(rows),
            "sqlite_version": sqlite3.sqlite_version,
            "query_only": True,
            "authorizer": True,
            "limits": dict(_EXECUTION_LIMITS),
        }
    finally:
        connection.set_progress_handler(None, 0)
        connection.set_authorizer(None)
        connection.close()


class ExternalDetectionValidator:
    """Authoritative parsers plus a bounded local SQLite execution boundary."""

    max_source_bytes = 256 * 1024
    max_fixture_bytes = 1024 * 1024

    @staticmethod
    def health() -> Mapping[str, Mapping[str, Any]]:
        return detection_backend_health()

    def parse_sigma(self, candidate: Any, source: str) -> Any:
        self._require_hypothesis(candidate, "sigma")
        source = self._source(source)
        details: dict[str, Any] = {}
        try:
            conversion = dict(convert_sigma_to_sqlite(source))
            details.update(conversion)
            if conversion["unsupported_fields"]:
                raise DetectionBackendError(
                    "SQLite backend emitted unsupported fields: "
                    + ", ".join(conversion["unsupported_fields"])
                )
            dry_run = execute_sqlite_query(str(conversion["converted_query"]), ())
        except DetectionBackendUnavailable as exc:
            raise DetectionError(str(exc) + "; candidate remains a hypothesis") from exc
        except DetectionBackendError as exc:
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason=str(exc)[:1000],
                validation={
                    **details,
                    "backend": "pySigma",
                    "errors": [str(exc)[:300]],
                    "source_sha256": _sha256_text(source),
                    "source_rule_executed": False,
                },
            )
        conversion.update(
            query_compiled=True,
            dry_run_result_fields=dry_run["result_fields"],
            source_rule_executed=False,
        )
        return candidate.transition(
            DetectionState.PARSED,
            rule_source=source,
            parser_backend={
                "name": "pySigma",
                "version": str(conversion["version"]),
                "conversion_backend": str(conversion["conversion_backend"]),
                "conversion_backend_version": str(conversion["conversion_backend_version"]),
            },
            validation=conversion,
        )

    def parse_sqlite(self, candidate: Any, source: str) -> Any:
        self._require_hypothesis(candidate, "sqlite")
        source = self._source(source)
        details: dict[str, Any] = {}
        try:
            inspection = inspect_sqlite_query(source)
            details = {
                "converted_query": inspection["query"],
                **{key: value for key, value in inspection.items() if key != "query"},
            }
            if inspection["unsupported_fields"]:
                raise DetectionBackendError(
                    "SQLite query references unsupported fields: "
                    + ", ".join(inspection["unsupported_fields"])
                )
            dry_run = execute_sqlite_query(source, ())
        except DetectionBackendError as exc:
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason=str(exc)[:1000],
                validation={
                    **details,
                    "backend": "SQLite bounded executor",
                    "version": sqlite3.sqlite_version,
                    "errors": [str(exc)[:300]],
                    "source_sha256": _sha256_text(source),
                    "source_rule_executed": False,
                },
            )
        validation = {
            "backend": "SQLite bounded executor",
            "version": sqlite3.sqlite_version,
            "conversion_table": "logs",
            "errors": [],
            "source_sha256": _sha256_text(source),
            "converted_query": inspection["query"],
            **{key: value for key, value in inspection.items() if key != "query"},
            "query_compiled": True,
            "dry_run_result_fields": dry_run["result_fields"],
            "source_rule_executed": False,
        }
        return candidate.transition(
            DetectionState.PARSED,
            rule_source=source,
            parser_backend={"name": "SQLite bounded executor", "version": sqlite3.sqlite_version},
            validation=validation,
        )

    def exercise_query_fixtures(self, candidate: Any, fixtures: Sequence[Mapping[str, Any]]) -> Any:
        if candidate.state is not DetectionState.PARSED:
            raise DetectionError("query candidate must be parsed before fixture exercise")
        result = self._execute_candidate_query(candidate, fixtures)
        fixture_ids = tuple(result["fixture_ids"])
        matched_ids = tuple(result["matched_fixture_ids"])
        validation = self._execution_validation(
            candidate,
            result,
            evaluated_fixture_ids=list(fixture_ids),
            matched_fixture_ids=list(matched_ids),
        )
        if not matched_ids:
            return candidate.transition(
                DetectionState.REJECTED,
                malicious_fixture_ids=fixture_ids,
                rejection_reason="executed query did not match a malicious fixture",
                validation=validation,
            )
        return candidate.transition(
            DetectionState.FIXTURE_EXERCISED,
            malicious_fixture_ids=fixture_ids,
            match_count=len(matched_ids),
            validation=validation,
        )

    def exercise_query_observed(self, candidate: Any, records: Sequence[Any]) -> Any:
        if candidate.state not in {DetectionState.PARSED, DetectionState.FIXTURE_EXERCISED}:
            raise DetectionError("query candidate must be parsed before observed exercise")
        observed = [
            record for record in records if record.provenance is EvidenceProvenance.OBSERVED
        ]
        fixtures = [dict(record.content, fixture_id=record.evidence_id) for record in observed]
        result = self._execute_candidate_query(candidate, fixtures)
        matched_ids = tuple(result["matched_fixture_ids"])
        observed_fields = tuple(result["mapped_fixture_fields"])
        predicted_fields = tuple(candidate.validation.get("mapped_fields", ()))
        drift = self.field_drift(predicted_fields, observed_fields)
        validation = self._execution_validation(
            candidate,
            result,
            evaluated_evidence_ids=list(result["fixture_ids"]),
            matched_evidence_ids=list(matched_ids),
        )
        if not matched_ids:
            return replace(
                candidate, observed_fields=observed_fields, field_drift=drift, validation=validation
            )
        return candidate.transition(
            DetectionState.OBSERVED_EXERCISED,
            observed_evidence_ids=matched_ids,
            match_count=candidate.match_count + len(matched_ids),
            observed_fields=observed_fields,
            field_drift=drift,
            validation=validation,
        )

    def evaluate_query_benign(
        self,
        candidate: Any,
        fixtures: Sequence[Mapping[str, Any]],
        *,
        notes: Iterable[str] = (),
    ) -> Any:
        if candidate.state not in {
            DetectionState.FIXTURE_EXERCISED,
            DetectionState.OBSERVED_EXERCISED,
        }:
            raise DetectionError("query candidate must be exercised before benign evaluation")
        result = self._execute_candidate_query(candidate, fixtures)
        return candidate.transition(
            DetectionState.BENIGN_EVALUATED,
            benign_fixture_ids=tuple(result["fixture_ids"]),
            benign_match_count=len(result["matched_fixture_ids"]),
            false_positive_notes=tuple(notes),
            validation=self._execution_validation(
                candidate,
                result,
                benign_evaluated_fixture_ids=list(result["fixture_ids"]),
                benign_matched_fixture_ids=list(result["matched_fixture_ids"]),
            ),
        )

    def _execute_candidate_query(
        self, candidate: Any, fixtures: Sequence[Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        if candidate.target_language not in {"sigma", "sqlite"} or not candidate.rule_source:
            raise DetectionError("candidate has no executable query source")
        try:
            if candidate.target_language == "sigma":
                conversion = convert_sigma_to_sqlite(candidate.rule_source)
                query = str(conversion["converted_query"])
                digest = str(conversion["query_sha256"])
                bound = (
                    "source_sha256",
                    "version",
                    "conversion_backend",
                    "conversion_backend_version",
                    "query_sha256",
                )
                if any(candidate.validation.get(key) != conversion.get(key) for key in bound):
                    raise DetectionBackendError(
                        "persisted Sigma conversion metadata does not match fresh conversion"
                    )
                if candidate.parser_backend != {
                    "name": "pySigma",
                    "version": conversion["version"],
                    "conversion_backend": conversion["conversion_backend"],
                    "conversion_backend_version": conversion["conversion_backend_version"],
                }:
                    raise DetectionBackendError("persisted Sigma parser metadata is invalid")
            else:
                inspection = inspect_sqlite_query(candidate.rule_source)
                query = str(inspection["query"])
                digest = str(inspection["query_sha256"])
                if (
                    candidate.validation.get("source_sha256") != _sha256_text(candidate.rule_source)
                    or candidate.validation.get("version") != sqlite3.sqlite_version
                    or candidate.validation.get("backend") != "SQLite bounded executor"
                    or candidate.parser_backend
                    != {"name": "SQLite bounded executor", "version": sqlite3.sqlite_version}
                ):
                    raise DetectionBackendError("persisted SQLite parser metadata is invalid")
            if digest != candidate.validation.get("query_sha256"):
                raise DetectionBackendError(
                    "persisted query digest does not match fresh conversion"
                )
            result = execute_sqlite_query(query, fixtures)
        except DetectionBackendError as exc:
            raise DetectionError(str(exc)) from exc
        if result["query_sha256"] != digest:
            raise DetectionError("executed query digest does not match fresh conversion")
        return result

    @staticmethod
    def _execution_validation(candidate: Any, result: Mapping[str, Any], **ids: Any) -> dict:
        return {
            **dict(candidate.validation),
            "source_rule_executed": True,
            "executed_query_sha256": result["query_sha256"],
            "execution_backend": "SQLite in-memory bounded executor",
            "execution_backend_version": result["sqlite_version"],
            "last_execution": dict(result),
            **ids,
        }

    def compile_yara(self, candidate: Any, source: str) -> Any:
        if candidate.target_language != "yara":
            raise DetectionError("candidate language must be yara")
        if candidate.state is not DetectionState.HYPOTHESIS:
            raise DetectionError("only a hypothesis can be compiled")
        source = self._source(source)
        try:
            version = _package_version("yara-python", _YARA_PIN)
        except DetectionBackendUnavailable as exc:
            raise DetectionError(str(exc) + "; candidate remains a hypothesis") from exc
        try:
            import yara
        except ImportError as exc:
            raise DetectionError(
                "YARA-Python is unavailable; candidate remains a hypothesis"
            ) from exc
        try:
            yara.compile(source=source, includes=False, error_on_warning=True)
        except yara.Error as exc:
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason="YARA rejected the rule",
                validation={"backend": "YARA-Python", "errors": [str(exc)[:300]]},
            )
        return candidate.transition(
            DetectionState.PARSED,
            rule_source=source,
            parser_backend={"name": "YARA-Python", "version": version},
            validation={
                "backend": "YARA-Python",
                "version": version,
                "compiled": True,
                "includes": False,
                "warnings_as_errors": True,
                "source_sha256": _sha256_text(source),
                "source_rule_executed": False,
            },
        )

    def exercise_yara_fixtures(self, candidate: Any, fixtures: Sequence[Mapping[str, Any]]) -> Any:
        if candidate.state is not DetectionState.PARSED or not candidate.rule_source:
            raise DetectionError("YARA candidate must be compiled before fixture exercise")
        fixture_ids, matched_ids = self._yara_matches(candidate, fixtures)
        validation = self._yara_execution_validation(
            candidate, fixture_ids, matched_ids, "evaluated_fixture_ids", "matched_fixture_ids"
        )
        if not matched_ids:
            return candidate.transition(
                DetectionState.REJECTED,
                malicious_fixture_ids=tuple(fixture_ids),
                rejection_reason="compiled YARA rule did not match a malicious fixture",
                validation=validation,
            )
        return candidate.transition(
            DetectionState.FIXTURE_EXERCISED,
            malicious_fixture_ids=tuple(fixture_ids),
            match_count=len(matched_ids),
            validation=validation,
        )

    def evaluate_yara_benign(
        self,
        candidate: Any,
        fixtures: Sequence[Mapping[str, Any]],
        *,
        notes: Iterable[str] = (),
    ) -> Any:
        if (
            candidate.state
            not in {DetectionState.FIXTURE_EXERCISED, DetectionState.OBSERVED_EXERCISED}
            or not candidate.rule_source
        ):
            raise DetectionError("YARA candidate must be exercised before benign evaluation")
        fixture_ids, matched_ids = self._yara_matches(candidate, fixtures)
        return candidate.transition(
            DetectionState.BENIGN_EVALUATED,
            benign_fixture_ids=tuple(fixture_ids),
            benign_match_count=len(matched_ids),
            false_positive_notes=tuple(notes),
            validation=self._yara_execution_validation(
                candidate,
                fixture_ids,
                matched_ids,
                "benign_evaluated_fixture_ids",
                "benign_matched_fixture_ids",
            ),
        )

    @staticmethod
    def _yara_execution_validation(
        candidate: Any,
        fixture_ids: Sequence[str],
        matched_ids: Sequence[str],
        evaluated_key: str,
        matched_key: str,
    ) -> dict[str, Any]:
        return {
            **dict(candidate.validation),
            "source_rule_executed": True,
            "executed_source_sha256": _sha256_text(candidate.rule_source),
            "execution_backend": "YARA-Python",
            "execution_backend_version": candidate.parser_backend["version"],
            evaluated_key: list(fixture_ids),
            matched_key: list(matched_ids),
        }

    def _yara_matches(
        self, candidate: Any, fixtures: Sequence[Mapping[str, Any]]
    ) -> tuple[list[str], list[str]]:
        if (
            isinstance(fixtures, (str, bytes))
            or not isinstance(fixtures, Sequence)
            or len(fixtures) > _MAX_FIXTURES
        ):
            raise DetectionError("YARA fixture inventory is invalid or exceeds its limit")
        try:
            version = _package_version("yara-python", _YARA_PIN)
        except DetectionBackendUnavailable as exc:
            raise DetectionError(str(exc)) from exc
        try:
            import yara
        except ImportError as exc:
            raise DetectionError("YARA-Python is unavailable") from exc
        if not candidate.rule_source:
            raise DetectionError("YARA candidate has no compiled rule source")
        if candidate.validation.get("source_sha256") != _sha256_text(
            candidate.rule_source
        ) or candidate.parser_backend != {"name": "YARA-Python", "version": version}:
            raise DetectionError("persisted YARA parser metadata is invalid")
        try:
            rules = yara.compile(
                source=candidate.rule_source, includes=False, error_on_warning=True
            )
        except yara.Error as exc:
            raise DetectionError("YARA-Python fixture compilation failed") from exc
        fixture_ids: list[str] = []
        matched_ids: list[str] = []
        total_bytes = 0
        for fixture in fixtures:
            if not isinstance(fixture, Mapping):
                raise DetectionError("each YARA fixture must be an object")
            fixture_id = fixture.get("fixture_id")
            if (
                not isinstance(fixture_id, str)
                or _FIXTURE_ID.fullmatch(fixture_id) is None
                or fixture_id in fixture_ids
            ):
                raise DetectionError("YARA fixture IDs must be valid and unique")
            payload = fixture.get("data", b"")
            if isinstance(payload, str):
                data = payload.encode("utf-8")
            elif isinstance(payload, bytes):
                data = payload
            else:
                raise DetectionError("YARA fixture data must be bytes or text")
            total_bytes += len(data)
            if total_bytes > self.max_fixture_bytes:
                raise DetectionError("YARA fixtures exceed the total byte limit")
            fixture_ids.append(fixture_id)
            try:
                matches = rules.match(data=data, timeout=2)
            except yara.Error as exc:
                raise DetectionError("YARA-Python fixture evaluation failed") from exc
            if matches:
                matched_ids.append(fixture_id)
        return fixture_ids, matched_ids

    def check_spl(self, candidate: Any, source: str) -> Any:
        self._require_hypothesis(candidate, "spl")
        source = self._source(source)
        problems: list[str] = []
        structural = source.replace('\\"', "")
        if structural.count('"') % 2:
            problems.append("unterminated quote")
        if any(
            structural.count(left) != structural.count(right)
            for left, right in {
                "(": ")",
                "[": "]",
                "{": "}",
            }.items()
        ):
            problems.append("unbalanced delimiter")
        if any(ord(character) < 9 for character in source):
            problems.append("control characters are not allowed")
        if problems:
            return candidate.transition(
                DetectionState.REJECTED,
                rule_source=source,
                rejection_reason="SPL structural check failed",
                validation={"backend": "structural-only", "errors": problems},
            )
        return replace(
            candidate,
            rule_source=source,
            validation={
                "backend": "structural-only",
                "syntax_checked": True,
                "authoritative_backend_validated": False,
                "errors": [],
            },
        )

    @staticmethod
    def field_drift(
        predicted_fields: Iterable[str], observed_fields: Iterable[str]
    ) -> Mapping[str, tuple[str, ...]]:
        predicted = {str(item) for item in predicted_fields if str(item)}
        observed = {str(item) for item in observed_fields if str(item)}
        return {
            "predicted_only": tuple(sorted(predicted - observed)),
            "observed_only": tuple(sorted(observed - predicted)),
            "intersection": tuple(sorted(predicted & observed)),
        }

    @staticmethod
    def compare_public_baseline(
        candidate_matches: Iterable[str], baseline_matches: Iterable[str]
    ) -> Mapping[str, Any]:
        candidate = set(candidate_matches)
        baseline = set(baseline_matches)
        return {
            "candidate_only": sorted(candidate - baseline),
            "baseline_only": sorted(baseline - candidate),
            "overlap": sorted(candidate & baseline),
            "incremental_candidate_matches": len(candidate - baseline),
        }

    def _source(self, source: str) -> str:
        if not isinstance(source, str) or not source.strip():
            raise DetectionError("detection source is required")
        if "\x00" in source or len(source.encode("utf-8")) > self.max_source_bytes:
            raise DetectionError("detection source is invalid or exceeds the byte limit")
        return source

    @staticmethod
    def _require_hypothesis(candidate: Any, language: str) -> None:
        if candidate.target_language != language:
            raise DetectionError(f"candidate language must be {language}")
        if candidate.state is not DetectionState.HYPOTHESIS:
            raise DetectionError("only a hypothesis can be parsed")


__all__ = "DetectionBackendError DetectionBackendUnavailable DetectionError DetectionState ExternalDetectionValidator SQLITE_LOG_FIELDS convert_sigma_to_sqlite execute_sqlite_query inspect_sqlite_query".split()
