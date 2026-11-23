"""Owner-local S3 extension setup; never acquire credentials or dispatch workers."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Any

from . import s3_access_setup as setup
from .runner_bootstrap import managed_product_root
from .runner_trust import load_local_enrollment
from .s3_access_contract import S3AccessError, document
from .s3_access_extension_store import S3ExtensionStore


def register(commands: Any) -> None:
    command = commands.add_parser("s3", help="Configure existing owned S3 access locally")
    actions = command.add_subparsers(dest="s3_command", required=True)
    status = actions.add_parser("status", help="Inspect local protected-reference metadata")
    status.add_argument("--profile", required=True)
    configure = actions.add_parser("configure", help="Review and apply exact local configuration")
    configuration = configure.add_subparsers(dest="s3_configure_command", required=True)
    for name in ("review", "apply"):
        selected = configuration.add_parser(name)
        selected.add_argument("--profile", required=True)
        selected.add_argument("--draft", type=Path, required=True)
        if name == "apply":
            selected.add_argument("--review", type=Path, required=True)
    credentials = actions.add_parser("credentials", help="Import already acquired temporary access")
    credential_actions = credentials.add_subparsers(dest="s3_credentials_command", required=True)
    setter = credential_actions.add_parser("set")
    setter.add_argument("--profile", required=True)
    setter.add_argument("--environment", required=True)
    setter.add_argument("--expected-revision", required=True)
    setter.add_argument("--stdin", action="store_true", required=True)
    reconcile = actions.add_parser(
        "reconcile", help="Inspect an original publication without replay"
    )
    reconcile.add_argument("--profile", required=True)
    reconcile.add_argument("--record-digest")
    reconcile.add_argument("--complete", action="store_true")


def _require_owned_linux() -> None:
    getuid, geteuid = (getattr(os, name, None) for name in ("getuid", "geteuid"))
    if (
        not sys.platform.startswith("linux")
        or not callable(getuid)
        or not callable(geteuid)
        or getuid() <= 0
        or getuid() != geteuid()
        or type(getattr(os, "O_NOFOLLOW", None)) is not int
        or type(getattr(os, "O_NONBLOCK", None)) is not int
    ):
        raise S3AccessError("S3 setup requires its existing owned Linux host.")


def _document(path: Path, maximum: int) -> dict[str, Any]:
    nofollow, nonblock = (getattr(os, name, None) for name in ("O_NOFOLLOW", "O_NONBLOCK"))
    if type(nofollow) is not int or type(nonblock) is not int:
        raise S3AccessError("S3 setup file inspection is unavailable on this host.")
    descriptor = os.open(path, os.O_RDONLY | nofollow | nonblock)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise S3AccessError("S3 setup input must be a bounded regular file.")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read(maximum + 1)
        after = os.fstat(descriptor)
        named = path.lstat()

        def identity(item):
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_nlink,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if identity(before) != identity(after) or identity(after) != identity(named):
            raise S3AccessError("S3 setup input changed during inspection.")
        return document(payload, limit=maximum)
    finally:
        os.close(descriptor)


def _selected_configuration(enrollment, configuration: Any, profile: str) -> dict[str, Any]:
    from .s3_access_configuration import validate_configuration

    row = validate_configuration(
        configuration, runner_id=enrollment.runner_id, profile_ids=enrollment.allowed_profile_ids
    )
    if any(entry["profile"]["profile_id"] != profile for entry in row["environments"]):
        raise S3AccessError("S3 draft must select the exact enrolled profile.")
    return row


def execute(args: argparse.Namespace) -> dict[str, Any]:
    """All diagnostics are fixed, with no file paths, provider errors or input bytes."""
    try:
        _require_owned_linux()
        enrollment = load_local_enrollment(
            managed_product_root() / "enrollment", verify_permissions_only=True
        )
        if args.profile not in enrollment.allowed_profile_ids:
            raise S3AccessError("S3 setup profile is not enrolled.")
        if args.s3_command == "status":
            configuration = setup.read_configuration(enrollment)
            selected = {
                entry["environment_id"]
                for entry in (configuration or {}).get("environments", [])
                if entry["profile"]["profile_id"] == args.profile
            }
            row = setup.inspect_extension(enrollment)
            row["references"] = [
                item for item in row["references"] if item["environment_id"] in selected
            ]
            return {
                "schema_version": "bluefire.s3-local-setup-status.v1",
                "profile_id": args.profile,
                "readiness_scope": "local_reference_metadata_only",
                **row,
            }
        if args.s3_command == "configure":
            configuration = _selected_configuration(
                enrollment, _document(args.draft, 512 * 1024), args.profile
            )
            if args.s3_configure_command == "review":
                return setup.review_configuration(enrollment, configuration)
            if args.s3_configure_command == "apply":
                return setup.apply_configuration(
                    enrollment, configuration, _document(args.review, 16 * 1024)
                )
        if args.s3_command == "reconcile":
            store = S3ExtensionStore(enrollment)
            if args.complete:
                if args.record_digest is None:
                    raise S3AccessError("S3 completion requires the inspected record digest.")
                return store.complete_publication(args.record_digest)
            return store.publication_state(args.record_digest)
        if args.s3_command == "credentials" and args.s3_credentials_command == "set":
            configuration = setup.read_configuration(enrollment)
            matches = [
                entry
                for entry in (configuration or {}).get("environments", [])
                if entry["environment_id"] == args.environment
                and entry["profile"]["profile_id"] == args.profile
            ]
            if len(matches) != 1 or args.stdin is not True or sys.stdin.isatty():
                raise S3AccessError(
                    "S3 temporary access requires the exact environment and binary stdin."
                )
            payload = sys.stdin.buffer.read(16 * 1024 + 1)
            return setup.import_temporary_material(
                enrollment, args.environment, payload, expected_revision=args.expected_revision
            )
        raise S3AccessError("S3 setup command is invalid.")
    except Exception:
        raise S3AccessError(
            "S3 local setup was refused. Check the host, profile, review and input."
        ) from None
