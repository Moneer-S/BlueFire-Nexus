"""Reviewed source integrity only; these checks never compile or run Rust/tools."""

from pathlib import Path

import pytest

from tools.native_command_source_audit import (
    _native_command_source_inventory_is_fixed,
    _reviewed_owned_sftp_sources,
)

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("owned_sftp.rs", "owned_sftp_process.rs", "actions/owned_sftp_action.rs")


def sources():
    return {name: (ROOT / "runner" / "src" / name).read_bytes() for name in NAMES}


def test_exact_reviewed_sftp_source_does_not_relax_native_command_inventory():
    assert _reviewed_owned_sftp_sources(sources())
    assert _native_command_source_inventory_is_fixed(ROOT)


@pytest.mark.parametrize("name", NAMES)
def test_changed_admission_launch_or_publication_bytes_require_a_new_source_review(name):
    rows = sources()
    rows[name] += b"\n// unreviewed change\n"
    assert not _reviewed_owned_sftp_sources(rows)
    del rows[name]
    assert not _reviewed_owned_sftp_sources(rows)


def test_new_helper_source_cannot_enter_the_closed_reviewed_consumer_set():
    rows = sources()
    rows["unreviewed_helper.rs"] = b"unreviewed"
    assert not _reviewed_owned_sftp_sources(rows)


def test_enabling_a_build_or_replacing_transport_options_breaks_the_source_pin():
    rows = sources()
    rows["owned_sftp.rs"] = rows["owned_sftp.rs"].replace(
        b"const REVIEWED_BUNDLES: &[ReviewedBundle] = &[];",
        b"const REVIEWED_BUNDLES: &[ReviewedBundle] = &[unreviewed];",
    )
    assert not _reviewed_owned_sftp_sources(rows)
    rows = sources()
    rows["owned_sftp_process.rs"] = rows["owned_sftp_process.rs"].replace(
        b"ProxyCommand=none", b"ProxyCommand=caller"
    )
    assert not _reviewed_owned_sftp_sources(rows)
