"""Adversarial contract tests; helper effects exist only in an in-memory fake."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict, replace
from typing import Any

import pytest

from bluefire.engine_workspace_transfer import (
    DEFAULT_TRANSFER_CAPS,
    BeginCommand,
    BeginReceipt,
    ChunkCommand,
    ChunkReceipt,
    FinalizeCommand,
    FinalizeReceipt,
    TransferBinding,
    TransferCaps,
    WorkspaceTransferBook,
    WorkspaceTransferError,
    sha256,
    workspace_destination,
)

BINDING = TransferBinding("attempt-1", "session-1", "resource-1", "profile-1", "request-1")


class FakeHelper:
    def __init__(self) -> None:
        self.data = b""
        self.chunks: list[ChunkReceipt] = []
        self.writes = 0
        self.publications = 0
        self.begin_receipt: BeginReceipt | None = None
        self.final_receipt: FinalizeReceipt | None = None

    def begin(self, command: BeginCommand) -> BeginReceipt:
        if self.begin_receipt is not None:
            assert self.begin_receipt.descriptor == command.descriptor
            return self.begin_receipt
        self.begin_receipt = BeginReceipt(command.descriptor, True, True, True)
        return self.begin_receipt

    def chunk(self, command: ChunkCommand) -> ChunkReceipt:
        receipt = command.receipt
        if receipt.index < len(self.chunks):
            assert self.chunks[receipt.index] == receipt
            return receipt
        assert receipt.index == len(self.chunks) and receipt.offset == len(self.data)
        assert sha256(command.payload) == receipt.chunk_digest
        self.data += command.payload
        self.chunks.append(receipt)
        self.writes += 1
        return receipt

    def finalize(self, command: FinalizeCommand) -> FinalizeReceipt:
        if self.final_receipt is not None:
            assert self.final_receipt.descriptor == command.descriptor
            assert self.final_receipt.chunk_count == command.chunk_count
            return self.final_receipt
        self.publications += 1
        self.final_receipt = FinalizeReceipt(
            command.descriptor,
            len(self.chunks),
            len(self.data),
            sha256(self.data),
            True,
            True,
            True,
        )
        return self.final_receipt


def begun(
    data: bytes = b"abcdef",
    *,
    caps: TransferCaps = DEFAULT_TRANSFER_CAPS,
) -> tuple[WorkspaceTransferBook, FakeHelper]:
    helper = FakeHelper()
    book, command = WorkspaceTransferBook().begin(
        binding=BINDING,
        transfer_id="transfer-1",
        destination="/workspace/output/result.json",
        total_bytes=len(data),
        content_digest=sha256(data),
        now=10,
        caps=caps,
    )
    return book.acknowledge_begin("transfer-1", helper.begin(command), now=11), helper


def written(data: bytes = b"abcdef") -> tuple[WorkspaceTransferBook, FakeHelper]:
    book, helper = begun(data)
    if data:
        book, command = book.chunk("transfer-1", index=0, offset=0, payload=data, now=12)
        book = book.acknowledge_chunk("transfer-1", helper.chunk(command), now=13)
    return book, helper


def test_success_is_immutable_and_requires_independent_readback_and_publish() -> None:
    initial, helper = begun()
    book, command = initial.chunk("transfer-1", index=0, offset=0, payload=b"abc", now=12)
    assert initial.get("transfer-1").phase == "ready"
    book = book.acknowledge_chunk("transfer-1", helper.chunk(command), now=13)
    book, command = book.chunk("transfer-1", index=1, offset=3, payload=b"def", now=14)
    book = book.acknowledge_chunk("transfer-1", helper.chunk(command), now=15)
    book, final = book.finalize("transfer-1", now=16)
    assert book.get("transfer-1").residue == "possible"
    receipt = helper.finalize(final)
    book = book.acknowledge_finalize("transfer-1", receipt, now=17)
    assert book.get("transfer-1").phase == "published"
    assert book.get("transfer-1").residue == "published"
    assert book.get("transfer-1")._data == ()
    assert (
        book.acknowledge_finalize("transfer-1", receipt, now=999).get("transfer-1").final_receipt
        == receipt
    )
    with pytest.raises(FrozenInstanceError):
        receipt.chunk_count = 0  # type: ignore[misc]


@pytest.mark.parametrize(
    "destination",
    [
        "/tmp/secret",
        "/workspace",
        "/workspace/",
        "/workspace/../secret",
        "/workspace/a/../../b",
        "/workspace/a//b",
        "/workspace/./b",
        "/workspace//root",
        "/workspace/a\\b",
        "/workspace/C:/secret",
        "/workspace/%2e%2e/b",
        "/workspace/a\x00b",
        "/workspace/a\nb",
        "/workspace/a\x7fb",
        "/workspace/café",
        "/workspace/CON",
        "/workspace/nul.txt",
        "/workspace/Com1.json",
        "/workspace/LPT9",
        "/workspace/a.",
        "/workspace/a ",
        "/workspace/" + "a" * 101,
        "/workspace/" + "/".join(["a"] * 17),
    ],
)
def test_rejects_noncanonical_unsafe_paths(destination: str) -> None:
    with pytest.raises(WorkspaceTransferError) as error:
        workspace_destination(destination)
    assert destination not in str(error.value)


def test_only_canonical_relative_destination_is_disclosed() -> None:
    data = b"secret payload with C:\\host\\path and token=private"
    book, helper = written(data)
    book, command = book.finalize("transfer-1", now=14)
    receipt = helper.finalize(command)
    book = book.acknowledge_finalize("transfer-1", receipt, now=15)
    assert receipt.descriptor.destination == "output/result.json"
    assert "secret payload" not in repr(book)
    assert "C:\\host" not in str(asdict(receipt))
    assert "private" not in str(asdict(receipt))
    assert "/workspace" not in str(asdict(receipt))


def test_chunk_retry_is_idempotent_before_and_after_ack() -> None:
    book, helper = begun()
    book, first = book.chunk("transfer-1", index=0, offset=0, payload=b"abc", now=12)
    book, retry = book.chunk("transfer-1", index=0, offset=0, payload=b"abc", now=13)
    assert retry == first
    receipt = helper.chunk(first)
    assert helper.chunk(retry) == receipt
    book = book.acknowledge_chunk("transfer-1", receipt, now=14)
    book, retry = book.chunk("transfer-1", index=0, offset=0, payload=b"abc", now=15)
    assert helper.chunk(retry) == receipt
    book = book.acknowledge_chunk("transfer-1", receipt, now=16)
    assert len(book.get("transfer-1").chunks) == helper.writes == 1
    assert book.get("transfer-1")._data == (b"abc",)
    for payload, offset in [(b"xxx", 0), (b"abc", 1)]:
        with pytest.raises(WorkspaceTransferError):
            book.chunk("transfer-1", index=0, offset=offset, payload=payload, now=17)


def test_begin_and_finalize_ambiguous_retries_do_not_repeat_effects() -> None:
    helper = FakeHelper()
    book, begin = WorkspaceTransferBook().begin(
        binding=BINDING,
        transfer_id="transfer-1",
        destination="/workspace/empty",
        total_bytes=0,
        content_digest=sha256(b""),
        now=10,
    )
    receipt = helper.begin(begin)
    assert helper.begin(begin) is receipt
    book = book.acknowledge_begin("transfer-1", receipt, now=11)
    book = book.acknowledge_begin("transfer-1", receipt, now=12)
    book, final = book.finalize("transfer-1", now=13)
    receipt_final = helper.finalize(final)
    book, retry = book.finalize("transfer-1", now=14)
    assert helper.finalize(retry) is receipt_final
    assert helper.publications == 1
    book = book.acknowledge_finalize("transfer-1", receipt_final, now=15)
    assert book.get("transfer-1").phase == "published"


def test_same_resource_destination_is_reserved_across_sessions_and_after_revoke() -> None:
    book, _ = begun()
    book = book.stop("transfer-1", reason="revoked", now=12)
    with pytest.raises(WorkspaceTransferError):
        book.begin(
            binding=replace(BINDING, session_id="session-2"),
            transfer_id="transfer-2",
            destination="/workspace/output/result.json",
            total_bytes=0,
            content_digest=sha256(b""),
            now=13,
        )


@pytest.mark.parametrize(
    "index,offset,payload",
    [
        (1, 0, b"abc"),
        (0, 1, b"abc"),
        (-1, 0, b"a"),
        (False, 0, b"a"),
        (0, False, b"a"),
        (0, 0, b""),
        (0, 0, b"abcdefg"),
        (0, 0, bytearray(b"abc")),
    ],
)
def test_chunk_rejects_gaps_overlap_empty_overflow_and_mutable_data(
    index: int,
    offset: int,
    payload: bytes,
) -> None:
    book, _ = begun()
    with pytest.raises(WorkspaceTransferError):
        book.chunk("transfer-1", index=index, offset=offset, payload=payload, now=12)


def test_pending_conflict_and_invented_ack_refused() -> None:
    book, _ = begun()
    with pytest.raises(WorkspaceTransferError):
        book.acknowledge_chunk(
            "transfer-1",
            ChunkReceipt(book.get("transfer-1").descriptor, 0, 0, 3, sha256(b"abc")),
            now=12,
        )
    book, command = book.chunk("transfer-1", index=0, offset=0, payload=b"abc", now=12)
    with pytest.raises(WorkspaceTransferError):
        book.chunk("transfer-1", index=1, offset=3, payload=b"def", now=13)
    with pytest.raises(WorkspaceTransferError):
        book.acknowledge_chunk(
            "transfer-1", replace(command.receipt, chunk_digest=sha256(b"xxx")), now=13
        )


@pytest.mark.parametrize(
    "field", ["attempt_id", "session_id", "resource_id", "profile_id", "request_id"]
)
def test_receipts_bind_every_identity(field: str) -> None:
    book, helper = written()
    book, command = book.finalize("transfer-1", now=14)
    receipt = helper.finalize(command)
    wrong_binding = replace(BINDING, **{field: "wrong"})
    wrong = replace(receipt, descriptor=replace(receipt.descriptor, binding=wrong_binding))
    with pytest.raises(WorkspaceTransferError):
        book.acknowledge_finalize("transfer-1", wrong, now=15)


@pytest.mark.parametrize(
    "field,value",
    [
        ("transfer_id", "wrong"),
        ("destination", "other.json"),
        ("total_bytes", 7),
        ("content_digest", sha256(b"wrong")),
        ("started_at", 11),
    ],
)
def test_descriptor_tampering_refused(field: str, value: Any) -> None:
    book, helper = written()
    book, command = book.finalize("transfer-1", now=14)
    receipt = helper.finalize(command)
    with pytest.raises(WorkspaceTransferError):
        descriptor = replace(receipt.descriptor, **{field: value})
        book.acknowledge_finalize("transfer-1", replace(receipt, descriptor=descriptor), now=15)


@pytest.mark.parametrize(
    "field,value",
    [
        ("file_fsynced", False),
        ("atomic_no_replace_published", False),
        ("directory_fsynced", False),
        ("staged_bytes", 5),
        ("chunk_count", 0),
        ("staged_digest", sha256(b"corrupt")),
        ("file_fsynced", 1),
    ],
)
def test_finalize_requires_complete_helper_evidence(field: str, value: Any) -> None:
    book, helper = written()
    book, command = book.finalize("transfer-1", now=14)
    receipt = helper.finalize(command)
    with pytest.raises(WorkspaceTransferError):
        book.acknowledge_finalize("transfer-1", replace(receipt, **{field: value}), now=15)
    assert book.get("transfer-1").residue == "possible"


def test_finalize_refuses_incomplete_pending_and_wrong_whole_digest() -> None:
    book, _ = begun()
    with pytest.raises(WorkspaceTransferError):
        book.finalize("transfer-1", now=12)
    book, command = book.chunk("transfer-1", index=0, offset=0, payload=b"xxxxxx", now=12)
    with pytest.raises(WorkspaceTransferError):
        book.finalize("transfer-1", now=13)
    book = book.acknowledge_chunk("transfer-1", command.receipt, now=13)
    with pytest.raises(WorkspaceTransferError):
        book.finalize("transfer-1", now=14)


def test_empty_transfer_requires_empty_digest_and_seal() -> None:
    book, helper = written(b"")
    book, command = book.finalize("transfer-1", now=14)
    book = book.acknowledge_finalize("transfer-1", helper.finalize(command), now=15)
    assert book.get("transfer-1").phase == "published"


@pytest.mark.parametrize(
    "reason,now", [("cancelled", 15), ("revoked", 15), ("unknown", 15), ("expired", 310)]
)
def test_terminal_outcomes_preserve_possible_residue_and_fence_late_success(
    reason: str, now: int
) -> None:
    book, helper = written()
    book, command = book.finalize("transfer-1", now=14)
    # The helper might already have published when the reply is lost.
    receipt = helper.finalize(command)
    book = book.stop("transfer-1", reason=reason, now=now)  # type: ignore[arg-type]
    assert book.get("transfer-1").residue == "possible"
    assert book.get("transfer-1")._data == ()
    with pytest.raises(WorkspaceTransferError):
        book.acknowledge_finalize("transfer-1", receipt, now=now)
    assert book.stop("transfer-1", reason="unknown", now=now).get("transfer-1").phase == reason


def test_stop_does_not_downgrade_known_published_residue() -> None:
    book, helper = written()
    book, command = book.finalize("transfer-1", now=14)
    book = book.acknowledge_finalize("transfer-1", helper.finalize(command), now=15)
    book = book.stop("transfer-1", reason="revoked", now=16)
    assert book.get("transfer-1").residue == "published"


def test_expiry_and_clock_rollback_refuse_without_claiming_absence() -> None:
    book, _ = begun()
    for now in (10, 310, 311, False):
        with pytest.raises(WorkspaceTransferError):
            book.chunk("transfer-1", index=0, offset=0, payload=b"abc", now=now)
    assert book.get("transfer-1").residue == "possible"


def test_caps_duplicates_and_aliases_are_bounded() -> None:
    book, _ = begun()
    for transfer_id, destination in [
        ("transfer-1", "/workspace/different"),
        ("transfer-2", "/workspace/output/result.json"),
        ("transfer-2", "/workspace/OUTPUT/RESULT.JSON"),
    ]:
        with pytest.raises(WorkspaceTransferError):
            book.begin(
                binding=BINDING,
                transfer_id=transfer_id,
                destination=destination,
                total_bytes=1,
                content_digest=sha256(b"a"),
                now=12,
            )
    with pytest.raises(WorkspaceTransferError):
        begun(caps=TransferCaps(max_total_bytes=5))
    with pytest.raises(WorkspaceTransferError):
        begun(caps=TransferCaps(max_chunk_bytes=2, max_chunks=2))
    book, _ = begun(caps=TransferCaps(max_chunk_bytes=3, max_chunks=2))
    with pytest.raises(WorkspaceTransferError):
        book.chunk("transfer-1", index=0, offset=0, payload=b"abcd", now=12)
    for values in [
        dict(max_total_bytes=8 * 1024 * 1024 + 1),
        dict(max_chunks=1025),
        dict(lifetime_seconds=301),
        dict(max_chunk_bytes=0),
        dict(max_chunks=True),
    ]:
        with pytest.raises(WorkspaceTransferError):
            TransferCaps(**values)  # type: ignore[arg-type]


def test_begin_refuses_unproven_link_device_or_exclusive_staging() -> None:
    book, command = WorkspaceTransferBook().begin(
        binding=BINDING,
        transfer_id="transfer-1",
        destination="/workspace/file",
        total_bytes=0,
        content_digest=sha256(b""),
        now=10,
    )
    receipt = BeginReceipt(command.descriptor, True, True, True)
    for field in ("private_regular_staging", "no_symlink_resolution", "exclusive_destination"):
        with pytest.raises(WorkspaceTransferError):
            book.acknowledge_begin("transfer-1", replace(receipt, **{field: False}), now=11)  # type: ignore[arg-type]
    with pytest.raises(WorkspaceTransferError):
        book.chunk("transfer-1", index=0, offset=0, payload=b"x", now=11)


def test_book_has_bounded_count_and_total_declared_bytes() -> None:
    book = WorkspaceTransferBook()
    for index in range(64):
        book, _ = book.begin(
            binding=BINDING,
            transfer_id=f"t-{index}",
            destination=f"/workspace/f-{index}",
            total_bytes=0,
            content_digest=sha256(b""),
            now=10,
        )
    with pytest.raises(WorkspaceTransferError):
        book.begin(
            binding=BINDING,
            transfer_id="last",
            destination="/workspace/last",
            total_bytes=0,
            content_digest=sha256(b""),
            now=10,
        )
    book = WorkspaceTransferBook()
    for index in range(2):
        book, _ = book.begin(
            binding=BINDING,
            transfer_id=f"t-{index}",
            destination=f"/workspace/f-{index}",
            total_bytes=8 * 1024 * 1024,
            content_digest=sha256(b""),
            now=10,
        )
    with pytest.raises(WorkspaceTransferError):
        book.begin(
            binding=BINDING,
            transfer_id="last",
            destination="/workspace/last",
            total_bytes=1,
            content_digest=sha256(b"a"),
            now=10,
        )
