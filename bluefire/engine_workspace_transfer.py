"""Pure, bounded controller protocol for a reviewed in-workspace write helper.

This module performs no I/O and supplies no executable transport. Commands may
only be handed to a separately reviewed helper through an injected interface.
That helper must resolve every component beneath its already-held /workspace
directory descriptor without following links, reject special files, create a
private exclusive staging file, write at the exact offset, and publish with
no-replace atomic rename after file fsync, then fsync the parent directory.
It must never accept a host path, shell command, stdin stream or bind mount.

Receipts are trusted helper attestations, not cryptographic proof of filesystem
behavior. The caller must authenticate that helper and independently authorize
the complete binding. Cancellation/expiry/unknown outcomes never prove cleanup.
The immutable book is controller-private state: persist it with compare-and-swap
before dispatch, and never dispatch commands from superseded snapshots. Terminal
reservations must survive retries; this bounded book deliberately has no eviction.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from typing import Literal, Protocol

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PART = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_DEVICES = frozenset({"con", "prn", "aux", "nul", "conin$", "conout$"}) | frozenset(
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(10)
)


class WorkspaceTransferError(ValueError):
    """A generic refusal; messages intentionally exclude supplied data and paths."""


def _require(condition: bool, message: str = "workspace transfer refused") -> None:
    if not condition:
        raise WorkspaceTransferError(message)


def _integer(value: int, minimum: int, maximum: int) -> None:
    _require(type(value) is int and minimum <= value <= maximum)


def _digest(value: str) -> None:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None)


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def workspace_destination(value: str) -> str:
    """Validate an exact absolute destination; return its canonical relative form."""
    _require(type(value) is str and value.startswith("/workspace/"))
    relative = value[len("/workspace/") :]
    _require(0 < len(relative) <= 512)
    parts = relative.split("/")
    _require(len(parts) <= 16)
    for part in parts:
        _require(_PART.fullmatch(part) is not None and part not in {".", ".."})
        _require(not part.endswith(".") and part.split(".")[0].lower() not in _DEVICES)
    return relative


@dataclass(frozen=True)
class TransferBinding:
    attempt_id: str
    session_id: str
    resource_id: str
    profile_id: str
    request_id: str

    def __post_init__(self) -> None:
        for value in (
            self.attempt_id,
            self.session_id,
            self.resource_id,
            self.profile_id,
            self.request_id,
        ):
            _require(type(value) is str and _ID.fullmatch(value) is not None)


@dataclass(frozen=True)
class TransferCaps:
    max_total_bytes: int = 8 * 1024 * 1024
    max_chunk_bytes: int = 64 * 1024
    max_chunks: int = 256
    lifetime_seconds: int = 300

    def __post_init__(self) -> None:
        _integer(self.max_total_bytes, 0, 8 * 1024 * 1024)
        _integer(self.max_chunk_bytes, 1, 256 * 1024)
        _integer(self.max_chunks, 1, 1024)
        _integer(self.lifetime_seconds, 1, 300)


DEFAULT_TRANSFER_CAPS = TransferCaps()


@dataclass(frozen=True)
class TransferDescriptor:
    binding: TransferBinding
    transfer_id: str
    destination: str
    total_bytes: int
    content_digest: str
    caps: TransferCaps
    started_at: int
    expires_at: int

    def __post_init__(self) -> None:
        _require(type(self.binding) is TransferBinding and type(self.caps) is TransferCaps)
        _require(type(self.transfer_id) is str and _ID.fullmatch(self.transfer_id) is not None)
        _require(workspace_destination("/workspace/" + self.destination) == self.destination)
        _integer(self.total_bytes, 0, self.caps.max_total_bytes)
        _digest(self.content_digest)
        _integer(self.started_at, 0, 2**53)
        _require(self.expires_at == self.started_at + self.caps.lifetime_seconds)
        _integer(self.expires_at, 0, 2**53)
        _require(self.total_bytes <= self.caps.max_chunk_bytes * self.caps.max_chunks)


@dataclass(frozen=True)
class BeginCommand:
    descriptor: TransferDescriptor


@dataclass(frozen=True)
class BeginReceipt:
    descriptor: TransferDescriptor
    private_regular_staging: bool
    no_symlink_resolution: bool
    exclusive_destination: bool

    def __post_init__(self) -> None:
        _require(type(self.descriptor) is TransferDescriptor)
        _require(
            all(
                type(flag) is bool
                for flag in (
                    self.private_regular_staging,
                    self.no_symlink_resolution,
                    self.exclusive_destination,
                )
            )
        )


@dataclass(frozen=True)
class ChunkReceipt:
    descriptor: TransferDescriptor
    index: int
    offset: int
    size: int
    chunk_digest: str

    def __post_init__(self) -> None:
        _require(type(self.descriptor) is TransferDescriptor)
        _integer(self.index, 0, self.descriptor.caps.max_chunks - 1)
        _integer(self.offset, 0, self.descriptor.total_bytes)
        _integer(self.size, 1, self.descriptor.caps.max_chunk_bytes)
        _require(self.offset + self.size <= self.descriptor.total_bytes)
        _digest(self.chunk_digest)


@dataclass(frozen=True)
class ChunkCommand:
    receipt: ChunkReceipt
    payload: bytes = field(repr=False)


@dataclass(frozen=True)
class FinalizeCommand:
    descriptor: TransferDescriptor
    chunk_count: int


@dataclass(frozen=True)
class FinalizeReceipt:
    descriptor: TransferDescriptor
    chunk_count: int
    staged_bytes: int
    staged_digest: str
    file_fsynced: bool
    atomic_no_replace_published: bool
    directory_fsynced: bool

    def __post_init__(self) -> None:
        _require(type(self.descriptor) is TransferDescriptor)
        _integer(self.chunk_count, 0, self.descriptor.caps.max_chunks)
        _integer(self.staged_bytes, 0, self.descriptor.caps.max_total_bytes)
        _digest(self.staged_digest)
        _require(
            all(
                type(flag) is bool
                for flag in (
                    self.file_fsynced,
                    self.atomic_no_replace_published,
                    self.directory_fsynced,
                )
            )
        )


class ReviewedWorkspaceHelper(Protocol):
    """Injected reviewed implementation; never automatically invoked here.

    Before every effect the helper must independently authorize the complete
    descriptor binding, caps, expiry and nonterminal transfer state. Begin and
    finalize retries must return their original receipts without creating or
    publishing twice; an acknowledged publication can be replayed after expiry
    without any new effect. A repeated identical chunk must return its original
    receipt without writing twice. Any conflicting retry must refuse. Finalize
    must rehash the staging file itself; controller hashes cannot stand in for
    helper readback. Cancellation/revocation must fence pending publication at
    the helper as well as at the controller; otherwise residue remains possible.
    """

    def begin(self, command: BeginCommand) -> BeginReceipt: ...

    def chunk(self, command: ChunkCommand) -> ChunkReceipt: ...

    def finalize(self, command: FinalizeCommand) -> FinalizeReceipt: ...


Phase = Literal[
    "begin", "ready", "chunk", "finalize", "published", "cancelled", "revoked", "unknown", "expired"
]
Residue = Literal["possible", "published"]


@dataclass(frozen=True)
class TransferState:
    descriptor: TransferDescriptor
    phase: Phase = "begin"
    residue: Residue = "possible"
    begin_receipt: BeginReceipt | None = None
    chunks: tuple[ChunkReceipt, ...] = ()
    final_receipt: FinalizeReceipt | None = None
    _data: tuple[bytes, ...] = field(default=(), repr=False)
    _pending: ChunkCommand | None = field(default=None, repr=False)
    _last_time: int = field(default=0, repr=False)


@dataclass(frozen=True)
class WorkspaceTransferBook:
    """Pure state transitions; callers must retain only each returned successor.

    Maximum 64 reservations and 16 MiB of declared data per book. All public
    receipts contain only bounded identity, workspace-relative paths and hashes.
    Data and helper exceptions must never be included in public projections.
    """

    transfers: tuple[TransferState, ...] = ()

    def get(self, transfer_id: str) -> TransferState:
        for state in self.transfers:
            if state.descriptor.transfer_id == transfer_id:
                return state
        raise WorkspaceTransferError("unknown workspace transfer")

    def _put(self, state: TransferState) -> WorkspaceTransferBook:
        return replace(
            self,
            transfers=tuple(
                state if old.descriptor.transfer_id == state.descriptor.transfer_id else old
                for old in self.transfers
            ),
        )

    def _live(self, transfer_id: str, now: int) -> TransferState:
        state = self.get(transfer_id)
        _integer(now, state._last_time, 2**53)
        _require(now < state.descriptor.expires_at, "workspace transfer expired")
        _require(state.phase in {"begin", "ready", "chunk", "finalize"})
        return replace(state, _last_time=now)

    def begin(
        self,
        *,
        binding: TransferBinding,
        transfer_id: str,
        destination: str,
        total_bytes: int,
        content_digest: str,
        now: int,
        caps: TransferCaps = DEFAULT_TRANSFER_CAPS,
    ) -> tuple[WorkspaceTransferBook, BeginCommand]:
        _require(type(caps) is TransferCaps)
        _integer(now, 0, 2**53 - 300)
        descriptor = TransferDescriptor(
            binding,
            transfer_id,
            workspace_destination(destination),
            total_bytes,
            content_digest,
            caps,
            now,
            now + caps.lifetime_seconds,
        )
        _require(len(self.transfers) < 64)
        _require(
            sum(item.descriptor.total_bytes for item in self.transfers) + total_bytes
            <= 16 * 1024 * 1024
        )
        for state in self.transfers:
            old = state.descriptor
            _require(old.transfer_id != transfer_id)
            # Conservative case-folding also prevents Windows aliases.
            _require(
                not (
                    old.binding.resource_id == binding.resource_id
                    and old.destination.casefold() == descriptor.destination.casefold()
                )
            )
        state = TransferState(descriptor, _last_time=now)
        return replace(self, transfers=(*self.transfers, state)), BeginCommand(descriptor)

    def acknowledge_begin(
        self, transfer_id: str, receipt: BeginReceipt, *, now: int
    ) -> WorkspaceTransferBook:
        state = self._live(transfer_id, now)
        _require(type(receipt) is BeginReceipt and receipt.descriptor == state.descriptor)
        if state.begin_receipt is not None:
            _require(state.begin_receipt == receipt)
            return self._put(state)
        _require(state.phase == "begin")
        _require(
            all(
                flag is True
                for flag in (
                    receipt.private_regular_staging,
                    receipt.no_symlink_resolution,
                    receipt.exclusive_destination,
                )
            )
        )
        return self._put(replace(state, phase="ready", begin_receipt=receipt))

    def chunk(
        self, transfer_id: str, *, index: int, offset: int, payload: bytes, now: int
    ) -> tuple[WorkspaceTransferBook, ChunkCommand]:
        state = self._live(transfer_id, now)
        descriptor = state.descriptor
        _integer(index, 0, descriptor.caps.max_chunks - 1)
        _integer(offset, 0, descriptor.total_bytes)
        _require(type(payload) is bytes and 0 < len(payload) <= descriptor.caps.max_chunk_bytes)
        receipt = ChunkReceipt(descriptor, index, offset, len(payload), sha256(payload))
        command = ChunkCommand(receipt, payload)
        if index < len(state.chunks):
            _require(state.chunks[index] == receipt)
            _require(state.phase in {"ready", "chunk"})
            return self._put(state), command
        if state._pending is not None:
            _require(state._pending == command)
            return self._put(state), command
        _require(state.phase == "ready" and index == len(state.chunks))
        _require(offset == sum(item.size for item in state.chunks))
        _require(offset + len(payload) <= descriptor.total_bytes)
        return self._put(replace(state, phase="chunk", _pending=command)), command

    def acknowledge_chunk(
        self, transfer_id: str, receipt: ChunkReceipt, *, now: int
    ) -> WorkspaceTransferBook:
        state = self._live(transfer_id, now)
        _require(type(receipt) is ChunkReceipt and receipt.descriptor == state.descriptor)
        _integer(receipt.index, 0, state.descriptor.caps.max_chunks - 1)
        if receipt.index < len(state.chunks):
            _require(receipt == state.chunks[receipt.index])
            return self._put(state)
        _require(state.phase == "chunk" and state._pending is not None)
        pending = state._pending
        if pending is None:
            raise WorkspaceTransferError("workspace transfer refused")
        _require(receipt == pending.receipt)
        return self._put(
            replace(
                state,
                phase="ready",
                chunks=(*state.chunks, receipt),
                _data=(*state._data, pending.payload),
                _pending=None,
            )
        )

    def finalize(
        self, transfer_id: str, *, now: int
    ) -> tuple[WorkspaceTransferBook, FinalizeCommand]:
        state = self._live(transfer_id, now)
        _require(state.phase in {"ready", "finalize"} and state._pending is None)
        _require(sum(item.size for item in state.chunks) == state.descriptor.total_bytes)
        _require(sha256(b"".join(state._data)) == state.descriptor.content_digest)
        command = FinalizeCommand(state.descriptor, len(state.chunks))
        return self._put(replace(state, phase="finalize")), command

    def acknowledge_finalize(
        self, transfer_id: str, receipt: FinalizeReceipt, *, now: int
    ) -> WorkspaceTransferBook:
        state = self.get(transfer_id)
        if state.phase == "published":
            _require(type(receipt) is FinalizeReceipt and receipt == state.final_receipt)
            _integer(now, state._last_time, 2**53)
            return self._put(replace(state, _last_time=now))
        state = self._live(transfer_id, now)
        _require(state.phase == "finalize")
        _require(type(receipt) is FinalizeReceipt and receipt.descriptor == state.descriptor)
        _require(type(receipt.chunk_count) is int and receipt.chunk_count == len(state.chunks))
        _require(
            type(receipt.staged_bytes) is int
            and receipt.staged_bytes == state.descriptor.total_bytes
        )
        _require(receipt.staged_digest == state.descriptor.content_digest)
        _require(
            all(
                flag is True
                for flag in (
                    receipt.file_fsynced,
                    receipt.atomic_no_replace_published,
                    receipt.directory_fsynced,
                )
            )
        )
        return self._put(
            replace(
                state,
                phase="published",
                residue="published",
                final_receipt=receipt,
                _data=(),
            )
        )

    def stop(
        self,
        transfer_id: str,
        *,
        reason: Literal["cancelled", "revoked", "unknown", "expired"],
        now: int,
    ) -> WorkspaceTransferBook:
        state = self.get(transfer_id)
        _integer(now, state._last_time, 2**53)
        _require(reason in {"cancelled", "revoked", "unknown", "expired"})
        if reason == "expired":
            _require(now >= state.descriptor.expires_at)
        if state.phase in {"published", "cancelled", "revoked", "unknown", "expired"}:
            return self._put(replace(state, _last_time=now))
        return self._put(replace(state, phase=reason, _data=(), _pending=None, _last_time=now))
