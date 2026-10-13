"""Finite Windows generated-file DACL recipe, not an ACL mutation authority."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

FILE_OWNER_ACCESS = 0x001F01FF
FILE_READER_ACCESS = 0x00120089
FILE_READER_METADATA = 0x00120080
DIRECTORY_READER_ACCESS = 0x001200A0
_ACCOUNT_SID = re.compile(
    r"S-1-5-21-([1-9][0-9]{0,9})-([1-9][0-9]{0,9})-([1-9][0-9]{0,9})-([1-9][0-9]{0,9})\Z"
)


class WindowsFileAccessPolicyError(ValueError):
    """The fixed generated-resource policy cannot represent these identities."""


def _account_sid(value: str) -> tuple[int, int, int, int]:
    match = _ACCOUNT_SID.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise WindowsFileAccessPolicyError("Windows file-access account identity is invalid")
    numbers = tuple(int(part) for part in match.groups())
    if any(number > 0xFFFFFFFF for number in numbers) or numbers[-1] < 1000:
        raise WindowsFileAccessPolicyError("Windows file-access account identity is unsupported")
    return numbers[0], numbers[1], numbers[2], numbers[3]


@dataclass(frozen=True)
class WindowsFileAccessPolicy:
    """An exact two-account recipe for one independently enrolled disposable lab.

    A common SID prefix is only a syntactic account-authority check. It does not
    establish a local account, distinct process, restricted token or enrollment.
    No SDDL from this value may be applied without the separate resource receipt,
    reviewed control operation and fresh identity/descriptor checks.
    """

    owner_sid: str = field(repr=False)
    reader_sid: str = field(repr=False)

    def __post_init__(self) -> None:
        owner, reader = _account_sid(self.owner_sid), _account_sid(self.reader_sid)
        if owner[:3] != reader[:3] or owner == reader:
            raise WindowsFileAccessPolicyError(
                "Windows file-access accounts are not a distinct pair"
            )

    def file_sddl(self, state: Literal["readable", "metadata_only"]) -> str:
        if state not in ("readable", "metadata_only"):
            raise WindowsFileAccessPolicyError("Windows file-access state is unsupported")
        reader_mask = FILE_READER_ACCESS if state == "readable" else FILE_READER_METADATA
        return self._sddl(reader_mask)

    def directory_sddl(self) -> str:
        """Metadata and traverse, without listing, writing or inherited ACEs."""
        return self._sddl(DIRECTORY_READER_ACCESS)

    def _sddl(self, reader_mask: int) -> str:
        return (
            f"O:{self.owner_sid}D:P"
            f"(A;;0x{FILE_OWNER_ACCESS:08x};;;{self.owner_sid})"
            f"(A;;0x{reader_mask:08x};;;{self.reader_sid})"
        )
