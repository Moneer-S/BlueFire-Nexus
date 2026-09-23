"""Byte-bound review of the fixed Linux GNU chmod process boundary."""

from tools.provider_gate_common import _sha256_bytes

REVIEWED_ATOMIC_CHMOD_SOURCE_SHA256 = (
    "sha256:979f526aa2a642009784c0ab6e171eeeebe73cfd54e440da7fd7907d3fd082e8"
)
REVIEWED_ATOMIC_CHMOD_SOURCE_BYTES = 12227


def reviewed_atomic_chmod_source(source: bytes) -> bool:
    if type(source) is not bytes or len(source) != REVIEWED_ATOMIC_CHMOD_SOURCE_BYTES:
        return False
    if _sha256_bytes(source) != REVIEWED_ATOMIC_CHMOD_SOURCE_SHA256:
        return False
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return False
    forbidden = ("sh -c", "bash -c", "cmd.exe", "powershell", "shell=true")
    return (
        text.count('Command::new(format!("/proc/self/fd/{}", inspected.fd()))') == 1
        and text.count('.args([mode, "--", &format!("/proc/self/fd/{input_fd}")])') == 1
        and text.count(".env_clear()") == 1
        and text.count("setpgid(0, 0)") == 1
        and text.count("kill(-(self.0.id() as i32), 9)") == 1
        and text.count("The permission operation exceeded its deadline.") == 1
        and not any(token in text.casefold() for token in forbidden)
    )
