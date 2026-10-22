"""Single dependency-neutral product version authority."""

import re

__version__ = "3.0.0rc2"

_PRODUCT_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:rc(0|[1-9][0-9]*))?$"
)


def native_runner_version(product_version: str) -> str:
    """Project normalized stable/RC PEP 440 versions to exact SemVer spelling."""

    if not isinstance(product_version, str):
        raise ValueError("product version must be a normalized stable or RC version")
    match = _PRODUCT_VERSION.fullmatch(product_version)
    if match is None:
        raise ValueError("product version must be a normalized stable or RC version")
    major, minor, patch, rc = match.groups()
    stable = f"{major}.{minor}.{patch}"
    return stable if rc is None else f"{stable}-rc{rc}"


__all__ = ["__version__", "native_runner_version"]
