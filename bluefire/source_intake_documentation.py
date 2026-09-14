"""Public attribution and source identity behind the README's intake references."""

from __future__ import annotations

import re

from .source_intake_package import (
    LICENSE_ASSET,
    LICENSE_ID,
    LICENSE_SHA256,
    REQUIRED_NOTICE,
    SOURCE_ASSET,
    SOURCE_COMMIT,
    SOURCE_SHA256,
)


def source_intake_documentation_complete(notices: str, guide: str, readme: str) -> bool:
    # The README introduces the integration; its linked documents retain the exact
    # reviewed identity and attribution, without duplicating an asset inventory there.
    required = (
        REQUIRED_NOTICE,
        LICENSE_ID,
        SOURCE_COMMIT,
        SOURCE_SHA256.removeprefix("sha256:"),
        SOURCE_ASSET,
        LICENSE_ASSET,
        LICENSE_SHA256.removeprefix("sha256:"),
        "T1082",
    )
    references = ("docs/SOURCE_INTAKE.md", "THIRD_PARTY_NOTICES.md")
    return (
        all(value in notices for value in required)
        and all(value in " ".join(guide.split()) for value in required)
        and "T1082" in readme
        and all(
            re.search(r"(?<!!)\[[^\]\r\n]+\]\(" + re.escape(path) + r"\)", readme)
            for path in references
        )
    )
