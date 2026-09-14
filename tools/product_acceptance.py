#!/usr/bin/env python3
"""Repository wrapper for the locked BlueFire product acceptance harness."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from bluefire.product_acceptance_tool import tool_main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(tool_main())
