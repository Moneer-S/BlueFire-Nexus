#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/bluefire.sh --profile basic_discovery
#   ./scripts/bluefire.sh --scenario scenarios/apt29_credential_access.yaml
exec python3 -m src.run_scenario "$@"
