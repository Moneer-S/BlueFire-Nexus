#!/usr/bin/env bash
# scripts/bluefire.sh
# Usage:
#   ./scripts/bluefire.sh --profile apt29 --ai --exfil dns

PROFILE=""
AI_ENABLED="false"
EXFIL=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --ai)
      AI_ENABLED="true"
      shift
      ;;
    --exfil)
      EXFIL="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      shift
      ;;
  esac
done

echo "[BlueFire] Running with profile='$PROFILE', AI='$AI_ENABLED', exfil='$EXFIL'"

# Call the Python entry point (see src/run_scenario.py)
python3 -m src.run_scenario --profile "$PROFILE" --ai "$AI_ENABLED" --exfil "$EXFIL"

exit 0
