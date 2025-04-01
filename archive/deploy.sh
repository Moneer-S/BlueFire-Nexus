#!/bin/bash
# archive/deploy.sh
# (Originally scripts/deploy.sh)

# Note: This script uses docker-compose to set up a test environment.
# It is currently BROKEN as it relies on a missing docker-compose.yml file.
# It also relies on the output of the archived build.sh (e.g., dist/sample.py).

echo "[Archive Deploy Script - WARNING]"
echo "This script is non-functional due to missing docker-compose.yml and reliance on archived build artifacts."
exit 1 # Prevent accidental execution

# --- Original (Non-functional) Commands Below ---

set -e

echo "[!] WARNING: This must ONLY run in isolated lab environments!"

# Check for docker-compose file (which is missing)
if [ ! -f "docker-compose.yml" ]; then
    echo "[X] Error: docker-compose.yml not found. Cannot proceed."
    exit 1
fi

# Build Docker test environment
echo "Attempting docker-compose build (will likely fail)..."
docker-compose build --no-cache || {
    echo "[X] Failed to build containers (as expected without docker-compose.yml)"
    exit 1
}

# Start monitoring stack
echo "Attempting to start monitoring stack (will likely fail)..."
docker-compose up -d splunk elasticsearch

# Check if build output directory exists (e.g., dist/ from archived build.sh)
BUILD_OUTPUT_DIR="dist" # Or dist_archive? Needs clarification
MALWARE_SCRIPT="sample.py" # Assumed name
MALWARE_PATH="$BUILD_OUTPUT_DIR/$MALWARE_SCRIPT"

if [ ! -f "$MALWARE_PATH" ]; then
    echo "[X] Error: Test malware script not found at $MALWARE_PATH. Did the archived build script run?"
    # Attempt cleanup of potentially started services
    echo "Attempting docker-compose down..."
    docker-compose down -v --remove-orphans
    exit 1
fi

# Deploy test malware with safety limits
echo "Attempting to run malware in container (will likely fail)..."
docker run --rm -it \
  --network bluefire_test `# Network name defined in missing docker-compose.yml` \
  -v "$(pwd)/$BUILD_OUTPUT_DIR":/malware \
  bluefire_nexus `# Service name defined in missing docker-compose.yml` \
  python3 "/malware/$MALWARE_SCRIPT" --test-mode --max-runtime 3600

# Attempt cleanup
echo "Attempting final docker-compose down..."
docker-compose down -v --remove-orphans

echo "[+] Archived deployment script finished (simulation)." 