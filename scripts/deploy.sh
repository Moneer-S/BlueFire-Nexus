#!/bin/bash
# scripts/deploy.sh
set -e

echo "[!] WARNING: This must ONLY run in isolated lab environments!"

# Build Docker test environment
docker-compose build --no-cache || {
    echo "[X] Failed to build containers"
    exit 1
}

# Start monitoring stack
docker-compose up -d splunk elasticsearch

# Deploy test malware with safety limits
docker run --rm -it \
  --network bluefire_test \
  -v $(pwd)/dist:/malware \
  bluefire_nexus \
  python3 /malware/sample.py --test-mode --max-runtime 3600

echo "[+] Deployment complete. Monitor security tools for detection events."