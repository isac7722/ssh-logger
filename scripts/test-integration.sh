#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
# This project and volume are only for synthetic integration fixtures.
cleanup() { docker compose -f tests/compose.yaml down -v; }
trap cleanup EXIT
docker compose -f tests/compose.yaml up -d --wait
python3 scripts/integration.py
docker run --rm --network host \
 -v "$PWD/tests/browser:/work" \
 -v "$PWD/tests/browser/test-results:/tmp/sshlogger-browser-results" \
 -v "$PWD/.secrets/admin_password:/run/test-password:ro" \
 -w /work mcr.microsoft.com/playwright:v1.63.0-noble \
 sh -c 'npm ci && npm test'
