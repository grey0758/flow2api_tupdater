#!/usr/bin/env bash
set -euo pipefail

export DB_PATH="${DB_PATH:-/tmp/flow2api-updater-ci/profiles.db}"
export LOG_DIR="${LOG_DIR:-/tmp/flow2api-updater-ci/logs}"
mkdir -p "$(dirname "$DB_PATH")" "$LOG_DIR"

python -m compileall -q token_updater tests
python -m pytest -q

test "$(grep -c '^\[program:slot[12]-xvfb\]$' supervisord.conf)" -eq 2
test "$(grep -c '^\[program:slot[12]-novnc\]$' supervisord.conf)" -eq 2
! grep -Eq '(^|[^0-9])(5901|5902|6081|6082):' docker-compose.yml
