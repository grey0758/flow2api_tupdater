#!/usr/bin/env bash
set -euo pipefail

export DB_PATH="${DB_PATH:-/tmp/flow2api-updater-ci/profiles.db}"
export LOG_DIR="${LOG_DIR:-/tmp/flow2api-updater-ci/logs}"
mkdir -p "$(dirname "$DB_PATH")" "$LOG_DIR"

python -m compileall -q token_updater tests
python -m pytest -q

private_key="$(python - <<'PY'
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
print(base64.urlsafe_b64encode(raw).decode().rstrip('='))
PY
)"
public_key="$(LOGIN_SLOT_PRIVATE_KEY="$private_key" python - <<'PY'
import base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
raw = base64.urlsafe_b64decode(os.environ['LOGIN_SLOT_PRIVATE_KEY'] + '===')
pub = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print(base64.urlsafe_b64encode(pub).decode().rstrip('='))
PY
)"
LOGIN_SLOT_SIGNING_PUBLIC_KEY="$public_key" \
LOGIN_SLOT_SIGNING_PRIVATE_KEY="$private_key" \
ADMIN_PASSWORD=ci-admin CONNECTION_TOKEN=ci-connection VNC_PASSWORD=ci-vnc \
docker compose -f docker-compose.login-slots.yml config --format json \
  | python scripts/check_login_slot_topology.py

! grep -R -E 'packages:[[:space:]]*write|push:[[:space:]]*true|docker/login-action|docker[[:space:]]+push' .github/workflows
