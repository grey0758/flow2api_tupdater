#!/usr/bin/env python3
"""Write the production Compose environment without emitting secret values."""

import json
import os
import secrets
import subprocess


container = json.loads(subprocess.check_output([
    "docker", "inspect", "sgp011-flow2api-token-updater-v34",
]))[0]
environment = {
    item.split("=", 1)[0]: item.split("=", 1)[1]
    for item in container["Config"]["Env"] if "=" in item
}
key_source = r"""
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
print(encode(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())))
print(encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
"""
private_key, public_key = subprocess.check_output([
    "docker", "run", "--rm", "--entrypoint", "python",
    "flow2api-token-updater-login-worker:secure-final", "-c", key_source,
], text=True).splitlines()
required = {
    "IMAGE_TAG": "secure-final",
    "CONTROL_CONTAINER_NAME": "sgp011-flow2api-token-updater-v34",
    "LOGIN_SLOT_SIGNING_PRIVATE_KEY": private_key,
    "LOGIN_SLOT_SIGNING_PUBLIC_KEY": public_key,
    "ADMIN_PASSWORD": environment.get("ADMIN_PASSWORD", ""),
    "API_KEY": environment.get("API_KEY", ""),
    "CONNECTION_TOKEN": environment.get("CONNECTION_TOKEN", ""),
    "VNC_PASSWORD": secrets.token_urlsafe(24),
    "FLOW2API_URL": environment.get("FLOW2API_URL", "http://172.19.240.1:18087"),
    "REFRESH_INTERVAL": environment.get("REFRESH_INTERVAL", "120"),
    "FLOW_PROTOCOL_REFRESH_ENABLED": environment.get(
        "FLOW_PROTOCOL_REFRESH_ENABLED", "false"
    ),
    "SESSION_TTL_MINUTES": environment.get("SESSION_TTL_MINUTES", "1440"),
    "UPDATER_PORT": "18083",
    "LOGIN_SLOT_RUNTIME_ROOT": "/run/flow2api-login-slots",
    "UPDATER_NETWORK_NAME": "sgp011-flow-updater-v34",
}
if not required["ADMIN_PASSWORD"] or not required["CONNECTION_TOKEN"]:
    raise SystemExit("existing control secrets unavailable")
path = "/opt/flow2api-token-updater-v34/.env.login-slots"
with open(path, "w") as output:
    for key, value in required.items():
        output.write(key + "=" + json.dumps(value) + "\n")
os.chmod(path, 0o600)
print("production env prepared with fields=" + ",".join(required))
