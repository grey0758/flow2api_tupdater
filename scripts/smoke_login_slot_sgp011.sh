#!/usr/bin/env bash
set -euo pipefail

root="${1:?stage root required}"
case "$root" in
  /opt/flow-login-slots-stage.*) ;;
  *) echo "unexpected stage root" >&2; exit 2 ;;
esac

project=flow-login-slots-final-smoke
compose="$root/docker-compose.login-slots.yml"
nginx_link=/etc/nginx/sites-enabled/flow-login-slot-smoke
htpasswd=/run/flow-login-slot-smoke.htpasswd
runner=flow-login-slot-https-runner
coord="$root/coord"

cleanup() {
  sudo docker logs "$runner" 2>&1 | tail -60 || true
  sudo docker rm -f "$runner" >/dev/null 2>&1 || true
  export IMAGE_TAG=secure-final LOGIN_SLOT_SIGNING_PRIVATE_KEY=x
  export LOGIN_SLOT_SIGNING_PUBLIC_KEY=x ADMIN_PASSWORD=x CONNECTION_TOKEN=x
  export VNC_PASSWORD=x LOGIN_SLOT_RUNTIME_ROOT="$root/runtime"
  export UPDATER_NETWORK_NAME=sgp011-flow-updater-v34 UPDATER_PORT=38083
  sudo -E docker compose -p "$project" -f "$compose" down -v >/dev/null 2>&1 || true
  sudo rm -f -- "$nginx_link" "$htpasswd"
  sudo nginx -t >/dev/null 2>&1 && sudo systemctl reload nginx || true
}
trap cleanup EXIT
trap 'echo "sgp011 final-topology smoke failed at line $LINENO" >&2' ERR

sudo rm -f -- "$coord/rfb-ready" "$coord/control-restarted" \
  "$root/data/profiles.db" "$root/data/profiles.db-wal" "$root/data/profiles.db-shm"

read -r private_key public_key < <(
  sudo docker run --rm -i --entrypoint python \
    flow2api-token-updater-login-worker:reconcile-final - <<'PY'
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
enc = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
print(enc(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())), enc(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
PY
)
admin_password="$(openssl rand -hex 32)"
basic_password="$(openssl rand -hex 32)"
vnc_password="$(openssl rand -hex 16)"

basic_hash="$(openssl passwd -apr1 "$basic_password")"
printf 'slot-smoke:%s\n' "$basic_hash" | sudo tee "$htpasswd" >/dev/null
sudo chown root:www-data "$htpasswd"
sudo chmod 0640 "$htpasswd"
sudo ln -s "$root/deploy/flow-updater-slot-smoke.nginx" "$nginx_link"
sudo nginx -t >/dev/null
sudo systemctl reload nginx

slot1_url="$(python3 - <<'PY'
import base64
html = "<body tabindex=0 style='background:red;margin:0;height:100vh' onkeydown=\"this.style.background='blue'\">slot1<script>document.body.focus()</script>"
print("data:text/html;base64," + base64.b64encode(html.encode()).decode())
PY
)"
slot2_url="$(python3 - <<'PY'
import base64
html = "<body tabindex=0 style='background:green;margin:0;height:100vh' onkeydown=\"this.style.background='yellow'\">slot2<script>document.body.focus()</script>"
print("data:text/html;base64," + base64.b64encode(html.encode()).decode())
PY
)"

export IMAGE_TAG=secure-final
export LOGIN_SLOT_SIGNING_PRIVATE_KEY="$private_key"
export LOGIN_SLOT_SIGNING_PUBLIC_KEY="$public_key"
export ADMIN_PASSWORD="$admin_password"
export CONNECTION_TOKEN=smoke-no-receiver
export VNC_PASSWORD="$vnc_password"
export FLOW2API_URL=http://127.0.0.1:9
export UPDATER_PORT=38083
export LOGIN_SLOT_RUNTIME_ROOT="$root/runtime"
export UPDATER_NETWORK_NAME=sgp011-flow-updater-v34
export LOGIN_SLOT1_LABS_URL="$slot1_url"
export LOGIN_SLOT2_LABS_URL="$slot2_url"
export LOGIN_SLOT1_LABS_AUTH_URL="$slot1_url"
export LOGIN_SLOT2_LABS_AUTH_URL="$slot2_url"

sudo -E docker compose -p "$project" -f "$compose" up -d --no-build --wait

for _ in $(seq 1 120); do
  curl -kfsS https://127.0.0.1:38443/api/auth/check \
    -u "slot-smoke:$basic_password" -H 'Host: flow-updater.opencodex.uk:38443' \
    >/dev/null 2>&1 && break
  sleep 0.25
done
curl -kfsS https://127.0.0.1:38443/api/auth/check \
  -u "slot-smoke:$basic_password" -H 'Host: flow-updater.opencodex.uk:38443' \
  >/dev/null

for worker in flow-login-worker-1 flow-login-worker-2; do
  test "$(sudo docker inspect -f '{{.State.Status}} {{.RestartCount}} {{.State.OOMKilled}}' "$worker")" = "running 0 false"
  test "$(sudo docker inspect -f '{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' "$worker")" = "none true false 2147483648 320"
  sudo docker top "$worker" -eo pid,uid | awk 'NR > 1 && $2 == 0 { exit 1 }'
  sudo docker exec "$worker" test ! -e /app/data/profiles.db
  sudo docker exec "$worker" test ! -e /app/logs/supervisord.log
  if sudo docker exec "$worker" sh -c 'tr "\0" "\n" </proc/1/environ' \
      | grep -Eq '^(ADMIN_PASSWORD|API_KEY|CONNECTION_TOKEN|LOGIN_SLOT_SIGNING_PRIVATE_KEY)='; then
    echo "$worker received a management secret" >&2
    exit 1
  fi
done

mapfile -t profile_sources < <(
  sudo docker inspect flow-login-worker-1 flow-login-worker-2 | python3 -c '
import json,sys
for container in json.load(sys.stdin):
    values=[m["Source"] for m in container["Mounts"] if m["Destination"]=="/slot/profile"]
    assert len(values)==1
    print(values[0])'
)
test "${profile_sources[0]}" != "${profile_sources[1]}"

sudo docker run -d --name "$runner" --network host \
  --add-host flow-updater.opencodex.uk:127.0.0.1 \
  -v "$coord:/coord" \
  -v "$root/scripts/smoke_login_slot_https.py:/smoke.py:ro" \
  -e LOGIN_SMOKE_HTTPS_BASE=https://flow-updater.opencodex.uk:38443 \
  -e LOGIN_SMOKE_ADMIN_PASSWORD="$admin_password" \
  -e LOGIN_SMOKE_BASIC_USER=slot-smoke \
  -e LOGIN_SMOKE_BASIC_PASSWORD="$basic_password" \
  flow2api-token-updater-control:secure-final python /smoke.py >/dev/null

for _ in $(seq 1 360); do
  sudo test -f "$coord/rfb-ready" && break
  test "$(sudo docker inspect -f '{{.State.Running}}' "$runner")" = true
  sleep 0.25
done
sudo test -f "$coord/rfb-ready"

for number in 1 2; do
  worker="flow-login-worker-$number"
  current_pids="$(sudo docker exec "$worker" cat /sys/fs/cgroup/pids.current)"
  peak_memory="$(sudo docker exec "$worker" cat /sys/fs/cgroup/memory.peak)"
  oom_kill="$(sudo docker exec "$worker" awk '/^oom_kill / {print $2}' /sys/fs/cgroup/memory.events)"
  test "$current_pids" -lt 256
  test "$peak_memory" -lt 1717986918
  test "$oom_kill" = 0
  echo "sgp011 worker $number bounds: pids=$current_pids peak_bytes=$peak_memory oom_kills=$oom_kill"
done

# Explicit chaos: worker state must fail closed, then the control plane must
# revoke in-memory invitations and reconcile both dirty Profile volumes.
sudo docker restart flow-login-worker-1 >/dev/null
for _ in $(seq 1 120); do
  test "$(sudo docker inspect -f '{{.State.Health.Status}}' flow-login-worker-1)" = healthy && break
  sleep 0.25
done
test "$(sudo docker inspect -f '{{.State.Health.Status}}' flow-login-worker-1)" = healthy
sudo docker restart flow2api-token-updater >/dev/null
for _ in $(seq 1 120); do
  curl -kfsS https://127.0.0.1:38443/api/auth/check \
    -u "slot-smoke:$basic_password" -H 'Host: flow-updater.opencodex.uk:38443' \
    >/dev/null 2>&1 && break
  sleep 0.25
done
sudo touch "$coord/control-restarted"

exit_code="$(sudo docker wait "$runner")"
sudo docker logs "$runner"
test "$exit_code" = 0
test "$(sudo docker inspect -f '{{.State.OOMKilled}}' flow-login-worker-1)" = false
test "$(sudo docker inspect -f '{{.State.OOMKilled}}' flow-login-worker-2)" = false
echo "sgp011 final HTTPS two-slot smoke: ok"
