#!/usr/bin/env bash
set -euo pipefail

tag="${IMAGE_TAG:-isolation-final}"
project="flow-login-isolation-smoke"
network="flow-login-isolation-smoke-network"
root="$(mktemp -d /tmp/flow-login-isolation-smoke.XXXXXX)"
runtime_root="$root/runtime"
mkdir -p "$root/data" "$root/profiles" "$root/logs" "$runtime_root"
# The final control process drops DAC_OVERRIDE.  These disposable directories
# contain no secret and are removed at exit; make them writable through the
# host bind regardless of a daemon-side uid mapping.
chmod 0711 "$root"
chmod 0777 "$root/data" "$root/profiles" "$root/logs"

cleanup() {
  export LOGIN_SLOT_SIGNING_PRIVATE_KEY=x LOGIN_SLOT_SIGNING_PUBLIC_KEY=x
  export ADMIN_PASSWORD=x CONNECTION_TOKEN=x VNC_PASSWORD=x
  export LOGIN_SMOKE_DATA_DIR="$root/data"
  export LOGIN_SMOKE_PROFILES_DIR="$root/profiles"
  export LOGIN_SMOKE_LOGS_DIR="$root/logs"
  export LOGIN_SLOT_RUNTIME_ROOT="$runtime_root"
  export UPDATER_NETWORK_NAME="$network"
  docker compose -p "$project" \
    -f docker-compose.login-slots.yml \
    -f docker-compose.login-slots.smoke.yml down -v >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  case "$root" in
    /tmp/flow-login-isolation-smoke.*) sudo -n rm -r -- "$root" ;;
    *) echo "refusing to remove unexpected smoke path" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'echo "login slot smoke failed at line $LINENO" >&2' ERR

docker image inspect "flow2api-token-updater-control:$tag" >/dev/null
docker image inspect "flow2api-token-updater-login-worker:$tag" >/dev/null
test "$(docker image inspect -f '{{.Config.User}}' \
  "flow2api-token-updater-login-worker:$tag")" = "11001:12000"
test "$(docker image inspect -f '{{json .Config.Volumes}}' \
  "flow2api-token-updater-login-worker:$tag")" = "null"

docker network create --driver bridge "$network" >/dev/null

read -r private_key public_key < <(python3 - <<'PY'
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private = Ed25519PrivateKey.generate()
encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
print(
    encode(private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )),
    encode(private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )),
)
PY
)

read -r slot1_url slot2_url < <(python3 - <<'PY'
import base64

def page(color, changed, name):
    markup = (
        f'<body tabindex=0 style="background:{color};margin:0;height:100vh" '
        f'onkeydown="this.style.background=\'{changed}\'">{name}'
        '<script>document.body.focus()</script>'
    )
    return "data:text/html;base64," + base64.b64encode(markup.encode()).decode()

print(page("red", "blue", "slot1"), page("green", "yellow", "slot2"))
PY
)

export IMAGE_TAG="$tag"
export LOGIN_SLOT_SIGNING_PRIVATE_KEY="$private_key"
export LOGIN_SLOT_SIGNING_PUBLIC_KEY="$public_key"
export ADMIN_PASSWORD=smoke-admin
export CONNECTION_TOKEN=smoke-connection
export VNC_PASSWORD=smoke-vnc
export UPDATER_PORT=38083
export FLOW2API_URL=http://127.0.0.1:9
export LOGIN_SMOKE_DATA_DIR="$root/data"
export LOGIN_SMOKE_PROFILES_DIR="$root/profiles"
export LOGIN_SMOKE_LOGS_DIR="$root/logs"
export LOGIN_SLOT_RUNTIME_ROOT="$runtime_root"
export UPDATER_NETWORK_NAME="$network"
export LOGIN_SLOT1_LABS_URL="$slot1_url"
export LOGIN_SLOT2_LABS_URL="$slot2_url"
export LOGIN_SLOT1_LABS_AUTH_URL="$slot1_url"
export LOGIN_SLOT2_LABS_AUTH_URL="$slot2_url"

docker compose -p "$project" \
  -f docker-compose.login-slots.yml \
  -f docker-compose.login-slots.smoke.yml up -d --no-build --wait

control="flow2api-token-updater"
workers=(flow-login-worker-1 flow-login-worker-2)

docker exec \
  -e LOGIN_SMOKE_SOCKET_1=/run/login-slot1/worker.sock \
  -e LOGIN_SMOKE_SOCKET_2=/run/login-slot2/worker.sock \
  -e LOGIN_SMOKE_PROXY_URL=http://127.0.0.1:18088 \
  -e PYTHONPATH=/app \
  "$control" python /smoke/smoke_isolated_login_workers.py

printf 'control-only\n' >"$root/data/control-sentinel"
printf 'logs-only\n' >"$root/logs/log-sentinel"
printf 'profiles-parent-only\n' >"$root/profiles/profile-parent-sentinel"

container_pids=()
mount_namespaces=()
pid_namespaces=()
for number in 1 2; do
  worker="${workers[$((number - 1))]}"
  expected_uid="1100$number"
  test "$(docker inspect -f '{{.Config.User}}' "$worker")" = "$expected_uid:12000"
  test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$worker")" = none
  test "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$worker")" = true
  test "$(docker inspect -f '{{.HostConfig.Privileged}}' "$worker")" = false
  test "$(docker inspect -f '{{.RestartCount}}' "$worker")" = 0
  test "$(docker inspect -f '{{.State.OOMKilled}}' "$worker")" = false
  test "$(docker inspect -f '{{.HostConfig.Memory}}' "$worker")" = 2147483648
  test "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$worker")" = 320
  test "$(docker inspect -f '{{.HostConfig.ShmSize}}' "$worker")" = 536870912
  test "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$worker")" = '["ALL"]'

  docker top "$worker" -eo pid,uid | awk 'NR > 1 && $2 == 0 { exit 1 }'
  if docker exec "$worker" /bin/sh -c \
      'for file in /proc/[0-9]*/cmdline; do tr "\0" " " <"$file" 2>/dev/null; echo; done' \
      | grep -E -- '--no-sandbox|--disable-setuid-sandbox'; then
    echo "worker $number launched Chromium without its sandbox" >&2
    exit 1
  fi
  docker exec "$worker" test ! -e /app/data/control-sentinel
  docker exec "$worker" test ! -e /app/logs/log-sentinel
  docker exec "$worker" test ! -e /app/profiles/profile-parent-sentinel
  if docker exec -i "$worker" python - <<'PY'
import socket
try:
    socket.create_connection(("169.254.169.254", 80), timeout=1)
except OSError:
    raise SystemExit(1)
PY
  then
    echo "network-none worker reached a non-loopback address" >&2
    exit 1
  fi

  pid="$(docker inspect -f '{{.State.Pid}}' "$worker")"
  container_pids+=("$pid")
  mount_namespaces+=("$(sudo -n readlink "/proc/$pid/ns/mnt")")
  pid_namespaces+=("$(sudo -n readlink "/proc/$pid/ns/pid")")

  current_pids="$(docker exec "$worker" cat /sys/fs/cgroup/pids.current)"
  peak_memory="$(docker exec "$worker" cat /sys/fs/cgroup/memory.peak)"
  oom_kill="$(docker exec "$worker" awk '/^oom_kill / {print $2}' /sys/fs/cgroup/memory.events)"
  echo "worker $number resource bounds: pids=$current_pids peak_bytes=$peak_memory oom_kills=$oom_kill"
  test "$current_pids" -lt 256
  test "$peak_memory" -lt 1717986918
  test "$oom_kill" = 0
done

test "${container_pids[0]}" != "${container_pids[1]}"
test "${mount_namespaces[0]}" != "${mount_namespaces[1]}"
test "${pid_namespaces[0]}" != "${pid_namespaces[1]}"

profile_sources=()
for worker in "${workers[@]}"; do
  source="$(docker inspect "$worker" | jq -r \
    '.[0].Mounts[] | select(.Destination == "/slot/profile") | .Source')"
  profile_sources+=("$source")
  test -n "$source"
done
test "${profile_sources[0]}" != "${profile_sources[1]}"

echo "isolated login worker Compose smoke: ok"
