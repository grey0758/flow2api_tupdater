"""Container-only smoke test for the two real desktop/browser stacks."""
import asyncio
import json
import subprocess

import websockets

from token_updater.config import config
from token_updater.login_slots import LoginSlots


PROGRAMS = tuple(
    f"slot{number}-{service}"
    for number in (1, 2)
    for service in ("xvfb", "fluxbox", "x11vnc", "novnc")
)
PORTS = (5901, 5902, 6081, 6082)


def supervisor_states() -> dict[str, str]:
    result = subprocess.run(
        ["supervisorctl", "-c", "/etc/supervisor/conf.d/supervisord.conf", "status", *PROGRAMS],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode not in {0, 3}:
        raise RuntimeError("supervisor status could not be read")
    output = result.stdout
    states = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            states[parts[0]] = parts[1]
    return states


def cgroup_memory() -> dict[str, int | None]:
    values = {}
    for label, path in (
        ("current_bytes", "/sys/fs/cgroup/memory.current"),
        ("peak_bytes", "/sys/fs/cgroup/memory.peak"),
    ):
        try:
            values[label] = int(open(path, encoding="ascii").read().strip())
        except (OSError, ValueError):
            values[label] = None
    return values


async def listening(port: int) -> bool:
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        return False
    writer.close()
    await writer.wait_closed()
    return True


async def rfb_handshake(port: int) -> str:
    async with websockets.connect(
        f"ws://127.0.0.1:{port}/websockify", subprotocols=["binary"]
    ) as socket:
        greeting = await asyncio.wait_for(socket.recv(), timeout=10)
    if not isinstance(greeting, bytes) or not greeting.startswith(b"RFB "):
        raise AssertionError(f"slot {port} did not return an RFB greeting")
    return greeting.decode("ascii", errors="replace").strip()


async def main() -> None:
    config.labs_url = "data:text/html,<title>isolated-login-slot-smoke</title>"
    manager = LoginSlots()
    profiles = (
        {"id": 9001, "name": "smoke-slot-one", "proxy_enabled": False},
        {"id": 9002, "name": "smoke-slot-two", "proxy_enabled": False},
    )
    try:
        first, second = await asyncio.gather(*(manager.launch(profile) for profile in profiles))
        await asyncio.sleep(1)
        active = {
            "slots": sorted((first.number, second.number)),
            "displays": sorted((first.display, second.display)),
            "profile_ids": sorted((first.profile_id, second.profile_id)),
            "contexts_distinct": first.context is not second.context,
            "ports": {str(port): await listening(port) for port in PORTS},
            "rfb": {
                "slot1": await rfb_handshake(6081),
                "slot2": await rfb_handshake(6082),
            },
            "memory": cgroup_memory(),
            "services": supervisor_states(),
        }
        assert active["slots"] == [1, 2]
        assert active["displays"] == [":101", ":102"]
        assert active["profile_ids"] == [9001, 9002]
        assert active["contexts_distinct"]
        assert all(active["ports"].values())
        assert all(value.startswith("RFB ") for value in active["rfb"].values())
        assert all(state == "RUNNING" for state in active["services"].values())
        print(json.dumps({"active": active}, sort_keys=True), flush=True)
    finally:
        await manager.stop()
    await asyncio.sleep(1)
    stopped = {
        "ports": {str(port): await listening(port) for port in PORTS},
        "memory": cgroup_memory(),
        "services": supervisor_states(),
    }
    assert not any(stopped["ports"].values())
    assert all(state == "STOPPED" for state in stopped["services"].values())
    print(json.dumps({"stopped": stopped}, sort_keys=True), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
