#!/usr/bin/env python3
"""Fail closed if the release Compose weakens login-worker isolation."""

import json
import sys
from pathlib import Path


def fail(message):
    raise SystemExit(message)


data = json.load(sys.stdin)
services = data.get("services", {})
workers = [services.get("login-worker-1"), services.get("login-worker-2")]
if any(not isinstance(worker, dict) for worker in workers):
    fail("two login workers are required")

profile_sources = []
for number, worker in enumerate(workers, 1):
    if str(worker.get("user")) != f"1100{number}:12000":
        fail(f"worker {number} must use its dedicated non-root uid")
    if worker.get("network_mode") != "none" or worker.get("read_only") is not True:
        fail(f"worker {number} must be network-none and rootfs-readonly")
    if "ALL" not in worker.get("cap_drop", []):
        fail(f"worker {number} must drop all capabilities")
    if "no-new-privileges:true" not in worker.get("security_opt", []):
        fail(f"worker {number} must set no-new-privileges")
    if "seccomp:deploy/login-worker-seccomp.json" not in worker.get("security_opt", []):
        fail(f"worker {number} must use the scoped Chromium userns seccomp profile")
    if not worker.get("mem_limit") or worker.get("pids_limit") != 320:
        fail(f"worker {number} resource limits are incomplete")
    env = worker.get("environment", {})
    allowed_env = {
        "DISPLAY", "FLOW_URL", "HOME", "LABS_AUTH_URL", "LABS_URL",
        "LOGIN_EGRESS_SOCKET", "LOGIN_PROFILE_DIR",
        "LOGIN_SLOT_NUMBER", "LOGIN_SLOT_SIGNING_PUBLIC_KEY", "LOGIN_WORKER_RUNTIME_DIR",
        "LOGIN_WORKER_SOCKET", "LOG_DIR", "PLAYWRIGHT_BROWSERS_PATH", "RESOLUTION",
    }
    if set(env) - allowed_env:
        fail(f"worker {number} received an unexpected environment field")
    if not str(env.get("LOGIN_SLOT_SIGNING_PUBLIC_KEY") or ""):
        fail(f"worker {number} is missing its public control key")
    mounts = worker.get("volumes", [])
    rw_profiles = []
    runtime_targets = set()
    for mount in mounts:
        if not isinstance(mount, dict):
            fail("Compose JSON long volume syntax expected")
        target = mount.get("target", "")
        if target in {"/app/data", "/app/logs", "/var/run/docker.sock"}:
            fail(f"worker {number} received forbidden mount {target}")
        if target == "/slot/profile" and not mount.get("read_only", False):
            rw_profiles.append(mount.get("source"))
            if mount.get("type") != "volume":
                fail(f"worker {number} Profile must use its dedicated named volume")
        elif target in {"/control", "/egress"}:
            if mount.get("type") != "bind":
                fail(f"worker {number} runtime sockets must use non-persistent binds")
            runtime_targets.add(target)
            if target == "/egress" and not mount.get("read_only", False):
                fail(f"worker {number} egress socket bind must be read-only")
        else:
            fail(f"worker {number} received unexpected mount {target}")
    if len(rw_profiles) != 1:
        fail(f"worker {number} must have exactly one rw Profile mount")
    if runtime_targets != {"/control", "/egress"}:
        fail(f"worker {number} is missing a runtime socket bind")
    tmpfs_targets = {str(item).split(":", 1)[0] for item in worker.get("tmpfs", [])}
    if not {"/tmp", "/run", "/app/data", "/app/logs", "/app/profiles"} <= tmpfs_targets:
        fail(f"worker {number} is missing an isolated tmpfs path")
    profile_sources.extend(rw_profiles)

if len(set(profile_sources)) != 2:
    fail("workers must use different Profile volumes")

control = services.get("token-updater", {})
published = control.get("ports", [])
if len(published) != 1 or published[0].get("host_ip") != "127.0.0.1":
    fail("only the control API may be published on loopback")
for name, service in services.items():
    if name != "token-updater" and service.get("ports"):
        fail(f"{name} must not publish a host port")

policy = json.loads(Path("deploy/login-worker-seccomp.json").read_text())
if policy.get("defaultAction") != "SCMP_ACT_ERRNO":
    fail("worker seccomp policy must deny by default")
comments = {entry.get("comment") for entry in policy.get("syscalls", [])}
required_comments = {
    "Chromium uses chroot after entering its unprivileged user namespace.",
    "Allow only CLONE_NEWUSER among namespace flags for Chromium sandbox unshare.",
    "Allow only CLONE_NEWUSER among namespace flags for Chromium sandbox clone.",
    "Chromium starts its sandbox helper with exactly user, pid, and network namespaces.",
    "Chromium zygote forks CLONE_NEWPID after entering its own user namespace.",
}
if not required_comments <= comments:
    fail("worker seccomp policy is missing a reviewed Chromium sandbox rule")

print("login-slot topology policy: ok")
