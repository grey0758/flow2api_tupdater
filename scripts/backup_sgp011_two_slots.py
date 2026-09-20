#!/usr/bin/env python3
"""Create scoped online predeploy backups without reading secret values."""

import json
import os
import pathlib
import sqlite3
import subprocess
import sys


backup = pathlib.Path(sys.argv[1])
source = "/opt/flow2api-token-updater-v34/data/profiles.db"
with sqlite3.connect(source) as origin, sqlite3.connect(backup / "profiles.db") as target:
    origin.backup(target)
assert sqlite3.connect(backup / "profiles.db").execute(
    "pragma integrity_check"
).fetchone()[0] == "ok"

mounts = json.loads(subprocess.check_output([
    "docker", "inspect", "flow2api-target-stage",
]))[0]["Mounts"]
candidates = []
for mount in mounts:
    source = mount.get("Source", "")
    if mount.get("Type") == "bind" and os.path.isdir(source):
        for name in ("flow.db",):
            path = os.path.join(source, name)
            if os.path.isfile(path):
                candidates.append(path)
if len(candidates) != 1:
    raise SystemExit("expected exactly one mounted Flow SQLite database")
with sqlite3.connect(candidates[0]) as origin, sqlite3.connect(backup / "flow.db") as target:
    origin.backup(target)
flow = sqlite3.connect(backup / "flow.db")
assert flow.execute("pragma integrity_check").fetchone()[0] == "ok"
tables = {
    row[0] for row in flow.execute(
        "select name from sqlite_master where type='table'"
    )
}
eligible = []
if "tokens" in tables:
    columns = {row[1] for row in flow.execute("pragma table_info(tokens)")}
    active = "is_active" if "is_active" in columns else "active"
    image = (
        "is_image_enabled" if "is_image_enabled" in columns
        else "image_enabled" if "image_enabled" in columns else None
    )
    where = f"coalesce({active},0)=1"
    if image:
        where += f" and coalesce({image},0)=1"
    eligible = [
        row[0] for row in flow.execute(
            f"select id from tokens where {where} order by id"
        )
    ]
tasks = (
    flow.execute("select count(*) from tasks").fetchone()[0]
    if "tasks" in tables else -1
)
max_log = (
    flow.execute("select coalesce(max(id),0) from request_logs").fetchone()[0]
    if "request_logs" in tables else -1
)
(backup / "boundary.txt").write_text(
    "updater_integrity=ok\n"
    "flow_integrity=ok\n"
    f"eligible_ids={','.join(map(str, eligible))}\n"
    f"tasks={tasks}\n"
    f"flow_max_log={max_log}\n"
)
for name in ("profiles.db", "flow.db", "boundary.txt"):
    os.chmod(backup / name, 0o600)
print("backup=" + str(backup))
print("eligible_ids=" + ",".join(map(str, eligible)))
print("tasks=" + str(tasks))
print("flow_max_log=" + str(max_log))
