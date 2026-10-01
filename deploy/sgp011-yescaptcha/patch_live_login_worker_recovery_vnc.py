"""Restore VNC when a quarantined login slot reopens its retained Profile.

Patch only the recovery method in the deployed worker. Production slots carry
different accepted project validators, so replacing the whole module is unsafe.
"""

import argparse
from pathlib import Path


def patch(source: str) -> str:
    start = source.index("    async def recover(")
    end = source.index("    async def validate(", start)
    recovery = source[start:end]
    anchor = '            self.state = "starting_browser"\n            try:\n                await self._open_browser()\n'
    if recovery.count(anchor) != 1:
        raise ValueError("expected exactly one recovery browser launch anchor")
    recovery = recovery.replace(
        anchor,
        '            self.state = "starting_browser"\n'
        '            try:\n'
        '                # Reconciliation abort stops x11vnc. A new invitation\n'
        '                # must restore the desktop before opening its browser.\n'
        '                await self._start_vnc()\n'
        '                await self._open_browser()\n',
        1,
    )
    updated = source[:start] + recovery + source[end:]
    compile(updated, "login_worker.py", "exec")
    return updated


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    args.source.write_text(patch(source), encoding="utf-8")
