"""Scheduling policy for low-cost destination checks and browser refreshes."""

from __future__ import annotations

from typing import Any


# Destination status checks are cheap and do not touch the retained browser.
# Keep them frequent enough that a restart or a busy execution gate cannot
# consume the whole one-hour Flow2API refresh-warning window.  The configured
# refresh interval remains the minimum cadence for an otherwise healthy
# profile and is deliberately not shortened by this policy.
MAX_STATUS_POLL_MINUTES = 5


def status_poll_interval_minutes(refresh_interval: Any) -> int:
    """Return the bounded scheduler tick without changing refresh cadence."""
    try:
        configured = int(refresh_interval)
    except (TypeError, ValueError):
        configured = MAX_STATUS_POLL_MINUTES
    return min(MAX_STATUS_POLL_MINUTES, max(1, configured))
