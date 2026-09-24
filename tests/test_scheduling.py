from token_updater.scheduling import (
    MAX_STATUS_POLL_MINUTES,
    status_poll_interval_minutes,
)


def test_status_poll_is_independent_from_long_refresh_cadence():
    assert status_poll_interval_minutes(120) == MAX_STATUS_POLL_MINUTES
    assert status_poll_interval_minutes(1440) == MAX_STATUS_POLL_MINUTES


def test_status_poll_preserves_shorter_configured_interval():
    assert status_poll_interval_minutes(1) == 1
    assert status_poll_interval_minutes(3) == 3


def test_status_poll_fails_closed_to_a_bounded_positive_value():
    assert status_poll_interval_minutes(0) == 1
    assert status_poll_interval_minutes(-10) == 1
    assert status_poll_interval_minutes("invalid") == MAX_STATUS_POLL_MINUTES
