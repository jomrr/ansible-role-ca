"""Shared certificate renewal policy helpers for CA role modules."""

from __future__ import annotations

import datetime as _dt
from typing import Any

from ansible.module_utils.ca_time import (  # type: ignore[import-not-found,import-untyped]
    now_utc,
    parse_datetime,
)


def _bool(value: Any) -> bool:
    """Return a predictable boolean for renewal policy values."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Any, default: int = 0) -> int:
    """Return an integer with an empty-value default."""
    if value in (None, ""):
        return default
    return int(value)


def renewal_policy(value: Any) -> dict[str, Any]:
    """Return normalized non-secret renewal policy values."""
    policy = value if isinstance(value, dict) else {}
    return {
        "warn_before_days": _int(policy.get("warn_before_days"), 0),
        "renew_before_days": _int(policy.get("renew_before_days"), 0),
        "renew_at": str(policy.get("renew_at") or ""),
        "rekey": _bool(policy.get("rekey", False)),
    }


def renewal_datetime(value: Any) -> _dt.datetime | None:
    """Parse an optional renewal timestamp."""
    return parse_datetime(value)


def renewal_decision(
    *,
    force: bool,
    not_before: _dt.datetime | None,
    not_after: _dt.datetime | None,
    policy_value: Any,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Return renewal and rekey decisions for an existing certificate."""
    policy = renewal_policy(policy_value)
    current_time = now if now is not None else now_utc()
    decision: dict[str, Any] = {
        "renew": False,
        "rekey": False,
        "reason": "",
        "warning": False,
        "days_remaining": None,
        "policy": policy,
    }
    if force:
        decision.update({"renew": True, "rekey": True, "reason": "force"})
        return decision
    if not_before is None or not_after is None:
        decision["reason"] = "missing"
        return decision

    seconds_remaining = (not_after - current_time).total_seconds()
    decision["days_remaining"] = max(0, int(seconds_remaining // 86400))

    if policy["warn_before_days"] > 0:
        warning_at = not_after - _dt.timedelta(days=policy["warn_before_days"])
        decision["warning"] = current_time >= warning_at

    if not_after <= current_time:
        decision.update({"renew": True, "reason": "expired"})
    else:
        renew_at = renewal_datetime(policy["renew_at"])
        if renew_at is not None and not_before < renew_at <= current_time:
            decision.update({"renew": True, "reason": "scheduled"})
        elif policy["renew_before_days"] > 0:
            renew_window = not_after - _dt.timedelta(days=policy["renew_before_days"])
            if current_time >= renew_window:
                decision.update({"renew": True, "reason": "renewal_window"})

    if decision["renew"] and policy["rekey"]:
        decision["rekey"] = True
    return decision


def renewal_status(
    certificate: dict[str, Any],
    policy_value: Any,
    *,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Return renewal status for a certificate summary and policy."""
    policy = renewal_policy(policy_value)
    current_time = now if now is not None else now_utc()
    not_before = parse_datetime(certificate["not_valid_before"])
    not_after = parse_datetime(certificate["not_valid_after"])
    if not_before is None or not_after is None:
        raise ValueError("certificate summary must contain validity timestamps")

    seconds_remaining = (not_after - current_time).total_seconds()
    days_remaining = max(0, int(seconds_remaining // 86400))
    renew_at = renewal_datetime(policy["renew_at"])
    scheduled = False
    scheduled_due = False
    if renew_at is not None:
        scheduled = not_before < renew_at
        scheduled_due = scheduled and renew_at <= current_time
    renew_window = (
        policy["renew_before_days"] > 0
        and current_time >= not_after - _dt.timedelta(days=policy["renew_before_days"])
    )
    warning = (
        policy["warn_before_days"] > 0
        and current_time >= not_after - _dt.timedelta(days=policy["warn_before_days"])
    )
    state = "valid"
    if not_after <= current_time:
        state = "expired"
    elif scheduled_due:
        state = "scheduled_due"
    elif renew_window:
        state = "renewal_due"
    elif warning:
        state = "warning"
    elif scheduled:
        state = "scheduled"
    return {
        "state": state,
        "days_remaining": days_remaining,
        "warning": warning,
        "renewal_due": state in {"expired", "scheduled_due", "renewal_due"},
        "scheduled": bool(scheduled),
        "rekey_on_renewal": policy["rekey"],
        "policy": policy,
    }
