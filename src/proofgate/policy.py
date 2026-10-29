"""Versioned, immutable, in-memory policy model and deterministic evaluator.

The evaluator is pure: no I/O, no clock, no model input. It maps
``(policy, action, args, state)`` to a ``(permitted, reason)`` verdict.

State view (supplied by the gate from live data)::

    {"balances": {"alice": 1000, ...}, "daily_spent": 0}

``daily_spent`` accumulates over the gate instance lifetime; calendar-day
rollover is explicitly out of scope for this prototype.
"""

from dataclasses import dataclass

from .canonical import SQLITE_INTEGER_MAX

__all__ = [
    "Policy",
    "PolicyError",
    "evaluate",
    "validate_policy_fields",
    "REASON_OK",
    "REASON_UNKNOWN_TOOL",
    "REASON_INVALID_AMOUNT",
    "REASON_TARGET_NOT_ALLOWED",
    "REASON_LIMIT_EXCEEDED",
    "REASON_DAILY_LIMIT",
    "REASON_INSUFFICIENT_FUNDS",
]

REASON_OK = "ok"
REASON_UNKNOWN_TOOL = "unknown_tool"
REASON_INVALID_AMOUNT = "invalid_amount"
REASON_TARGET_NOT_ALLOWED = "target_not_allowed"
REASON_LIMIT_EXCEEDED = "policy_limit_exceeded"
REASON_DAILY_LIMIT = "daily_limit_exceeded"
REASON_INSUFFICIENT_FUNDS = "insufficient_funds"

ACTION_BALANCE = "get_balance"
ACTION_TRANSFER = "transfer_money"


class PolicyError(ValueError):
    """Raised when policy field values are invalid."""


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate_policy_fields(*, version, per_transfer_cap, daily_cap,
                           allowed_targets):
    """Validate raw policy fields; raise PolicyError on any violation."""
    if not isinstance(version, str) or not version:
        raise PolicyError("version must be a non-empty string")
    for name, cap in (("per_transfer_cap", per_transfer_cap),
                      ("daily_cap", daily_cap)):
        if (
            not _is_int(cap)
            or cap < 0
            or cap > SQLITE_INTEGER_MAX
        ):
            raise PolicyError(
                "%s must be a non-negative int storable in "
                "SQLite (at most 2**63 - 1)" % name
            )
    if isinstance(allowed_targets, (str, bytes)):
        raise PolicyError(
            "allowed_targets must be a collection of strings, "
            "not a bare string or bytes"
        )
    try:
        targets = list(allowed_targets)
    except TypeError:
        raise PolicyError("allowed_targets must be an iterable of strings")
    for target in targets:
        if not isinstance(target, str) or not target:
            raise PolicyError("allowed_targets must hold non-empty strings")
    return None


@dataclass(frozen=True)
class Policy:
    """Immutable policy. Construct via :meth:`create` (validated).

    Caps are in integer minor units. ``allowed_targets`` is stored as a
    sorted tuple for determinism; an empty tuple denies all transfers.
    """

    version: str
    per_transfer_cap: int
    daily_cap: int
    allowed_targets: tuple = ()

    @classmethod
    def create(cls, *, version, per_transfer_cap, daily_cap,
               allowed_targets=()):
        validate_policy_fields(
            version=version,
            per_transfer_cap=per_transfer_cap,
            daily_cap=daily_cap,
            allowed_targets=allowed_targets,
        )
        return cls(
            version=version,
            per_transfer_cap=per_transfer_cap,
            daily_cap=daily_cap,
            allowed_targets=tuple(sorted(set(allowed_targets))),
        )


def evaluate(policy, action, args, state):
    """Return ``(permitted, reason)`` for *action* under *policy*.

    Pure function of its inputs. Boundary rule: a transfer whose amount
    exactly equals a cap, or that brings ``daily_spent`` exactly to the
    daily cap, is permitted (only exceeding denies).
    """
    if action == ACTION_BALANCE:
        return (True, REASON_OK)
    if action != ACTION_TRANSFER:
        return (False, REASON_UNKNOWN_TOOL)

    amount = args.get("amount") if isinstance(args, dict) else None
    if not _is_int(amount) or amount <= 0:
        return (False, REASON_INVALID_AMOUNT)
    target = args.get("target")
    if target not in policy.allowed_targets:
        return (False, REASON_TARGET_NOT_ALLOWED)
    if amount > policy.per_transfer_cap:
        return (False, REASON_LIMIT_EXCEEDED)
    daily_spent = state.get("daily_spent", 0)
    if daily_spent + amount > policy.daily_cap:
        return (False, REASON_DAILY_LIMIT)
    balances = state.get("balances", {})
    source = args.get("source")
    if balances.get(source, 0) < amount:
        return (False, REASON_INSUFFICIENT_FUNDS)
    return (True, REASON_OK)
