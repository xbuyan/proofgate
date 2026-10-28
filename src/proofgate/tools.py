"""Synthetic tool handlers and strict request/argument validation.

Schemas (exact keys, no extras):

- ``get_balance``: ``{"account": <non-empty str>}``
- ``transfer_money``: ``{"source": ..., "target": ..., "amount": ...}``
  with distinct non-empty string parties and a positive ``int`` amount
  (``bool`` excluded).

``get_balance`` is read-only and safe to expose. ``transfer_money``
requires the gate-held mutator capability and raises
:class:`OperationNotAuthorized` without it, so no supported public call
mutates the ledger except through the enforcement entry point. A
confirmation supplied for the read-only action is rejected as an
unexpected argument.

``transfer_money`` requests may carry an optional ``idempotency_key``:
a caller-chosen bearer string (1-128 chars of letters, digits,
hyphen, underscore) naming the intended operation. Same key plus same
action/canonical-arguments means same operation; the key alone decides
retry identity across lost responses and restarts.
"""

import re

from .canonical import arg_hash as _arg_hash
from .ledger import _Mutator

__all__ = [
    "SUPPORTED_TOOLS",
    "OperationNotAuthorized",
    "ValidationError",
    "get_balance",
    "transfer_money",
    "is_valid_idempotency_key",
    "validate_args",
    "validate_request",
    "REASON_UNKNOWN_TOOL",
    "REASON_INVALID_ARGS",
]

SUPPORTED_TOOLS = ("get_balance", "transfer_money")

REASON_UNKNOWN_TOOL = "unknown_tool"
REASON_INVALID_ARGS = "invalid_arguments"

_REQUEST_KEYS = frozenset({
    "action", "actor", "args", "confirmation", "idempotency_key",
})
_BALANCE_KEYS = frozenset({"account"})
_TRANSFER_KEYS = frozenset({"source", "target", "amount"})


class ValidationError(Exception):
    """Strict validation failure with best-effort record fields."""

    def __init__(self, reason, action="unknown", arg_hash="",
                 actor="unknown"):
        super().__init__(reason)
        self.reason = reason
        self.action = action
        self.arg_hash = arg_hash
        self.actor = actor


class OperationNotAuthorized(Exception):
    """A mutation was attempted without the gate-held capability."""


_IDEMPOTENCY_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def is_valid_idempotency_key(value):
    """Return True for a well-formed caller idempotency key."""
    return (
        isinstance(value, str)
        and _IDEMPOTENCY_KEY_RE.match(value) is not None
    )


def _best_effort_hash(args):
    try:
        return _arg_hash(args)
    except Exception:
        return ""


def _is_non_empty_str(value):
    return isinstance(value, str) and bool(value)


def _is_amount(value):
    return isinstance(value, int) and not isinstance(value, bool) \
        and value > 0


def validate_args(action, args):
    """Validate *args* for *action*; return normalized args dict.

    Raises :class:`ValidationError` with ``unknown_tool`` for an
    unsupported action or ``invalid_arguments`` for any schema violation.
    """
    if action not in SUPPORTED_TOOLS:
        raise ValidationError(
            REASON_UNKNOWN_TOOL,
            action=action if isinstance(action, str) else "unknown",
            arg_hash=_best_effort_hash(args),
        )
    if not isinstance(args, dict):
        raise ValidationError(
            REASON_INVALID_ARGS, action=action,
            arg_hash=_best_effort_hash(args),
        )
    if action == "get_balance":
        if set(args) != _BALANCE_KEYS or not _is_non_empty_str(
            args.get("account")
        ):
            raise ValidationError(
                REASON_INVALID_ARGS, action=action,
                arg_hash=_best_effort_hash(args),
            )
        return {"account": args["account"]}
    if set(args) != _TRANSFER_KEYS:
        raise ValidationError(
            REASON_INVALID_ARGS, action=action,
            arg_hash=_best_effort_hash(args),
        )
    source = args["source"]
    target = args["target"]
    amount = args["amount"]
    if (
        not _is_non_empty_str(source)
        or not _is_non_empty_str(target)
        or source == target
        or not _is_amount(amount)
    ):
        raise ValidationError(
            REASON_INVALID_ARGS, action=action,
            arg_hash=_best_effort_hash(args),
        )
    return {"source": source, "target": target, "amount": amount}


def validate_request(request):
    """Validate a gate request; return ``(action, actor, args, token,
    key)``.

    ``args`` is the normalized dict from :func:`validate_args``,
    ``token`` is the confirmation string or ``None``, and ``key`` is
    the idempotency key string or ``None``. Any violation raises
    :class:`ValidationError` carrying best-effort audit fields.
    """
    if not isinstance(request, dict):
        raise ValidationError(REASON_INVALID_ARGS)
    if set(request) - _REQUEST_KEYS:
        raise ValidationError(REASON_INVALID_ARGS)
    actor = request.get("actor", "agent")
    if not isinstance(actor, str):
        raise ValidationError(REASON_INVALID_ARGS)
    action = request.get("action")
    if not isinstance(action, str) or action not in SUPPORTED_TOOLS:
        raise ValidationError(
            REASON_UNKNOWN_TOOL,
            action=action if isinstance(action, str) else "unknown",
            arg_hash=_best_effort_hash(request.get("args")),
            actor=actor,
        )
    try:
        args = validate_args(action, request.get("args"))
    except ValidationError as exc:
        exc.actor = actor
        raise
    token = request.get("confirmation")
    if token is not None and (
        not isinstance(token, str) or not token
    ):
        raise ValidationError(
            REASON_INVALID_ARGS, action=action,
            arg_hash=_best_effort_hash(request.get("args")), actor=actor,
        )
    if action == "get_balance" and token is not None:
        raise ValidationError(
            REASON_INVALID_ARGS, action=action,
            arg_hash=_best_effort_hash(request.get("args")), actor=actor,
        )
    key = request.get("idempotency_key")
    if key is not None and not is_valid_idempotency_key(key):
        raise ValidationError(
            REASON_INVALID_ARGS, action=action,
            arg_hash=_best_effort_hash(request.get("args")), actor=actor,
        )
    if action == "get_balance" and key is not None:
        raise ValidationError(
            REASON_INVALID_ARGS, action=action,
            arg_hash=_best_effort_hash(request.get("args")), actor=actor,
        )
    return (action, actor, args, token, key)


def get_balance(ledger, account):
    """Return the balance of *account* (read-only)."""
    return ledger.balance(account)


def transfer_money(mutator, source, target, amount):
    """Apply a transfer; requires the gate-held mutator capability."""
    if not isinstance(mutator, _Mutator):
        raise OperationNotAuthorized(
            "transfer_money requires gate authorization"
        )
    return mutator.apply_transfer(source, target, amount)
