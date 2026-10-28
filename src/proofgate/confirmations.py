"""Server-issued, single-use confirmation tokens.

Each token is bound to one :class:`Binding` of ``(action, arg_hash,
policy_version)``. Redemption checks, in order: existence, single-use,
expiry, policy-version match, then action/argument match. Comparisons use
constant-time digest comparison.

Only an 8-character ``token_id`` prefix is ever logged; the full token is
returned to the caller alone. TTL comparisons use a monotonic envelope
over an injectable clock source (default ``time.monotonic``): only the
highest timestamp ever observed counts, so a backward clock jump can
never re-arm an expired confirmation. Redemption at or past the
envelope time ``expires_at`` is expired.
"""

import hmac
import math
import secrets
import threading
import time
from dataclasses import dataclass

__all__ = [
    "Binding",
    "ConfirmationError",
    "ConfirmationStore",
    "DEFAULT_TTL_SECONDS",
    "REASON_INVALID",
    "REASON_REUSED",
    "REASON_EXPIRED",
    "REASON_MISMATCH",
    "REASON_SUPERSEDED",
]

DEFAULT_TTL_SECONDS = 300

REASON_INVALID = "invalid_confirmation"
REASON_REUSED = "confirmation_reused"
REASON_EXPIRED = "confirmation_expired"
REASON_MISMATCH = "confirmation_mismatch"
REASON_SUPERSEDED = "policy_superseded"


class ConfirmationError(Exception):
    """Redemption failure; ``reason`` is the machine-readable code."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Binding:
    """Exact (action, canonical-argument hash, policy version) binding."""

    action: str
    arg_hash: str
    policy_version: str


@dataclass
class _Entry:
    binding: Binding
    issued_at: float
    expires_at: float
    used: bool = False


def _eq(a, b):
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except (AttributeError, TypeError):
        return False


class ConfirmationStore:
    """Issues and redeems single-use confirmation tokens."""

    def __init__(self, ttl_seconds=DEFAULT_TTL_SECONDS, clock=None):
        if isinstance(ttl_seconds, bool) or not isinstance(
            ttl_seconds, (int, float)
        ) or ttl_seconds <= 0 or not math.isfinite(ttl_seconds):
            raise ValueError("ttl_seconds must be a positive number")
        self._ttl = ttl_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._entries = {}
        self._latest = float("-inf")

    @staticmethod
    def token_id(token):
        """Return the log-safe 8-character prefix of *token*."""
        return token[:8]

    def _now_locked(self):
        """Monotonic envelope over the injected clock (lock held)."""
        now = self._clock()
        if now > self._latest:
            self._latest = now
        return self._latest

    def issue(self, action, arg_hash, policy_version):
        """Issue a token bound to the given action, arg hash, and version."""
        with self._lock:
            now = self._now_locked()
            token = secrets.token_urlsafe(32)
            while token in self._entries:
                token = secrets.token_urlsafe(32)
            self._entries[token] = _Entry(
                binding=Binding(action, arg_hash, policy_version),
                issued_at=now,
                expires_at=now + self._ttl,
            )
        return token

    def redeem(self, token, action, arg_hash, policy_version):
        """Redeem *token* or raise ConfirmationError with the reason code."""
        with self._lock:
            now = self._now_locked()
            entry = self._entries.get(token)
            if entry is None:
                raise ConfirmationError(REASON_INVALID)
            if entry.used:
                raise ConfirmationError(REASON_REUSED)
            if now >= entry.expires_at:
                raise ConfirmationError(REASON_EXPIRED)
            if not _eq(entry.binding.policy_version, policy_version):
                raise ConfirmationError(REASON_SUPERSEDED)
            if not (
                _eq(entry.binding.action, action)
                and _eq(entry.binding.arg_hash, arg_hash)
            ):
                raise ConfirmationError(REASON_MISMATCH)
            entry.used = True
            return entry.binding

    def check(self, token, action, arg_hash, policy_version):
        """Validate *token* without consuming it; return the binding.

        Same checks and reason codes as :meth:`redeem`, but the token
        stays usable. The gate calls this before policy revalidation so
        pre-execution rejections never consume a confirmation.
        """
        with self._lock:
            now = self._now_locked()
            entry = self._entries.get(token)
            if entry is None:
                raise ConfirmationError(REASON_INVALID)
            if entry.used:
                raise ConfirmationError(REASON_REUSED)
            if now >= entry.expires_at:
                raise ConfirmationError(REASON_EXPIRED)
            if not _eq(entry.binding.policy_version, policy_version):
                raise ConfirmationError(REASON_SUPERSEDED)
            if not (
                _eq(entry.binding.action, action)
                and _eq(entry.binding.arg_hash, arg_hash)
            ):
                raise ConfirmationError(REASON_MISMATCH)
            return entry.binding

    def consume(self, token):
        """Mark *token* used; call only after a successful :meth:`check`.

        Raises only when the entry is missing or already used, which is
        unreachable when the gate serializes check-then-consume under its
        lock; the gate treats any such failure defensively.
        """
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                raise ConfirmationError(REASON_INVALID)
            if entry.used:
                raise ConfirmationError(REASON_REUSED)
            entry.used = True
            return entry.binding

    def purge_version(self, policy_version):
        """Drop all tokens bound to *policy_version*; return the count."""
        with self._lock:
            doomed = [
                token
                for token, entry in self._entries.items()
                if entry.binding.policy_version == policy_version
            ]
            for token in doomed:
                del self._entries[token]
            return len(doomed)

    def count_version(self, policy_version):
        """Return how many stored tokens bind to *policy_version*.

        Read-only: same predicate as :meth:`purge_version`, so the
        count always equals what a subsequent purge would remove while
        the store is undisturbed.
        """
        with self._lock:
            return sum(
                1
                for entry in self._entries.values()
                if entry.binding.policy_version == policy_version
            )

    def clear(self):
        """Drop all tokens; return the count removed."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            return count

    def pending_count(self):
        """Return the number of stored (used or unused) tokens."""
        with self._lock:
            return len(self._entries)
