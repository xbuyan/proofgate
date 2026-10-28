"""Storage backends for gate state (A2.1 seam).

:class:`StorageBackend` is the construction + transaction contract behind
which Step 2 will add SQLite. :class:`MemoryBackend` preserves the
prototype's exact in-memory behavior: no durability is claimed, access is
single-process, and atomicity comes solely from the gate lock.
"""

import abc
import contextlib

from .audit import AuditLog
from .confirmations import ConfirmationStore, DEFAULT_TTL_SECONDS
from .journal import Journal
from .ledger import SyntheticLedger
from .ledger import _Mutator

__all__ = ["MemoryBackend", "StorageBackend"]


class StorageBackend(abc.ABC):
    """Owns a gate's state objects and marks transaction boundaries.

    Implementations expose ``ledger``, ``journal``, ``audit``, and
    ``confirmations`` attributes holding stores with the same method
    contracts as the in-memory classes. Confirmation stores expose
    ``count_version(v)``: a read-only count of tokens bound to ``v``
    using the same predicate as ``purge_version``.

    ``transaction()`` wraps exactly one gate operation. It is entered
    inside the gate lock and never nested; transactional backends may
    rely on non-nested use.

    Policy, retired-version, daily-counter, and opening-balance state
    are backend-owned. ``get_policy()`` returns the active policy;
    ``retired_versions()`` returns retired versions as a frozenset;
    ``activate_policy(new)`` retires the current version and activates
    ``new``; ``get_daily_spent()`` / ``add_daily_spent(amount)`` /
    ``reset_daily_spent()`` manage the spend counter;
    ``get_opening_balances()`` returns the construction balances used
    for reconciliation; ``mutator()`` returns the gate-held ledger
    mutation capability for this backend's ledger. Write methods must
    be called inside ``transaction()``. Degraded state remains
    gate-held (in-memory) for this milestone.
    """

    ledger = None
    journal = None
    audit = None
    confirmations = None

    @abc.abstractmethod
    def transaction(self):
        """Yield once per gate operation (see class contract)."""
        raise NotImplementedError


class MemoryBackend(StorageBackend):
    """In-memory backend: current prototype behavior, unchanged."""

    def __init__(self, *, policy, balances, ttl_seconds=None, clock=None,
                 prior_export_hash=None):
        self.ledger = SyntheticLedger(balances)
        self.journal = Journal()
        self.audit = AuditLog(
            initial_policy_version=policy.version,
            prior_export_hash=prior_export_hash,
            clock=clock,
        )
        self.confirmations = ConfirmationStore(
            ttl_seconds=DEFAULT_TTL_SECONDS
            if ttl_seconds is None else ttl_seconds,
            clock=clock,
        )
        self._policy = policy
        self._retired_versions = set()
        self._daily_spent = 0
        self._opening = self.ledger.snapshot()

    @contextlib.contextmanager
    def transaction(self):
        """Reentrant-safe no-op: the gate lock provides atomicity."""
        yield

    def mutator(self):
        """Return the gate-held mutation capability for our ledger."""
        return _Mutator(self.ledger)

    def get_policy(self):
        """Return the active policy."""
        return self._policy

    def retired_versions(self):
        """Return retired policy versions as a frozenset."""
        return frozenset(self._retired_versions)

    def activate_policy(self, new_policy):
        """Retire the active version and activate *new_policy*."""
        self._retired_versions.add(self._policy.version)
        self._policy = new_policy

    def get_daily_spent(self):
        """Return the accumulated spend counter."""
        return self._daily_spent

    def add_daily_spent(self, amount):
        """Add *amount* to the spend counter."""
        self._daily_spent += amount

    def reset_daily_spent(self):
        """Reset the spend counter to zero."""
        self._daily_spent = 0

    def get_opening_balances(self):
        """Return the construction balances for reconciliation."""
        return dict(self._opening)
