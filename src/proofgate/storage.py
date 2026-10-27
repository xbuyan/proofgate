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

__all__ = ["MemoryBackend", "StorageBackend"]


class StorageBackend(abc.ABC):
    """Owns a gate's state objects and marks transaction boundaries.

    Implementations expose ``ledger``, ``journal``, ``audit``, and
    ``confirmations`` attributes holding stores with the same method
    contracts as the in-memory classes.

    ``transaction()`` wraps exactly one gate operation. It is entered
    inside the gate lock and never nested; transactional backends may
    rely on non-nested use. Policy, retired versions, counters, and
    degraded state remain gate-held in this step and migrate into the
    backend with the Step 2 SQLite implementation.
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

    @contextlib.contextmanager
    def transaction(self):
        """Reentrant-safe no-op: the gate lock provides atomicity."""
        yield
