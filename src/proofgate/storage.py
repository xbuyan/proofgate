"""Storage backends for gate state (A2.1 seam).

:class:`StorageBackend` is the construction + transaction contract behind
which Step 2 will add SQLite. :class:`MemoryBackend` preserves the
prototype's exact in-memory behavior: no durability is claimed, access is
single-process, and atomicity comes solely from the gate lock.
"""

import abc
import contextlib
import copy

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

    Operation records bind a caller idempotency key to one intended
    transfer: ``get_operation(key)`` returns the record dict or
    ``None``; ``register_operation(key, action, arg_hash, actor)``
    stores a ``pending`` record (duplicate keys fail closed);
    ``complete_operation(key, receipt)`` flips ``pending`` to
    ``committed`` with the stored receipt (anything else fails
    closed); ``get_token_operation_key(token)`` returns the linked
    key or ``None``; ``link_token_operation(token, key)`` attaches a
    key to an unlinked token. Records are dicts with ``key``,
    ``action``, ``arg_hash``, ``actor``, ``status``, ``receipt``
    (``None`` until committed), ``created_epoch``, ``updated_epoch``.
    Records survive ``confirmations.clear()``: wiping tokens must
    never erase committed outcomes.
    """

    ledger = None
    journal = None
    audit = None
    confirmations = None

    @abc.abstractmethod
    def transaction(self):
        """Yield once per gate operation (see class contract)."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_operation(self, op_key):
        """Return the operation record dict, or ``None`` if absent."""
        raise NotImplementedError

    @abc.abstractmethod
    def register_operation(self, op_key, action, arg_hash, actor):
        """Store a ``pending`` record; fail closed on duplicate keys."""
        raise NotImplementedError

    @abc.abstractmethod
    def complete_operation(self, op_key, receipt):
        """Flip ``pending`` to ``committed`` with the stored receipt."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_token_operation_key(self, token):
        """Return the linked operation key, or ``None``."""
        raise NotImplementedError

    @abc.abstractmethod
    def link_token_operation(self, token, op_key):
        """Attach *op_key* to an unlinked token; fail closed."""
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
        self._operations = {}

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

    def get_operation(self, op_key):
        """Return a copy of the operation record, or ``None``."""
        record = self._operations.get(op_key)
        return copy.deepcopy(record) if record is not None else None

    def register_operation(self, op_key, action, arg_hash, actor):
        """Store a ``pending`` record; duplicate keys raise."""
        if op_key in self._operations:
            raise ValueError(
                "operation already registered: %r" % (op_key,)
            )
        record = {
            "key": op_key,
            "action": action,
            "arg_hash": arg_hash,
            "actor": actor,
            "status": "pending",
            "receipt": None,
            "created_epoch": 0,
            "updated_epoch": 0,
        }
        self._operations[op_key] = record
        return copy.deepcopy(record)

    def complete_operation(self, op_key, receipt):
        """Flip ``pending`` to ``committed`` with a copied receipt."""
        record = self._operations.get(op_key)
        if record is None or record["status"] != "pending":
            raise ValueError(
                "operation not pending: %r" % (op_key,)
            )
        record["status"] = "committed"
        record["receipt"] = copy.deepcopy(receipt)
        return copy.deepcopy(record)

    def get_token_operation_key(self, token):
        """Return the linked operation key, or ``None``."""
        entry = self.confirmations._entries.get(token)
        if entry is None:
            return None
        return entry.op_key

    def link_token_operation(self, token, op_key):
        """Attach *op_key* to an unlinked token."""
        entry = self.confirmations._entries.get(token)
        if entry is None or entry.op_key is not None:
            raise ValueError(
                "token cannot be linked to an operation"
            )
        entry.op_key = op_key
