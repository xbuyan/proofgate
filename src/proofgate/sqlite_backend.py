"""SQLite-backed storage for gate state (A2.2 foundation slice).

Isolated persistence only: versioned schema, WAL configuration, and an
explicit transaction manager. NOT YET WIRED into Gate operations: this
step adds no crash recovery, boot epochs, confirmation sweeping,
startup verification, operation IDs, or audit anchoring.

Explicitly unsupported: multi-process serving, network filesystems, and
direct multi-threaded use without external serialization (``sqlite3``
fails loudly on cross-thread connection use). The memory backend
remains the default; behavior there is unchanged.
"""

import copy
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import time

from .audit import (
    AuditCorruptionError,
    GENESIS_PREV_HASH,
    _verify_chain,
)
from .canonical import CanonicalizationError, canonicalize
from .confirmations import (
    REASON_INVALID,
    REASON_REUSED,
    REASON_EXPIRED,
    REASON_MISMATCH,
    REASON_SUPERSEDED,
    Binding,
    ConfirmationError,
    DEFAULT_TTL_SECONDS,
    _eq,
)
from .journal import JournalEntry
from .ledger import LedgerError, SyntheticLedger
from .ledger import _Mutator as _LedgerMutator
from .policy import Policy, validate_policy_fields
from .storage import StorageBackend

__all__ = ["SCHEMA_VERSION", "SQLiteBackend", "SQLiteBackendError"]

SCHEMA_VERSION = "1"

# One statement per entry (no splitting); DDL runs inside the seed
# transaction so creation is atomic.
_SCHEMA = (
    "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE policy_versions("
    "version TEXT PRIMARY KEY, "
    "per_transfer_cap INTEGER NOT NULL, "
    "daily_cap INTEGER NOT NULL, "
    "allowed_targets TEXT NOT NULL, "
    "retired INTEGER NOT NULL DEFAULT 0 CHECK (retired IN (0, 1)))",
    "CREATE UNIQUE INDEX active_policy_unique "
    "ON policy_versions(retired) WHERE retired = 0",
    "CREATE TABLE counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL)",
    "CREATE TABLE confirmations("
    "token TEXT PRIMARY KEY, "
    "action TEXT NOT NULL, "
    "arg_hash TEXT NOT NULL, "
    "policy_version TEXT NOT NULL, "
    "issued_at REAL NOT NULL, "
    "expires_at REAL NOT NULL, "
    "used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)))",
    "CREATE TABLE ledger("
    "account TEXT PRIMARY KEY, "
    "balance INTEGER NOT NULL CHECK (balance >= 0))",
    "CREATE TABLE journal("
    "seq INTEGER PRIMARY KEY, "
    "action TEXT NOT NULL, "
    "source TEXT NOT NULL, "
    "target TEXT NOT NULL, "
    "amount INTEGER NOT NULL)",
    "CREATE TABLE audit("
    "seq INTEGER PRIMARY KEY, "
    "kind TEXT NOT NULL, "
    "ts REAL NOT NULL, "
    "actor TEXT NOT NULL, "
    "action TEXT NOT NULL, "
    "arg_hash TEXT NOT NULL, "
    "policy_version TEXT NOT NULL, "
    "decision TEXT NOT NULL, "
    "reason TEXT NOT NULL, "
    "token_id TEXT NULL, "
    "extra_json TEXT NOT NULL, "
    "prev_hash TEXT NOT NULL, "
    "record_hash TEXT NOT NULL)",
    "CREATE TABLE incidents("
    "id INTEGER PRIMARY KEY, "
    "case_name TEXT NOT NULL, "
    "detail TEXT NOT NULL, "
    "created_at REAL NOT NULL, "
    "cleared_at REAL NULL)",
)


class SQLiteBackendError(Exception):
    """Backend misuse or unusable database (see message)."""


def _record_from_row(row):
    return {
        "kind": row["kind"],
        "seq": row["seq"],
        "ts": row["ts"],
        "actor": row["actor"],
        "action": row["action"],
        "arg_hash": row["arg_hash"],
        "policy_version": row["policy_version"],
        "decision": row["decision"],
        "reason": row["reason"],
        "token_id": row["token_id"],
        "extra": json.loads(row["extra_json"]),
        "prev_hash": row["prev_hash"],
        "record_hash": row["record_hash"],
    }


def _record_hash(body):
    return hashlib.sha256(canonicalize(body)).hexdigest()


def _checked_ttl(ttl_seconds):
    """Resolve ``None`` to the default; reject anything non-conforming.

    Same rule and error as :class:`ConfirmationStore`; keep in sync.
    """
    if ttl_seconds is None:
        return DEFAULT_TTL_SECONDS
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, (int, float))
        or ttl_seconds <= 0
        or not math.isfinite(ttl_seconds)
    ):
        raise ValueError("ttl_seconds must be a positive number")
    return ttl_seconds


class _SQLiteLedger:
    """Ledger facade: same contract as SyntheticLedger (plus tx guard)."""

    def __init__(self, backend):
        self._backend = backend
        self.fault_hook = None

    def balance(self, account):
        row = self._backend._conn.execute(
            "SELECT balance FROM ledger WHERE account = ?", (account,)
        ).fetchone()
        return row["balance"] if row is not None else 0

    def snapshot(self):
        return {
            row["account"]: row["balance"]
            for row in self._backend._conn.execute(
                "SELECT account, balance FROM ledger"
            )
        }


class _Mutator(_LedgerMutator):
    """Gate-held mutation capability for the SQLite ledger facade.

    Subclasses :class:`ledger._Mutator` so the ``isinstance`` gate in
    :func:`tools.transfer_money` accepts it without any tools change;
    Step 3 wiring only has to construct this instead of the memory one.
    """

    def apply_transfer(self, source, target, amount):
        backend = self._ledger._backend
        backend._require_transaction()
        if self._ledger.fault_hook is not None:
            self._ledger.fault_hook()
        conn = backend._conn
        source_balance = self._ledger.balance(source)
        if source_balance < amount:
            raise LedgerError("insufficient_funds")
        target_balance = self._ledger.balance(target)
        conn.execute(
            "INSERT OR REPLACE INTO ledger(account, balance) "
            "VALUES (?, ?)",
            (source, source_balance - amount),
        )
        conn.execute(
            "INSERT OR REPLACE INTO ledger(account, balance) "
            "VALUES (?, ?)",
            (target, target_balance + amount),
        )
        return (source_balance - amount, target_balance + amount)


class _SQLiteJournal:
    """Journal facade: same contract as Journal (plus tx guard)."""

    def __init__(self, backend):
        self._backend = backend

    def append_transfer(self, source, target, amount):
        backend = self._backend
        backend._require_transaction()
        seq = backend._next_seq("journal_seq")
        backend._conn.execute(
            "INSERT INTO journal(seq, action, source, target, amount) "
            "VALUES (?, 'transfer_money', ?, ?, ?)",
            (seq, source, target, amount),
        )
        return JournalEntry(
            seq=seq, action="transfer_money", source=source,
            target=target, amount=amount,
        )

    def entries(self):
        return tuple(
            JournalEntry(
                seq=row["seq"], action=row["action"],
                source=row["source"], target=row["target"],
                amount=row["amount"],
            )
            for row in self._backend._conn.execute(
                "SELECT seq, action, source, target, amount "
                "FROM journal ORDER BY seq"
            )
        )

    def __len__(self):
        row = self._backend._conn.execute(
            "SELECT COUNT(*) AS n FROM journal"
        ).fetchone()
        return row["n"]


class _SQLiteAuditLog:
    """Audit facade: same record format/contract as AuditLog."""

    def __init__(self, backend):
        self._backend = backend
        self.fault_hook = None

    @property
    def records(self):
        return tuple(
            _record_from_row(row)
            for row in self._backend._conn.execute(
                "SELECT kind, seq, ts, actor, action, arg_hash, "
                "policy_version, decision, reason, token_id, "
                "extra_json, prev_hash, record_hash "
                "FROM audit ORDER BY seq"
            )
        )

    def __len__(self):
        row = self._backend._conn.execute(
            "SELECT COUNT(*) AS n FROM audit"
        ).fetchone()
        return row["n"]

    def append(self, *, kind, actor, action, arg_hash, policy_version,
               decision, reason, token_id=None, extra=None):
        if self.fault_hook is not None:
            self.fault_hook(kind)
        backend = self._backend
        backend._require_transaction()
        last_row = backend._conn.execute(
            "SELECT kind, seq, ts, actor, action, arg_hash, "
            "policy_version, decision, reason, token_id, extra_json, "
            "prev_hash, record_hash FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if last_row is not None:
            last = _record_from_row(last_row)
            body = {k: v for k, v in last.items() if k != "record_hash"}
            try:
                expected = _record_hash(body)
            except CanonicalizationError as exc:
                raise AuditCorruptionError(
                    "audit_corrupt", {"problem": "unencodable_last"}
                ) from exc
            stored = last.get("record_hash", "")
            if not isinstance(stored, str) or not hmac.compare_digest(
                expected, stored
            ):
                raise AuditCorruptionError(
                    "audit_corrupt", {"problem": "last_link"}
                )
            prev_hash = last["record_hash"]
            seq = last["seq"] + 1
        else:
            prev_hash = GENESIS_PREV_HASH
            seq = 1
        body = {
            "kind": kind,
            "seq": seq,
            "ts": backend._wall_now(),
            "actor": actor,
            "action": action,
            "arg_hash": arg_hash,
            "policy_version": policy_version,
            "decision": decision,
            "reason": reason,
            "token_id": token_id,
            "extra": copy.deepcopy(extra) if extra else {},
            "prev_hash": prev_hash,
        }
        record_hash = _record_hash(body)
        record = dict(body)
        record["record_hash"] = record_hash
        if _record_hash(body) != record_hash:
            raise AuditCorruptionError(
                "audit_corrupt", {"problem": "self_check"}
            )
        backend._conn.execute(
            "INSERT INTO audit(kind, seq, ts, actor, action, arg_hash, "
            "policy_version, decision, reason, token_id, extra_json, "
            "prev_hash, record_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (kind, seq, body["ts"], actor, action, arg_hash,
             policy_version, decision, reason, token_id,
             canonicalize(body["extra"]).decode("utf-8"), prev_hash,
             record_hash),
        )
        return copy.deepcopy(record)

    def verify(self):
        """Return ``(ok, detail)`` for the full chain check."""
        return _verify_chain(list(self.records))

    def export_jsonl(self, path):
        """Write a read-only canonical snapshot; return report dict."""
        records = self.records
        blob = b"".join(
            canonicalize(record) + b"\n" for record in records
        )
        with open(path, "wb") as handle:
            handle.write(blob)
        return {
            "path": path,
            "records": len(records),
            "sha256": hashlib.sha256(blob).hexdigest(),
        }


class _SQLiteConfirmations:
    """Confirmation facade: same check matrix as ConfirmationStore."""

    def __init__(self, backend):
        self._backend = backend

    @staticmethod
    def token_id(token):
        """Return the log-safe 8-character prefix of *token*."""
        return token[:8]

    def _fetch(self, token):
        return self._backend._conn.execute(
            "SELECT token, action, arg_hash, policy_version, issued_at, "
            "expires_at, used FROM confirmations WHERE token = ?",
            (token,),
        ).fetchone()

    def issue(self, action, arg_hash, policy_version):
        backend = self._backend
        backend._require_transaction()
        now = backend._now()
        token = secrets.token_urlsafe(32)
        while self._fetch(token) is not None:
            token = secrets.token_urlsafe(32)
        backend._conn.execute(
            "INSERT INTO confirmations(token, action, arg_hash, "
            "policy_version, issued_at, expires_at, used) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (token, action, arg_hash, policy_version, now,
             now + backend._ttl),
        )
        return token

    def _checked_binding(self, token, action, arg_hash, policy_version):
        row = self._fetch(token)
        if row is None:
            raise ConfirmationError(REASON_INVALID)
        if row["used"]:
            raise ConfirmationError(REASON_REUSED)
        if self._backend._now() >= row["expires_at"]:
            raise ConfirmationError(REASON_EXPIRED)
        if not _eq(row["policy_version"], policy_version):
            raise ConfirmationError(REASON_SUPERSEDED)
        if not (
            _eq(row["action"], action)
            and _eq(row["arg_hash"], arg_hash)
        ):
            raise ConfirmationError(REASON_MISMATCH)
        return Binding(
            row["action"], row["arg_hash"], row["policy_version"]
        )

    def redeem(self, token, action, arg_hash, policy_version):
        backend = self._backend
        backend._require_transaction()
        binding = self._checked_binding(
            token, action, arg_hash, policy_version
        )
        backend._conn.execute(
            "UPDATE confirmations SET used = 1 WHERE token = ?",
            (token,),
        )
        return binding

    def check(self, token, action, arg_hash, policy_version):
        return self._checked_binding(
            token, action, arg_hash, policy_version
        )

    def consume(self, token):
        backend = self._backend
        backend._require_transaction()
        row = self._fetch(token)
        if row is None:
            raise ConfirmationError(REASON_INVALID)
        if row["used"]:
            raise ConfirmationError(REASON_REUSED)
        backend._conn.execute(
            "UPDATE confirmations SET used = 1 WHERE token = ?",
            (token,),
        )
        return Binding(
            row["action"], row["arg_hash"], row["policy_version"]
        )

    def purge_version(self, policy_version):
        self._backend._require_transaction()
        cursor = self._backend._conn.execute(
            "DELETE FROM confirmations WHERE policy_version = ?",
            (policy_version,),
        )
        return cursor.rowcount

    def clear(self):
        self._backend._require_transaction()
        cursor = self._backend._conn.execute("DELETE FROM confirmations")
        return cursor.rowcount

    def pending_count(self):
        row = self._backend._conn.execute(
            "SELECT COUNT(*) AS n FROM confirmations"
        ).fetchone()
        return row["n"]


class SQLiteBackend(StorageBackend):
    """SQLite-backed storage (isolated slice; see module docstring)."""

    def __init__(self, conn, *, clock=None, ttl_seconds=None):
        self._conn = conn
        self._clock = clock
        self._ttl = _checked_ttl(ttl_seconds)
        self._latest = float("-inf")
        self._in_transaction = False
        self.ledger = _SQLiteLedger(self)
        self.journal = _SQLiteJournal(self)
        self.audit = _SQLiteAuditLog(self)
        self.confirmations = _SQLiteConfirmations(self)

    # -- construction ------------------------------------------------

    @classmethod
    def create(cls, path, *, policy, balances, ttl_seconds=None,
               clock=None, prior_export_hash=None):
        """Create and seed a new database file. Refuses existing paths."""
        if path != ":memory:" and os.path.exists(path):
            # Fast path only (also covers existing directories); the
            # O_EXCL reservation below is the race-safe arbiter.
            raise FileExistsError(
                "refusing to create over existing path: %r" % (path,)
            )
        validate_policy_fields(
            version=policy.version,
            per_transfer_cap=policy.per_transfer_cap,
            daily_cap=policy.daily_cap,
            allowed_targets=policy.allowed_targets,
        )
        seed_balances = SyntheticLedger(balances).snapshot()
        if prior_export_hash is not None and not isinstance(
            prior_export_hash, str
        ):
            raise TypeError("prior_export_hash must be None or a string")
        # Validate before touching the filesystem: a bad TTL must not
        # leave an empty file behind.
        _checked_ttl(ttl_seconds)
        owned = False
        if path != ":memory:":
            # Atomic reservation: exactly one creator wins. A loser (or
            # a pre-existing path) sees FileExistsError without the
            # winner's file being opened, modified, or deleted.
            try:
                fd = os.open(
                    path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644
                )
            except FileExistsError:
                raise FileExistsError(
                    "refusing to create over existing path: %r" % (path,)
                )
            os.close(fd)
            owned = True
        backend = None
        try:
            backend = cls._connect(
                path, clock=clock, ttl_seconds=ttl_seconds
            )
            with backend.transaction():
                for statement in _SCHEMA:
                    backend._conn.execute(statement)
                backend._conn.execute(
                    "INSERT INTO meta(key, value) VALUES (?, ?)",
                    ("schema_version", SCHEMA_VERSION),
                )
                backend._conn.execute(
                    "INSERT INTO policy_versions(version, "
                    "per_transfer_cap, daily_cap, allowed_targets, "
                    "retired) VALUES (?, ?, ?, ?, 0)",
                    (policy.version, policy.per_transfer_cap,
                     policy.daily_cap,
                     canonicalize(
                         list(policy.allowed_targets)).decode("utf-8")),
                )
                # Audit seqs derive from the chain (like the memory
                # log's len+1), so only the journal needs a counter.
                for name, value in (
                    ("daily_spent", 0),
                    ("journal_seq", 1),
                ):
                    backend._conn.execute(
                        "INSERT INTO counters(name, value) VALUES (?, ?)",
                        (name, value),
                    )
                for account, balance in seed_balances.items():
                    backend._conn.execute(
                        "INSERT INTO ledger(account, balance) "
                        "VALUES (?, ?)",
                        (account, balance),
                    )
                extra = {}
                if prior_export_hash is not None:
                    extra["prior_export_hash"] = prior_export_hash
                backend.audit.append(
                    kind="genesis", actor="operator", action="genesis",
                    arg_hash="", policy_version=policy.version,
                    decision="recorded", reason="genesis", extra=extra,
                )
        except BaseException:
            if backend is not None:
                backend.close()
            if owned:
                # Remove only what this invocation created: the reserved
                # file plus any WAL sidecars our own connection made.
                # Another database's files are never touched: losers of
                # the reservation race never reach this branch.
                for victim in (path, path + "-wal", path + "-shm"):
                    try:
                        os.remove(victim)
                    except OSError:
                        pass
            raise
        return backend

    @classmethod
    def open(cls, path, *, clock=None, ttl_seconds=None):
        """Open an existing database. Refuses missing-path and foreign DBs."""
        if path != ":memory:" and not os.path.exists(path):
            raise FileNotFoundError(
                "no such ProofGate database: %r" % (path,)
            )
        backend = cls._connect(
            path, clock=clock, ttl_seconds=ttl_seconds
        )
        try:
            try:
                row = backend._conn.execute(
                    "SELECT value FROM meta WHERE key = ?",
                    ("schema_version",),
                ).fetchone()
            except sqlite3.Error as exc:
                raise SQLiteBackendError(
                    "not a ProofGate database: %r" % (path,)
                ) from exc
            if row is None or row["value"] != SCHEMA_VERSION:
                raise SQLiteBackendError(
                    "unsupported schema version in %r" % (path,)
                )
        except BaseException:
            backend.close()
            raise
        return backend

    @classmethod
    def _connect(cls, path, *, clock, ttl_seconds):
        conn = sqlite3.connect(path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            if path != ":memory:":
                mode = conn.execute(
                    "PRAGMA journal_mode=WAL"
                ).fetchone()[0]
                if str(mode).lower() != "wal":
                    conn.close()
                    raise SQLiteBackendError(
                        "WAL mode unavailable for %r" % (path,)
                    )
            conn.execute("PRAGMA synchronous=FULL")
            level = conn.execute("PRAGMA synchronous").fetchone()[0]
            if level != 2:
                conn.close()
                raise SQLiteBackendError(
                    "FULL synchronous mode unavailable for %r" % (path,)
                )
        except sqlite3.Error as exc:
            # Foreign or corrupt file: SQLite fails while reading the
            # header, before any write. Close without touching the file
            # and report the backend's rejection, not a raw driver error.
            conn.close()
            raise SQLiteBackendError(
                "not a ProofGate database: %r" % (path,)
            ) from exc
        try:
            return cls(conn, clock=clock, ttl_seconds=ttl_seconds)
        except BaseException:
            conn.close()
            raise

    def close(self):
        """Close the connection. Idempotent."""
        self._conn.close()

    # -- transaction management --------------------------------------

    def transaction(self):
        """Exactly-one atomic unit per gate op; nesting rejected."""
        return _Transaction(self)

    def _require_transaction(self):
        if not self._in_transaction:
            raise SQLiteBackendError(
                "writes require backend.transaction()"
            )

    # -- clocks ------------------------------------------------------

    def _wall_now(self):
        return (self._clock or time.time)()

    def _now(self):
        now = (self._clock or time.monotonic)()
        if now > self._latest:
            self._latest = now
        return self._latest

    # -- small data access -------------------------------------------

    def _next_seq(self, name):
        self._require_transaction()
        row = self._conn.execute(
            "SELECT value FROM counters WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise SQLiteBackendError("counter missing: %r" % (name,))
        self._conn.execute(
            "UPDATE counters SET value = value + 1 WHERE name = ?",
            (name,),
        )
        return row["value"]

    def get_policy(self):
        """Return the active Policy."""
        row = self._conn.execute(
            "SELECT version, per_transfer_cap, daily_cap, "
            "allowed_targets FROM policy_versions WHERE retired = 0"
        ).fetchone()
        if row is None:
            raise SQLiteBackendError("no active policy")
        return Policy.create(
            version=row["version"],
            per_transfer_cap=row["per_transfer_cap"],
            daily_cap=row["daily_cap"],
            allowed_targets=tuple(json.loads(row["allowed_targets"])),
        )

    def retired_versions(self):
        """Return retired policy versions as a frozenset."""
        return frozenset(
            row["version"] for row in self._conn.execute(
                "SELECT version FROM policy_versions WHERE retired = 1"
            )
        )

    def get_daily_spent(self):
        """Return the persisted daily-spent counter."""
        row = self._conn.execute(
            "SELECT value FROM counters WHERE name = ?",
            ("daily_spent",),
        ).fetchone()
        if row is None:
            raise SQLiteBackendError("counter missing: 'daily_spent'")
        return row["value"]


class _Transaction:
    """Explicit BEGIN IMMEDIATE / COMMIT / ROLLBACK unit."""

    def __init__(self, backend):
        self._backend = backend

    def __enter__(self):
        backend = self._backend
        if backend._in_transaction:
            raise SQLiteBackendError(
                "nested transactions are not supported"
            )
        backend._in_transaction = True
        backend._conn.execute("BEGIN IMMEDIATE")
        return backend

    def __exit__(self, exc_type, exc_value, traceback):
        backend = self._backend
        try:
            if exc_type is None:
                try:
                    backend._conn.commit()
                except BaseException:
                    backend._conn.rollback()
                    raise
            else:
                backend._conn.rollback()
        finally:
            backend._in_transaction = False
        return False
