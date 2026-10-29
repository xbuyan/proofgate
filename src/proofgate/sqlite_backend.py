"""SQLite-backed storage for gate state (A2.2 foundation slice).

Isolated persistence only: versioned schema, WAL configuration, and an
explicit transaction manager. NOT YET WIRED into Gate operations: this
step adds no crash recovery, confirmation sweeping,
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
    REASON_STALE,
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
from .verify import VerificationError, verify_database

__all__ = ["SCHEMA_VERSION", "SQLiteBackend", "SQLiteBackendError"]

SCHEMA_VERSION = "3"

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
    "used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)), "
    "epoch INTEGER NOT NULL, "
    "op_key TEXT NULL)",
    "CREATE TABLE operations("
    "op_key TEXT PRIMARY KEY, "
    "action TEXT NOT NULL, "
    "arg_hash TEXT NOT NULL, "
    "actor TEXT NOT NULL, "
    "status TEXT NOT NULL "
    "CHECK (status IN ('pending', 'committed')), "
    "receipt_json TEXT NULL, "
    "created_epoch INTEGER NOT NULL, "
    "updated_epoch INTEGER NOT NULL)",
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

_REQUIRED_TABLES = frozenset({
    "meta", "policy_versions", "counters", "confirmations",
    "ledger", "journal", "audit", "incidents", "operations",
})

_V2_TABLES = frozenset({
    "meta", "policy_versions", "counters", "confirmations",
    "ledger", "journal", "audit", "incidents",
})

_V1_CONFIRMATION_COLUMNS = frozenset({
    "token", "action", "arg_hash", "policy_version",
    "issued_at", "expires_at", "used",
})

_V2_CONFIRMATION_COLUMNS = frozenset({
    "token", "action", "arg_hash", "policy_version",
    "issued_at", "expires_at", "used", "epoch",
})


class SQLiteBackendError(Exception):
    """Backend misuse or unusable database (see message)."""


class _CommitUncertainError(Exception):
    """A commit (or rollback) failed; the outcome cannot be established.

    Raised only by :class:`_Transaction.__exit__`. The gate translates
    it into an ``outcome_uncertain`` result; it must never surface as
    a denial, a success, or a claim that rollback succeeded. Imported
    by the enforcement module under its private name (same precedent
    as ``ledger._Mutator``).
    """


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


def _targets_json(targets):
    return canonicalize(list(targets)).decode("utf-8")


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
    """Confirmation facade: store matrix plus boot-epoch binding."""

    def __init__(self, backend):
        self._backend = backend

    @staticmethod
    def token_id(token):
        """Return the log-safe 8-character prefix of *token*."""
        return token[:8]

    def _fetch(self, token):
        return self._backend._conn.execute(
            "SELECT token, action, arg_hash, policy_version, issued_at, "
            "expires_at, used, epoch, op_key "
            "FROM confirmations WHERE token = ?",
            (token,),
        ).fetchone()

    def issue(self, action, arg_hash, policy_version, op_key=None):
        backend = self._backend
        backend._require_transaction()
        now = backend._now()
        token = secrets.token_urlsafe(32)
        while self._fetch(token) is not None:
            token = secrets.token_urlsafe(32)
        # S4: stamp the active boot epoch so a later restart
        # invalidates this token. Zero survives only on rows
        # backfilled by the v1 migration, which are stale by the
        # same rule after the migrating open advances past 0.
        # op_key optionally links the token to a caller operation;
        # linkage never weakens the binding or epoch checks.
        backend._conn.execute(
            "INSERT INTO confirmations(token, action, arg_hash, "
            "policy_version, issued_at, expires_at, used, epoch, "
            "op_key) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (token, action, arg_hash, policy_version, now,
             now + backend._ttl, backend._current_epoch(), op_key),
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
        # Temporal validity before binding comparisons: any epoch
        # other than the active one (older, newer, or NULL) is
        # stale. Fail-closed: inequality alone rejects.
        if row["epoch"] != self._backend._current_epoch():
            raise ConfirmationError(REASON_STALE)
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

    def count_version(self, policy_version):
        """Return how many stored tokens bind to *policy_version*.

        Read-only counterpart to :meth:`purge_version`: same match
        predicate, so the count equals what a subsequent purge in the
        same undisturbed transaction would remove.
        """
        row = self._backend._conn.execute(
            "SELECT COUNT(*) AS n FROM confirmations "
            "WHERE policy_version = ?",
            (policy_version,),
        ).fetchone()
        return row["n"]

    def clear(self):
        self._backend._require_transaction()
        cursor = self._backend._conn.execute("DELETE FROM confirmations")
        return cursor.rowcount

    def pending_count(self):
        row = self._backend._conn.execute(
            "SELECT COUNT(*) AS n FROM confirmations"
        ).fetchone()
        return row["n"]


def _close_target(target):
    """Close a backup destination connection.

    Narrow seam so tests can inject a deterministic close failure: a
    real close failure is otherwise uninducible without threads.
    Production behavior is exactly ``Connection.close()``.
    """
    target.close()


class SQLiteBackend(StorageBackend):
    """SQLite-backed storage (isolated slice; see module docstring)."""

    def __init__(self, conn, *, clock=None, ttl_seconds=None,
                 path=None):
        self._conn = conn
        self._path = path
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
                # Owner-only: the database holds confirmation bearer
                # tokens. The mode is masked by, never widened
                # beyond, the process umask.
                fd = os.open(
                    path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
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
                    "INSERT INTO meta(key, value) VALUES (?, ?)",
                    ("opening_balances",
                     canonicalize(seed_balances).decode("utf-8")),
                )
                backend._conn.execute(
                    "INSERT INTO policy_versions(version, "
                    "per_transfer_cap, daily_cap, allowed_targets, "
                    "retired) VALUES (?, ?, ?, ?, 0)",
                    (policy.version, policy.per_transfer_cap,
                     policy.daily_cap,
                     _targets_json(policy.allowed_targets)),
                )
                # Audit seqs derive from the chain (like the memory
                # log's len+1), so only the journal needs a counter.
                for name, value in (
                    ("daily_spent", 0),
                    ("journal_seq", 1),
                    ("boot_epoch", 0),
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
            version = cls._read_schema_version(backend, path)
            if version == "1":
                cls._migrate_v1_to_v2(backend, path)
                version = "2"
            if version == "2":
                cls._migrate_v2_to_v3(backend, path)
                version = "3"
            if version == SCHEMA_VERSION:
                cls._require_tables(backend, path)
            # Unknown versions fall through to the verifier, which
            # refuses them; only v1 and v2 take migration paths.
            verify_database(
                backend._conn, SCHEMA_VERSION, _REQUIRED_TABLES
            )
            # Verified: this open counts as one boot. Advancement is
            # last so any failure above leaves the epoch untouched.
            cls._advance_boot_epoch(backend)
        except BaseException:
            backend.close()
            raise
        return backend

    @classmethod
    def _read_schema_version(cls, backend, path):
        try:
            row = backend._conn.execute(
                "SELECT value FROM meta WHERE key = ?",
                ("schema_version",),
            ).fetchone()
        except sqlite3.Error as exc:
            raise SQLiteBackendError(
                "not a ProofGate database: %r" % (path,)
            ) from exc
        if row is None:
            raise SQLiteBackendError(
                "unsupported schema version in %r" % (path,)
            )
        return row["value"]

    @classmethod
    def _require_tables(cls, backend, path, expected=None):
        """Refuse a database missing any required table."""
        tables = {
            row[0]
            for row in backend._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        missing = sorted((expected or _REQUIRED_TABLES) - tables)
        if missing:
            raise VerificationError(
                "schema_tables",
                "incomplete ProofGate database %r: missing tables: %s"
                % (path, ", ".join(missing)),
            )

    @classmethod
    def _migrate_v1_to_v2(cls, backend, path):
        """Migrate a verified v1 database to version 2, atomically.

        Read-only pre-checks first; the column add, counter seed, and
        version flip then commit together. No audit records are
        touched and no semantic validity is claimed (S2 owns that).
        """
        cls._require_tables(backend, path, _V2_TABLES)
        columns = {
            row["name"]
            for row in backend._conn.execute(
                "PRAGMA table_info(confirmations)"
            )
        }
        if columns != _V1_CONFIRMATION_COLUMNS:
            raise VerificationError(
                "schema_tables",
                "refusing to migrate %r: confirmations table does not "
                "match the expected version-1 schema" % (path,),
            )
        row = backend._conn.execute(
            "SELECT value FROM counters WHERE name = ?",
            ("boot_epoch",),
        ).fetchone()
        if row is not None:
            raise VerificationError(
                "counters",
                "refusing to migrate %r: unexpected boot_epoch row "
                "in a version-1 database" % (path,),
            )
        with backend.transaction():
            backend._conn.execute(
                "ALTER TABLE confirmations ADD COLUMN epoch "
                "INTEGER NOT NULL DEFAULT 0"
            )
            backend._conn.execute(
                "INSERT INTO counters(name, value) VALUES "
                "('boot_epoch', 0)"
            )
            backend._conn.execute(
                "UPDATE meta SET value = ? WHERE key = ?",
                ("2", "schema_version"),
            )

    @classmethod
    def _migrate_v2_to_v3(cls, backend, path):
        """Migrate a verified v2 database to version 3, atomically.

        Read-only pre-checks first; the operations table, the token
        link column, and the version flip then commit together. No
        audit records are touched. Pre-existing tokens keep a NULL
        link and behave exactly as before (no idempotency).
        """
        cls._require_tables(backend, path, _V2_TABLES)
        columns = {
            row["name"]
            for row in backend._conn.execute(
                "PRAGMA table_info(confirmations)"
            )
        }
        if columns != _V2_CONFIRMATION_COLUMNS:
            raise VerificationError(
                "schema_tables",
                "refusing to migrate %r: confirmations table does not "
                "match the expected version-2 schema" % (path,),
            )
        tables = {
            row[0]
            for row in backend._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "operations" in tables:
            raise VerificationError(
                "schema_tables",
                "refusing to migrate %r: unexpected operations table "
                "in a version-2 database" % (path,),
            )
        with backend.transaction():
            backend._conn.execute(
                "CREATE TABLE operations("
                "op_key TEXT PRIMARY KEY, "
                "action TEXT NOT NULL, "
                "arg_hash TEXT NOT NULL, "
                "actor TEXT NOT NULL, "
                "status TEXT NOT NULL "
                "CHECK (status IN ('pending', 'committed')), "
                "receipt_json TEXT NULL, "
                "created_epoch INTEGER NOT NULL, "
                "updated_epoch INTEGER NOT NULL)"
            )
            backend._conn.execute(
                "ALTER TABLE confirmations ADD COLUMN op_key TEXT NULL"
            )
            backend._conn.execute(
                "UPDATE meta SET value = ? WHERE key = ?",
                (SCHEMA_VERSION, "schema_version"),
            )

    @classmethod
    def _advance_boot_epoch(cls, backend):
        """Advance boot_epoch by exactly one, with audit evidence.

        Runs inside one backend transaction: the counter update and
        the boot audit record commit together or not at all. Called
        only from :meth:`open` after verification succeeds; callers
        must never invoke it on an unverified database. Sweeping
        arrives separately; this step advances and records only.
        """
        with backend.transaction():
            prior_epoch = backend._current_epoch()
            new_epoch = prior_epoch + 1
            backend._conn.execute(
                "UPDATE counters SET value = ? "
                "WHERE name = 'boot_epoch'",
                (new_epoch,),
            )
            backend.audit.append(
                kind="boot", actor="operator", action="startup",
                arg_hash="",
                policy_version=backend.get_policy().version,
                decision="recorded", reason="ok",
                extra={
                    "prior_epoch": prior_epoch,
                    "new_epoch": new_epoch,
                },
            )

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
            return cls(conn, clock=clock, ttl_seconds=ttl_seconds,
                       path=path)
        except BaseException:
            conn.close()
            raise

    def close(self):
        """Close the connection. Idempotent."""
        self._conn.close()

    def backup(self, dest_path):
        """Copy this database to *dest_path* via the SQLite backup API.

        Uses ``Connection.backup()`` so the snapshot reflects committed
        state even while this backend stays open in WAL mode; copying
        the main ``.db`` file instead would silently drop uncheckpointed
        frames. The source is never mutated, closed, or advanced: no
        epoch change, no audit event. The destination is verified with
        the startup verifier before success is reported.

        Refuses existing destinations, ``':memory:'`` destinations,
        and source/destination aliasing. Refuses to run inside a
        backend transaction, where uncommitted writes would be silently
        excluded from the snapshot. On failure only the reserved
        destination file is removed: it is the one path this call
        provably owns. Sidecars are never deleted, since absence from
        an earlier check cannot prove ownership; the destination
        connection runs in rollback-journal mode, so close() already
        removes any journal it created. A close failure during cleanup
        is attached to the original error as a note, never masking it.
        A failure to close the verified destination is treated as
        backup failure instead: the close error propagates and the
        reserved file is removed. Any sidecars left behind by a failed
        close are never deleted — their ownership cannot be
        established — and are inert without the destination file.

        A backup is a consistent snapshot, not necessarily a current
        one: restoring an older valid backup rolls state back, and no
        rollback protection is claimed.
        """
        if self._in_transaction:
            raise SQLiteBackendError(
                "cannot back up inside a transaction"
            )
        if self._path is None:
            raise SQLiteBackendError(
                "cannot back up a backend with no source path"
            )
        if dest_path == ":memory:":
            raise ValueError("cannot back up to ':memory:'")
        if self._path != ":memory:" and os.path.realpath(
            dest_path
        ) == os.path.realpath(self._path):
            raise ValueError(
                "refusing to back up onto the source database: %r"
                % (dest_path,)
            )
        if os.path.exists(dest_path):
            # Fast path only (also covers existing directories); the
            # O_EXCL reservation below is the race-safe arbiter.
            raise FileExistsError(
                "refusing to back up over existing path: %r"
                % (dest_path,)
            )
        try:
            # Owner-only, like create(): the database holds
            # confirmation bearer tokens. The mode is masked by, never
            # widened beyond, the process umask.
            fd = os.open(
                dest_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
        except FileExistsError:
            raise FileExistsError(
                "refusing to back up over existing path: %r"
                % (dest_path,)
            )
        target = None
        try:
            # Releasing the reservation descriptor is part of the
            # guarded operation: a failure here follows the same
            # cleanup path as any later backup failure.
            os.close(fd)
            try:
                target = sqlite3.connect(dest_path)
                self._conn.backup(target)
            except sqlite3.Error as exc:
                raise SQLiteBackendError(
                    "backup to %r failed" % (dest_path,)
                ) from exc
            verify_database(target, SCHEMA_VERSION, _REQUIRED_TABLES)
            # Clear first: if the close below fails, the handler must
            # treat it as backup failure (remove the reservation, keep
            # the close error primary) without closing twice.
            closer = target
            target = None
            _close_target(closer)
        except BaseException as original:
            # Cleanup must neither mask the original failure nor skip
            # the removal below: a close error is noted on the
            # original exception, never raised in its place.
            if target is not None:
                try:
                    _close_target(target)
                except Exception as close_exc:
                    original.add_note(
                        "backup cleanup: closing the destination "
                        "connection also failed: %r" % (close_exc,)
                    )
            # Ownership-safe: the reserved file is provably ours via
            # O_EXCL above, and it is the only path unlinked here.
            # Sidecars are never deleted — absence from any earlier
            # check cannot prove another process did not create one
            # since. Our own transient journal, if the failed backup
            # created one, is already gone with the rolled-back close.
            try:
                os.remove(dest_path)
            except OSError as remove_exc:
                original.add_note(
                    "backup cleanup: removing the reserved "
                    "destination also failed: %r" % (remove_exc,)
                )
            raise

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

    def _current_epoch(self):
        """Return the active boot epoch; fail closed if missing."""
        row = self._conn.execute(
            "SELECT value FROM counters WHERE name = 'boot_epoch'"
        ).fetchone()
        if row is None:
            raise SQLiteBackendError("counter missing: 'boot_epoch'")
        return row["value"]

    def _operation_from_row(self, row):
        blob = row["receipt_json"]
        if blob is not None:
            try:
                receipt = json.loads(blob)
            except (TypeError, ValueError) as exc:
                raise SQLiteBackendError(
                    "operation receipt unparseable: %r"
                    % (row["op_key"],)
                ) from exc
        else:
            receipt = None
        return {
            "key": row["op_key"],
            "action": row["action"],
            "arg_hash": row["arg_hash"],
            "actor": row["actor"],
            "status": row["status"],
            "receipt": receipt,
            "created_epoch": row["created_epoch"],
            "updated_epoch": row["updated_epoch"],
        }

    def get_operation(self, op_key):
        """Return the operation record dict, or ``None`` if absent."""
        row = self._conn.execute(
            "SELECT op_key, action, arg_hash, actor, status, "
            "receipt_json, created_epoch, updated_epoch "
            "FROM operations WHERE op_key = ?",
            (op_key,),
        ).fetchone()
        if row is None:
            return None
        return self._operation_from_row(row)

    def register_operation(self, op_key, action, arg_hash, actor):
        """Store a ``pending`` record; duplicate keys fail closed."""
        self._require_transaction()
        epoch = self._current_epoch()
        try:
            self._conn.execute(
                "INSERT INTO operations(op_key, action, arg_hash, "
                "actor, status, receipt_json, created_epoch, "
                "updated_epoch) VALUES (?, ?, ?, ?, 'pending', "
                "NULL, ?, ?)",
                (op_key, action, arg_hash, actor, epoch, epoch),
            )
        except sqlite3.IntegrityError as exc:
            raise SQLiteBackendError(
                "operation already registered: %r" % (op_key,)
            ) from exc
        return self.get_operation(op_key)

    def complete_operation(self, op_key, receipt):
        """Flip ``pending`` to ``committed`` with the stored receipt."""
        self._require_transaction()
        blob = canonicalize(receipt).decode("utf-8")
        cursor = self._conn.execute(
            "UPDATE operations SET status = 'committed', "
            "receipt_json = ?, updated_epoch = ? "
            "WHERE op_key = ? AND status = 'pending'",
            (blob, self._current_epoch(), op_key),
        )
        if cursor.rowcount != 1:
            raise SQLiteBackendError(
                "operation not pending: %r" % (op_key,)
            )
        return self.get_operation(op_key)

    def get_token_operation_key(self, token):
        """Return the linked operation key, or ``None``."""
        row = self._conn.execute(
            "SELECT op_key FROM confirmations WHERE token = ?",
            (token,),
        ).fetchone()
        if row is None:
            return None
        return row["op_key"]

    def link_token_operation(self, token, op_key):
        """Attach *op_key* to an unlinked token."""
        self._require_transaction()
        cursor = self._conn.execute(
            "UPDATE confirmations SET op_key = ? "
            "WHERE token = ? AND op_key IS NULL",
            (op_key, token),
        )
        if cursor.rowcount != 1:
            raise SQLiteBackendError(
                "token cannot be linked to an operation"
            )

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

    def activate_policy(self, new_policy):
        """Retire the active version and activate *new_policy*."""
        self._require_transaction()
        self._conn.execute(
            "UPDATE policy_versions SET retired = 1 WHERE retired = 0"
        )
        self._conn.execute(
            "INSERT INTO policy_versions(version, per_transfer_cap, "
            "daily_cap, allowed_targets, retired) "
            "VALUES (?, ?, ?, ?, 0)",
            (new_policy.version, new_policy.per_transfer_cap,
             new_policy.daily_cap,
             _targets_json(new_policy.allowed_targets)),
        )

    def add_daily_spent(self, amount):
        """Add *amount* to the persisted spend counter."""
        self._require_transaction()
        self._conn.execute(
            "UPDATE counters SET value = value + ? "
            "WHERE name = 'daily_spent'",
            (amount,),
        )

    def reset_daily_spent(self):
        """Reset the persisted spend counter to zero."""
        self._require_transaction()
        self._conn.execute(
            "UPDATE counters SET value = 0 WHERE name = 'daily_spent'"
        )

    def get_opening_balances(self):
        """Return the construction balances for reconciliation."""
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?",
            ("opening_balances",),
        ).fetchone()
        if row is None:
            raise SQLiteBackendError("opening balances missing")
        return json.loads(row["value"])

    def mutator(self):
        """Return the gate-held mutation capability for our ledger."""
        return _Mutator(self.ledger)


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
        # Flag set only after BEGIN succeeds: a failed BEGIN must not
        # wedge the backend into a phantom transaction.
        backend._conn.execute("BEGIN IMMEDIATE")
        backend._in_transaction = True
        return backend

    def __exit__(self, exc_type, exc_value, traceback):
        backend = self._backend
        try:
            if exc_type is None:
                try:
                    backend._conn.commit()
                except Exception as exc:
                    # BaseExceptions (KeyboardInterrupt/SystemExit)
                    # propagate untouched per F2; the owner treats a
                    # mid-commit interrupt as suspect state.
                    try:
                        backend._conn.rollback()
                    except Exception as rollback_exc:
                        raise _CommitUncertainError(
                            "commit failed (%s) and rollback failed "
                            "(%s); outcome uncertain"
                            % (exc, rollback_exc)
                        ) from exc
                    raise _CommitUncertainError(
                        "commit failed (%s); outcome uncertain" % (exc,)
                    ) from exc
            else:
                try:
                    backend._conn.rollback()
                except Exception as exc:
                    raise _CommitUncertainError(
                        "rollback failed (%s); outcome uncertain"
                        % (exc,)
                    ) from exc
        finally:
            backend._in_transaction = False
        return False
