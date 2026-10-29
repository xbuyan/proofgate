"""Tests for the isolated SQLite backend slice (A2.2).

Schema, connection config, transaction mechanics, and contract parity
with the memory backend. Gate wiring, crash recovery, and durability
claims are out of scope: nothing here touches ``Gate``.
"""
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.audit import AuditError, verify_export
from proofgate.canonical import canonicalize
from proofgate.confirmations import (
    REASON_EXPIRED,
    REASON_INVALID,
    REASON_MISMATCH,
    REASON_REUSED,
    REASON_SUPERSEDED,
    REASON_STALE,
    Binding,
    ConfirmationError,
)
from proofgate.ledger import LedgerError
from proofgate.ledger import _Mutator as LedgerMutator
from proofgate.policy import Policy, PolicyError
from proofgate.sqlite_backend import (
    SCHEMA_VERSION,
    SQLiteBackend,
    SQLiteBackendError,
)
from proofgate.sqlite_backend import _Mutator as SQLiteMutator
from proofgate.storage import MemoryBackend, StorageBackend
from proofgate.tools import transfer_money
from proofgate.verify import VerificationError


class FakeClock:
    """Controllable clock; ``set`` models an unreliable time source.

    Unlike the F1 faithful-monotonic fake, this fake may retreat: the
    envelope test below proves the backend still refuses to re-arm an
    expired confirmation even then.
    """

    def __init__(self, value=1000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds

    def set(self, value):
        self.value = float(value)


def make_policy(**overrides):
    params = {
        "version": "v1",
        "per_transfer_cap": 500,
        "daily_cap": 1000,
        "allowed_targets": ("bob", "carol"),
    }
    params.update(overrides)
    return Policy.create(**params)


class SQLiteCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._backends = []
        self.addCleanup(self.tmp.cleanup)

    def tearDown(self):
        for backend in self._backends:
            try:
                backend.close()
            except Exception:
                pass

    def path(self, name="g.db"):
        return os.path.join(self.tmp.name, name)

    def create(self, name="g.db", **overrides):
        params = {
            "policy": make_policy(),
            "balances": {"alice": 10000},
        }
        params.update(overrides)
        backend = SQLiteBackend.create(self.path(name), **params)
        self._backends.append(backend)
        return backend

    def reopen(self, backend, name="g.db", **overrides):
        backend.close()
        reopened = SQLiteBackend.open(self.path(name), **overrides)
        self._backends.append(reopened)
        return reopened


class SchemaTests(SQLiteCase):
    def test_create_builds_all_tables(self):
        backend = self.create(clock=FakeClock())
        self.assertIsInstance(backend, StorageBackend)
        raw = sqlite3.connect(self.path())
        try:
            tables = {
                row[0]
                for row in raw.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table'"
                )
            }
        finally:
            raw.close()
        self.assertEqual(
            tables,
            {
                "meta", "policy_versions", "counters", "confirmations",
                "ledger", "journal", "audit", "incidents", "operations",
            },
        )
        self.assertEqual(SCHEMA_VERSION, "3")
        self.assertEqual(backend.get_policy(), make_policy())
        self.assertEqual(backend.retired_versions(), frozenset())
        self.assertEqual(backend.get_daily_spent(), 0)
        self.assertEqual(backend.ledger.snapshot(), {"alice": 10000})
        self.assertEqual(len(backend.journal), 0)
        (genesis,) = backend.audit.records
        self.assertEqual(genesis["kind"], "genesis")
        self.assertEqual(genesis["seq"], 1)
        self.assertEqual(genesis["policy_version"], "v1")
        self.assertEqual(genesis["extra"], {})
        self.assertNotIn("prior_verified", genesis)

    def test_wal_and_synchronous_configured(self):
        backend = self.create()
        raw = sqlite3.connect(self.path())
        try:
            mode = raw.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(str(mode).lower(), "wal")
        # synchronous is per-connection: assert on our own handle.
        level = backend._conn.execute("PRAGMA synchronous").fetchone()[0]
        self.assertEqual(level, 2)

    def test_genesis_prior_export_hash_recorded_verbatim(self):
        ref = "ab12" * 16
        backend = self.create(prior_export_hash=ref)
        (genesis,) = backend.audit.records
        self.assertEqual(genesis["extra"], {"prior_export_hash": ref})
        self.assertNotIn("prior_verified", genesis)

    def test_create_refuses_existing_path(self):
        path = self.path()
        with open(path, "wb") as handle:
            handle.write(b"junk")
        with self.assertRaises(FileExistsError):
            SQLiteBackend.create(
                path, policy=make_policy(),
                balances={"alice": 10000},
            )
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), b"junk")
        self.assertEqual(os.listdir(self.tmp.name), ["g.db"])

    @unittest.skipUnless(
        hasattr(os, "umask"), "POSIX umask required"
    )
    def test_create_restricts_new_file_permissions(self):
        previous = os.umask(0o000)
        try:
            backend = SQLiteBackend.create(
                self.path(), policy=make_policy(),
                balances={"alice": 10000},
            )
            self._backends.append(backend)
            mode = os.stat(self.path()).st_mode & 0o777
        finally:
            os.umask(previous)
        # Owner-only even under a fully permissive umask: group
        # and other receive no permissions on the new database.
        self.assertEqual(mode, 0o600)

    @unittest.skipUnless(
        hasattr(os, "umask"), "POSIX umask required"
    )
    def test_create_existing_path_keeps_permissions(self):
        path = self.path()
        with open(path, "wb") as handle:
            handle.write(b"junk")
        os.chmod(path, 0o644)
        original_mode = os.stat(path).st_mode & 0o777
        with self.assertRaises(FileExistsError):
            SQLiteBackend.create(
                path, policy=make_policy(),
                balances={"alice": 10000},
            )
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), b"junk")
        self.assertEqual(os.stat(path).st_mode & 0o777, original_mode)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)

    @unittest.skipUnless(
        hasattr(os, "umask"), "POSIX umask required"
    )
    def test_sidecars_grant_no_group_or_other_access(self):
        previous = os.umask(0o000)
        try:
            backend = self.create()
            try:
                # A real write transaction reliably materializes
                # both sidecars: WAL takes the frames, SHM takes
                # the wal-index.
                with backend.transaction():
                    SQLiteMutator(backend.ledger).apply_transfer(
                        "alice", "bob", 10
                    )
                wal = self.path() + "-wal"
                shm = self.path() + "-shm"
                self.assertTrue(os.path.exists(wal))
                self.assertTrue(os.path.exists(shm))
                for victim in (self.path(), wal, shm):
                    mode = stat.S_IMODE(os.stat(victim).st_mode)
                    self.assertEqual(mode & 0o077, 0)
            finally:
                backend.close()
        finally:
            os.umask(previous)
        # Clean close checkpoints and unlinks the sidecars.
        self.assertFalse(os.path.exists(self.path() + "-wal"))
        self.assertFalse(os.path.exists(self.path() + "-shm"))

    def test_create_validates_before_touching_filesystem(self):
        bad_policy = SimpleNamespace(
            version="", per_transfer_cap=1, daily_cap=1,
            allowed_targets=(),
        )
        cases = [
            ({"policy": bad_policy}, PolicyError),
            ({"balances": {"alice": -1}}, LedgerError),
            ({"balances": {"alice": 1.5}}, LedgerError),
            ({"balances": {"alice": 2**63}}, LedgerError),
            ({"ttl_seconds": float("inf")}, ValueError),
            ({"ttl_seconds": float("nan")}, ValueError),
            ({"prior_export_hash": 123}, TypeError),
        ]
        for index, (overrides, error) in enumerate(cases):
            name = "bad%d.db" % index
            with self.assertRaises(error):
                SQLiteBackend.create(self.path(name), **{
                    "policy": make_policy(),
                    "balances": {"alice": 10000},
                    **overrides,
                })
            self.assertFalse(os.path.exists(self.path(name)))

    def test_create_refuses_existing_directory(self):
        path = self.path()
        os.mkdir(path)
        with self.assertRaises(FileExistsError):
            SQLiteBackend.create(
                path, policy=make_policy(),
                balances={"alice": 10000},
            )
        self.assertTrue(os.path.isdir(path))
        self.assertEqual(os.listdir(path), [])

    def test_create_race_loser_preserves_existing_file(self):
        from unittest import mock

        # Deterministic race simulation: the fast-path check reports
        # "absent" (as if a winner created the file in the gap), so the
        # O_EXCL reservation is the sole arbiter. No timing involved.
        path = self.path()
        garbage = b"winner bytes" * 4
        with open(path, "wb") as handle:
            handle.write(garbage)
        with mock.patch("os.path.exists", return_value=False):
            with self.assertRaises(FileExistsError):
                SQLiteBackend.create(
                    path, policy=make_policy(),
                    balances={"alice": 10000},
                )
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), garbage)
        self.assertEqual(os.listdir(self.tmp.name), ["g.db"])

    def test_create_race_loser_preserves_winner_database(self):
        from unittest import mock

        db_path = self.path("winner.db")
        winner = SQLiteBackend.create(
            db_path, policy=make_policy(), balances={"alice": 1}
        )
        self._backends.append(winner)
        winner.close()
        with mock.patch("os.path.exists", return_value=False):
            with self.assertRaises(FileExistsError):
                SQLiteBackend.create(
                    db_path, policy=make_policy(),
                    balances={"alice": 10000},
                )
        # The winner database opens and reads back intact.
        check = SQLiteBackend.open(db_path)
        self._backends.append(check)
        self.assertEqual(check.get_policy(), make_policy())
        self.assertEqual(check.ledger.snapshot(), {"alice": 1})

    def test_create_failure_cleans_up_only_own_files(self):
        def exploding_clock():
            raise ZeroDivisionError("boom")

        path = self.path()
        with self.assertRaises(ZeroDivisionError):
            SQLiteBackend.create(
                path, policy=make_policy(),
                balances={"alice": 10000}, clock=exploding_clock,
            )
        # Main file plus any WAL sidecars from our own connection are
        # gone; the directory is exactly as it was.
        self.assertEqual(os.listdir(self.tmp.name), [])
        # A retry at the same path succeeds on the clean slate.
        backend = SQLiteBackend.create(
            path, policy=make_policy(), balances={"alice": 10000}
        )
        self._backends.append(backend)
        self.assertEqual(backend.ledger.snapshot(), {"alice": 10000})

    def test_create_memory_backend_works(self):
        backend = SQLiteBackend.create(
            ":memory:", policy=make_policy(),
            balances={"alice": 10000},
        )
        self._backends.append(backend)
        with backend.transaction():
            backend.journal.append_transfer("alice", "bob", 10)
        self.assertEqual(len(backend.journal), 1)
        self.assertEqual(backend.get_policy(), make_policy())


class OpenTests(SQLiteCase):
    def test_open_missing_path(self):
        with self.assertRaises(FileNotFoundError):
            SQLiteBackend.open(self.path("nope.db"))

    def test_open_foreign_empty_file(self):
        path = self.path()
        open(path, "wb").close()
        with self.assertRaises(SQLiteBackendError):
            SQLiteBackend.open(path)

    def test_open_foreign_garbage(self):
        path = self.path()
        garbage = b"this is not a database file at all" * 4
        with open(path, "wb") as handle:
            handle.write(garbage)
        with self.assertRaises(SQLiteBackendError):
            SQLiteBackend.open(path)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), garbage)

    def test_open_wrong_schema_version(self):
        backend = self.create()
        backend.close()
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "UPDATE meta SET value = ? WHERE key = ?",
                ("999", "schema_version"),
            )
            raw.commit()
        finally:
            raw.close()
        with self.assertRaises(VerificationError):
            SQLiteBackend.open(self.path())

    def test_open_memory_is_fresh(self):
        with self.assertRaises(SQLiteBackendError):
            SQLiteBackend.open(":memory:")

    def test_reopen_persists_everything(self):
        clock = FakeClock(1000.0)
        backend = self.create(clock=clock)
        with backend.transaction():
            first = backend.journal.append_transfer("alice", "bob", 100)
            second = backend.journal.append_transfer("alice", "carol", 50)
            record = backend.audit.append(
                kind="decision", actor="agent", action="transfer_money",
                arg_hash="h", policy_version="v1",
                decision="confirmation_required", reason="ok",
            )
            token = backend.confirmations.issue(
                "transfer_money", "h", "v1"
            )
            SQLiteMutator(backend.ledger).apply_transfer(
                "alice", "bob", 100
            )
            SQLiteMutator(backend.ledger).apply_transfer(
                "alice", "carol", 50
            )
            # Gate-consistent evidence: every journal entry needs its
            # successful OUTCOME record for startup verification.
            for seq in (1, 2):
                backend.audit.append(
                    kind="outcome", actor="agent",
                    action="transfer_money", arg_hash="h",
                    policy_version="v1", decision="allowed",
                    reason="ok", token_id="deadbeef",
                    extra={"journal_seq": seq},
                )
        self.assertEqual((first.seq, second.seq), (1, 2))
        backend = self.reopen(backend, clock=FakeClock(1000.0))
        entries = backend.journal.entries()
        self.assertEqual(
            [(e.seq, e.action, e.source, e.target, e.amount)
             for e in entries],
            [(1, "transfer_money", "alice", "bob", 100),
             (2, "transfer_money", "alice", "carol", 50)],
        )
        records = backend.audit.records
        # The reopen is one boot: S3 appends boot evidence without
        # rewriting the pre-existing chain.
        self.assertEqual(len(records), 5)
        self.assertEqual(records[1], record)
        boot = records[4]
        self.assertEqual(boot["kind"], "boot")
        self.assertEqual(boot["action"], "startup")
        self.assertEqual(
            (boot["extra"]["prior_epoch"],
             boot["extra"]["new_epoch"]),
            (0, 1),
        )
        # S4: the pre-restart token persists but is stale; a
        # fresh token issued in the new epoch validates normally.
        with self.assertRaises(ConfirmationError) as caught:
            backend.confirmations.check(
                token, "transfer_money", "h", "v1"
            )
        self.assertEqual(caught.exception.reason, REASON_STALE)
        with backend.transaction():
            fresh = backend.confirmations.issue(
                "transfer_money", "h2", "v1"
            )
        binding = backend.confirmations.check(
            fresh, "transfer_money", "h2", "v1"
        )
        self.assertEqual(
            binding, Binding("transfer_money", "h2", "v1")
        )
        self.assertEqual(
            backend.ledger.snapshot(),
            {"alice": 9850, "bob": 100, "carol": 50},
        )
        self.assertEqual(backend.get_policy(), make_policy())
        ok, _ = backend.audit.verify()
        self.assertTrue(ok)


class SchemaVersionTests(SQLiteCase):
    def make_v1_database(self, name="g.db"):
        """Build a true v1 database by downgrading a fresh create."""
        backend = self.create(name=name)
        with backend.transaction():
            SQLiteMutator(backend.ledger).apply_transfer(
                "alice", "bob", 100
            )
            backend.journal.append_transfer("alice", "bob", 100)
            backend.audit.append(
                kind="outcome", actor="agent", action="transfer_money",
                arg_hash="h", policy_version="v1",
                decision="allowed", reason="ok", token_id="deadbeef",
                extra={"journal_seq": 1},
            )
            token = backend.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        backend.close()
        raw = sqlite3.connect(self.path(name))
        try:
            raw.execute(
                "ALTER TABLE confirmations DROP COLUMN op_key"
            )
            raw.execute(
                "ALTER TABLE confirmations DROP COLUMN epoch"
            )
            raw.execute("DROP TABLE operations")
            raw.execute(
                "DELETE FROM counters WHERE name = 'boot_epoch'"
            )
            raw.execute(
                "UPDATE meta SET value = '1' "
                "WHERE key = 'schema_version'"
            )
            raw.commit()
            columns = {
                row[1]
                for row in raw.execute(
                    "PRAGMA table_info(confirmations)"
                )
            }
        finally:
            raw.close()
        # Pin the fixture to the historical v1 contract.
        self.assertEqual(
            columns,
            {"token", "action", "arg_hash", "policy_version",
             "issued_at", "expires_at", "used"},
        )
        return token

    def test_create_seeds_version_3_and_boot_epoch(self):
        backend = self.create()
        raw = sqlite3.connect(self.path())
        try:
            version = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            epoch = raw.execute(
                "SELECT value FROM counters WHERE name = 'boot_epoch'"
            ).fetchone()[0]
            columns = {
                row[1]
                for row in raw.execute(
                    "PRAGMA table_info(confirmations)"
                )
            }
            tables = {
                row[0]
                for row in raw.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table'"
                )
            }
        finally:
            raw.close()
        self.assertEqual(version, "3")
        self.assertEqual(version, SCHEMA_VERSION)
        self.assertEqual(epoch, 0)
        self.assertIn("epoch", columns)
        self.assertIn("op_key", columns)
        self.assertIn("operations", tables)
        with backend.transaction():
            token = backend.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        raw = sqlite3.connect(self.path())
        try:
            row = raw.execute(
                "SELECT epoch, used FROM confirmations WHERE token = ?",
                (token,),
            ).fetchone()
        finally:
            raw.close()
        self.assertEqual(tuple(row), (0, 0))

    def test_migrate_v1_to_v3(self):
        token = self.make_v1_database()
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        raw = sqlite3.connect(self.path())
        try:
            version = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            epoch = raw.execute(
                "SELECT value FROM counters WHERE name = 'boot_epoch'"
            ).fetchone()[0]
            token_row = raw.execute(
                "SELECT epoch, op_key FROM confirmations "
                "WHERE token = ?",
                (token,),
            ).fetchone()
            balance = raw.execute(
                "SELECT balance FROM ledger WHERE account = 'alice'"
            ).fetchone()[0]
            journal_rows = raw.execute(
                "SELECT COUNT(*) FROM journal"
            ).fetchone()[0]
            audit_rows = raw.execute(
                "SELECT COUNT(*) FROM audit"
            ).fetchone()[0]
            op_rows = raw.execute(
                "SELECT COUNT(*) FROM operations"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(version, "3")
        # The opening migration is followed by one boot (S3): the
        # epoch advances 0 -> 1 with its audit evidence.
        self.assertEqual(epoch, 1)
        self.assertEqual(tuple(token_row), (0, None))
        self.assertEqual(balance, 9900)
        self.assertEqual(journal_rows, 1)
        self.assertEqual(audit_rows, 3)
        self.assertEqual(op_rows, 0)
        self.assertEqual(backend.get_policy(), make_policy())
        # Migrated store is fully functional.
        with backend.transaction():
            fresh = backend.confirmations.issue(
                "transfer_money", "h2", "v1"
            )
        binding = backend.confirmations.check(
            fresh, "transfer_money", "h2", "v1"
        )
        self.assertEqual(binding.policy_version, "v1")
        # S4: the migrated v1 token (epoch 0) is stale after
        # the migrating open advanced to epoch 1.
        with self.assertRaises(ConfirmationError) as caught:
            backend.confirmations.check(
                token, "transfer_money", "h", "v1"
            )
        self.assertEqual(caught.exception.reason, REASON_STALE)

    def test_migrate_v1_rollback(self):
        self.make_v1_database()
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "CREATE TRIGGER t_abort_meta BEFORE UPDATE ON meta "
                "BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
            raw.commit()
        finally:
            raw.close()
        # RAISE(ABORT, ...) reports SQLITE_CONSTRAINT, which Python
        # maps to IntegrityError (not OperationalError).
        with self.assertRaises(sqlite3.IntegrityError):
            SQLiteBackend.open(self.path())
        raw = sqlite3.connect(self.path())
        try:
            version = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            columns = {
                row[1]
                for row in raw.execute(
                    "PRAGMA table_info(confirmations)"
                )
            }
            boot = raw.execute(
                "SELECT value FROM counters WHERE name = 'boot_epoch'"
            ).fetchone()
        finally:
            raw.close()
        self.assertEqual(version, "1")
        self.assertNotIn("epoch", columns)
        self.assertIsNone(boot)
        # Retry after removing the fault migrates cleanly.
        raw = sqlite3.connect(self.path())
        try:
            raw.execute("DROP TRIGGER t_abort_meta")
            raw.commit()
        finally:
            raw.close()
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        self.assertEqual(backend.get_policy(), make_policy())
        raw = sqlite3.connect(self.path())
        try:
            version = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(version, "3")

    def test_open_unknown_version_refused(self):
        backend = self.create()
        backend.close()
        for bad in ("", "4", "v2", "02"):
            raw = sqlite3.connect(self.path())
            try:
                raw.execute(
                    "UPDATE meta SET value = ? "
                    "WHERE key = 'schema_version'",
                    (bad,),
                )
                raw.commit()
            finally:
                raw.close()
            with open(self.path(), "rb") as handle:
                before = handle.read()
            with self.assertRaises(VerificationError, msg=bad):
                SQLiteBackend.open(self.path())
            with open(self.path(), "rb") as handle:
                self.assertEqual(handle.read(), before)
            raw = sqlite3.connect(self.path())
            try:
                kept = raw.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()[0]
            finally:
                raw.close()
            self.assertEqual(kept, bad)

    def test_open_missing_tables_refused(self):
        for version in ("2", "1"):
            name = "thin-%s.db" % version
            raw = sqlite3.connect(self.path(name))
            try:
                raw.execute(
                    "CREATE TABLE meta(key TEXT PRIMARY KEY, "
                    "value TEXT NOT NULL)"
                )
                raw.execute(
                    "INSERT INTO meta(key, value) VALUES "
                    "('schema_version', ?)",
                    (version,),
                )
                # Commit first: journal_mode cannot change inside the
                # implicit transaction opened by the INSERT above, and
                # the pragma would otherwise fail silently.
                raw.commit()
                mode = raw.execute(
                    "PRAGMA journal_mode=WAL"
                ).fetchone()[0]
                self.assertEqual(str(mode).lower(), "wal")
                raw.commit()
            finally:
                raw.close()
            with open(self.path(name), "rb") as handle:
                before = handle.read()
            with self.assertRaises(VerificationError):
                SQLiteBackend.open(self.path(name))
            with open(self.path(name), "rb") as handle:
                self.assertEqual(handle.read(), before)
            raw = sqlite3.connect(self.path(name))
            try:
                tables = {
                    row[0]
                    for row in raw.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table'"
                    )
                }
                kept = raw.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()[0]
            finally:
                raw.close()
            self.assertEqual(tables, {"meta"})
            self.assertEqual(kept, version)
        with self.assertRaises(VerificationError) as caught:
            SQLiteBackend.open(self.path("thin-2.db"))
        self.assertIn("missing tables", str(caught.exception))
        self.assertIn("audit", str(caught.exception))
        self.assertEqual(caught.exception.category, "schema_tables")

    def test_open_nonmigratable_v1_refused(self):
        backend = self.create(name="frank-a.db")
        backend.close()
        raw = sqlite3.connect(self.path("frank-a.db"))
        try:
            raw.execute(
                "UPDATE meta SET value = '1' "
                "WHERE key = 'schema_version'"
            )
            raw.commit()
        finally:
            raw.close()
        with self.assertRaises(VerificationError):
            SQLiteBackend.open(self.path("frank-a.db"))
        self.make_v1_database(name="frank-b.db")
        raw = sqlite3.connect(self.path("frank-b.db"))
        try:
            raw.execute(
                "INSERT INTO counters(name, value) VALUES "
                "('boot_epoch', 999)"
            )
            raw.commit()
        finally:
            raw.close()
        with self.assertRaises(VerificationError):
            SQLiteBackend.open(self.path("frank-b.db"))
        raw = sqlite3.connect(self.path("frank-b.db"))
        try:
            kept = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            boot = raw.execute(
                "SELECT value FROM counters WHERE name = 'boot_epoch'"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(kept, "1")
        self.assertEqual(boot, 999)

    def make_v2_database(self, name="g.db"):
        """Build a true v2 database by downgrading a fresh create."""
        backend = self.create(name=name)
        with backend.transaction():
            token = backend.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        backend.close()
        raw = sqlite3.connect(self.path(name))
        try:
            raw.execute(
                "ALTER TABLE confirmations DROP COLUMN op_key"
            )
            raw.execute("DROP TABLE operations")
            raw.execute(
                "UPDATE meta SET value = '2' "
                "WHERE key = 'schema_version'"
            )
            raw.commit()
            columns = {
                row[1]
                for row in raw.execute(
                    "PRAGMA table_info(confirmations)"
                )
            }
            tables = {
                row[0]
                for row in raw.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table'"
                )
            }
        finally:
            raw.close()
        # Pin the fixture to the historical v2 contract.
        self.assertEqual(
            columns,
            {"token", "action", "arg_hash", "policy_version",
             "issued_at", "expires_at", "used", "epoch"},
        )
        self.assertNotIn("operations", tables)
        return token

    def test_migrate_v2_to_v3(self):
        token = self.make_v2_database()
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        raw = sqlite3.connect(self.path())
        try:
            version = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            link = raw.execute(
                "SELECT op_key FROM confirmations WHERE token = ?",
                (token,),
            ).fetchone()[0]
            op_rows = raw.execute(
                "SELECT COUNT(*) FROM operations"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(version, "3")
        self.assertIsNone(link)
        self.assertEqual(op_rows, 0)
        self.assertEqual(backend.get_policy(), make_policy())
        # Migrated store supports the operation lifecycle.
        with backend.transaction():
            backend.register_operation(
                "op-m", "transfer_money", "h", "agent"
            )
            fresh = backend.confirmations.issue(
                "transfer_money", "h", "v1", op_key="op-m"
            )
        self.assertEqual(
            backend.get_token_operation_key(fresh), "op-m"
        )
        record = backend.get_operation("op-m")
        self.assertEqual(record["status"], "pending")

    def test_migrate_v2_rollback(self):
        self.make_v2_database()
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "CREATE TRIGGER t_abort_meta BEFORE UPDATE ON meta "
                "BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
            raw.commit()
        finally:
            raw.close()
        with self.assertRaises(sqlite3.IntegrityError):
            SQLiteBackend.open(self.path())
        raw = sqlite3.connect(self.path())
        try:
            version = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            columns = {
                row[1]
                for row in raw.execute(
                    "PRAGMA table_info(confirmations)"
                )
            }
            tables = {
                row[0]
                for row in raw.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table'"
                )
            }
        finally:
            raw.close()
        self.assertEqual(version, "2")
        self.assertNotIn("op_key", columns)
        self.assertNotIn("operations", tables)
        # Retry after removing the fault migrates cleanly.
        raw = sqlite3.connect(self.path())
        try:
            raw.execute("DROP TRIGGER t_abort_meta")
            raw.commit()
        finally:
            raw.close()
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        self.assertEqual(backend.get_policy(), make_policy())
        raw = sqlite3.connect(self.path())
        try:
            version = raw.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(version, "3")

    def test_open_nonmigratable_v2_refused(self):
        self.make_v2_database(name="grace-a.db")
        raw = sqlite3.connect(self.path("grace-a.db"))
        try:
            raw.execute(
                "CREATE TABLE operations(op_key TEXT PRIMARY KEY)"
            )
            raw.commit()
        finally:
            raw.close()
        with open(self.path("grace-a.db"), "rb") as handle:
            before = handle.read()
        with self.assertRaises(VerificationError):
            SQLiteBackend.open(self.path("grace-a.db"))
        with open(self.path("grace-a.db"), "rb") as handle:
            self.assertEqual(handle.read(), before)


class TransactionTests(SQLiteCase):
    def test_commit_persists_writes(self):
        backend = self.create()
        with backend.transaction():
            entry = backend.journal.append_transfer("a", "b", 10)
            backend.audit.append(
                kind="decision", actor="x", action="get_balance",
                arg_hash="h", policy_version="v1",
                decision="allowed", reason="ok",
            )
        self.assertEqual(entry.seq, 1)
        self.assertEqual(len(backend.journal), 1)
        self.assertEqual(len(backend.audit), 2)

    def test_rollback_discards_all_writes(self):
        backend = self.create()
        with self.assertRaises(RuntimeError):
            with backend.transaction():
                backend.journal.append_transfer("a", "b", 10)
                backend.audit.append(
                    kind="decision", actor="x", action="get_balance",
                    arg_hash="h", policy_version="v1",
                    decision="allowed", reason="ok",
                )
                backend.confirmations.issue("transfer_money", "h", "v1")
                SQLiteMutator(backend.ledger).apply_transfer(
                    "alice", "bob", 10
                )
                raise RuntimeError("boom")
        self.assertEqual(len(backend.journal), 0)
        self.assertEqual(len(backend.audit), 1)
        self.assertEqual(backend.confirmations.pending_count(), 0)
        self.assertEqual(backend.ledger.snapshot(), {"alice": 10000})

    def test_backend_reusable_after_rollback(self):
        backend = self.create()
        with self.assertRaises(ValueError):
            with backend.transaction():
                backend.journal.append_transfer("a", "b", 10)
                raise ValueError("boom")
        with backend.transaction():
            entry = backend.journal.append_transfer("a", "b", 10)
        self.assertEqual(entry.seq, 1)
        self.assertEqual(len(backend.journal), 1)

    def test_nested_transaction_rejected_outer_survives(self):
        backend = self.create()
        with backend.transaction():
            backend.journal.append_transfer("a", "b", 10)
            with self.assertRaises(SQLiteBackendError):
                with backend.transaction():
                    pass
            backend.journal.append_transfer("a", "b", 20)
        self.assertEqual(
            [e.amount for e in backend.journal.entries()], [10, 20]
        )

    def test_writes_require_transaction(self):
        backend = self.create()
        with self.assertRaises(SQLiteBackendError):
            backend.journal.append_transfer("a", "b", 10)
        with self.assertRaises(SQLiteBackendError):
            backend.audit.append(
                kind="decision", actor="x", action="get_balance",
                arg_hash="h", policy_version="v1",
                decision="allowed", reason="ok",
            )
        with self.assertRaises(SQLiteBackendError):
            backend.confirmations.issue("transfer_money", "h", "v1")
        with backend.transaction():
            token = backend.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        with self.assertRaises(SQLiteBackendError):
            backend.confirmations.redeem(
                token, "transfer_money", "h", "v1"
            )
        with self.assertRaises(SQLiteBackendError):
            backend.confirmations.consume(token)
        with self.assertRaises(SQLiteBackendError):
            backend.confirmations.purge_version("v1")
        with self.assertRaises(SQLiteBackendError):
            backend.confirmations.clear()
        with self.assertRaises(SQLiteBackendError):
            SQLiteMutator(backend.ledger).apply_transfer(
                "alice", "bob", 10
            )
        # Nothing above took effect.
        self.assertEqual(len(backend.journal), 0)
        self.assertEqual(len(backend.audit), 1)
        self.assertEqual(backend.confirmations.pending_count(), 1)
        self.assertEqual(backend.ledger.snapshot(), {"alice": 10000})

    def test_reads_allowed_outside_transaction(self):
        backend = self.create(clock=FakeClock(2000.0))
        self.assertEqual(backend.ledger.balance("alice"), 10000)
        self.assertEqual(backend.ledger.snapshot(), {"alice": 10000})
        self.assertEqual(backend.journal.entries(), ())
        self.assertEqual(len(backend.journal), 0)
        self.assertEqual(len(backend.audit), 1)
        self.assertEqual(len(backend.audit.records), 1)
        ok, _ = backend.audit.verify()
        self.assertTrue(ok)
        self.assertEqual(backend.get_policy(), make_policy())
        self.assertEqual(backend.retired_versions(), frozenset())
        self.assertEqual(backend.get_daily_spent(), 0)
        self.assertEqual(backend.confirmations.pending_count(), 0)

    def test_sequences_monotonic_across_transactions(self):
        backend = self.create()
        seqs = []
        for _ in range(3):
            with backend.transaction():
                seqs.append(
                    backend.journal.append_transfer(
                        "a", "b", 1
                    ).seq
                )
        self.assertEqual(seqs, [1, 2, 3])
        audit_seqs = []
        for _ in range(2):
            with backend.transaction():
                record = backend.audit.append(
                    kind="decision", actor="x", action="get_balance",
                    arg_hash="h", policy_version="v1",
                    decision="allowed", reason="ok",
                )
                audit_seqs.append(record["seq"])
        self.assertEqual(audit_seqs, [2, 3])

    def test_failed_begin_leaves_no_phantom_transaction(self):
        backend = self.create()
        backend.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            with backend.transaction():
                pass
        self.assertFalse(backend._in_transaction)

    def test_policy_and_counter_writes_require_transaction(self):
        backend = self.create()
        with self.assertRaises(SQLiteBackendError):
            backend.activate_policy(make_policy(version="v2"))
        with self.assertRaises(SQLiteBackendError):
            backend.add_daily_spent(10)
        with self.assertRaises(SQLiteBackendError):
            backend.reset_daily_spent()
        self.assertEqual(backend.get_policy(), make_policy())
        self.assertEqual(backend.get_daily_spent(), 0)


class ContractParityTests(SQLiteCase):
    def _pair(self):
        mem = MemoryBackend(
            policy=make_policy(), balances={"alice": 10000},
            clock=FakeClock(5000.0),
        )
        sql = self.create(clock=FakeClock(5000.0))
        return mem, sql

    @staticmethod
    def _reason(func, *args):
        try:
            func(*args)
        except ConfirmationError as exc:
            return exc.reason
        raise AssertionError("expected ConfirmationError")

    def test_confirmation_check_matrix_identical(self):
        mem, sql = self._pair()
        with sql.transaction():
            sql_token = sql.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        mem_token = mem.confirmations.issue("transfer_money", "h", "v1")
        # Success returns equal bindings with attribute access.
        mem_binding = mem.confirmations.check(
            mem_token, "transfer_money", "h", "v1"
        )
        sql_binding = sql.confirmations.check(
            sql_token, "transfer_money", "h", "v1"
        )
        self.assertEqual(mem_binding.policy_version, "v1")
        self.assertEqual(sql_binding.policy_version, "v1")
        self.assertEqual(mem_binding, sql_binding)
        # Forged token.
        self.assertEqual(
            self._reason(
                mem.confirmations.check, "nope", "transfer_money",
                "h", "v1",
            ),
            REASON_INVALID,
        )
        self.assertEqual(
            self._reason(
                sql.confirmations.check, "nope", "transfer_money",
                "h", "v1",
            ),
            REASON_INVALID,
        )
        # Consumed token replays as reused on both.
        mem.confirmations.consume(mem_token)
        with sql.transaction():
            sql.confirmations.consume(sql_token)
        for store in (mem.confirmations, sql.confirmations):
            self.assertEqual(
                self._reason(
                    store.check,
                    mem_token if store is mem.confirmations
                    else sql_token,
                    "transfer_money", "h", "v1",
                ),
                REASON_REUSED,
            )

    def test_confirmation_mismatch_and_superseded_identical(self):
        mem, sql = self._pair()
        with sql.transaction():
            sql_token = sql.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        mem_token = mem.confirmations.issue("transfer_money", "h", "v1")
        pairs = [
            (mem.confirmations, mem_token),
            (sql.confirmations, sql_token),
        ]
        for store, token in pairs:
            self.assertEqual(
                self._reason(
                    store.check, token, "get_balance", "h", "v1"
                ),
                REASON_MISMATCH,
            )
            self.assertEqual(
                self._reason(
                    store.check, token, "transfer_money", "other",
                    "v1",
                ),
                REASON_MISMATCH,
            )
            self.assertEqual(
                self._reason(
                    store.check, token, "transfer_money", "h", "v2"
                ),
                REASON_SUPERSEDED,
            )
        # Redeem-then-replay behaves the same on both.
        mem.confirmations.redeem(mem_token, "transfer_money", "h", "v1")
        with sql.transaction():
            sql.confirmations.redeem(
                sql_token, "transfer_money", "h", "v1"
            )
        for store, token in pairs:
            self.assertEqual(
                self._reason(
                    store.check, token, "transfer_money", "h", "v1"
                ),
                REASON_REUSED,
            )

    def test_confirmation_expiry_identical(self):
        mem_clock = FakeClock(1000.0)
        sql_clock = FakeClock(1000.0)
        mem = MemoryBackend(
            policy=make_policy(), balances={"alice": 10000},
            clock=mem_clock,
        )
        sql = self.create(clock=sql_clock)
        mem_token = mem.confirmations.issue("transfer_money", "h", "v1")
        with sql.transaction():
            sql_token = sql.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        mem_clock.advance(299.0)
        sql_clock.advance(299.0)
        mem.confirmations.check(mem_token, "transfer_money", "h", "v1")
        sql.confirmations.check(sql_token, "transfer_money", "h", "v1")
        mem_clock.advance(2.0)
        sql_clock.advance(2.0)
        self.assertEqual(
            self._reason(
                mem.confirmations.check, mem_token,
                "transfer_money", "h", "v1",
            ),
            REASON_EXPIRED,
        )
        self.assertEqual(
            self._reason(
                sql.confirmations.check, sql_token,
                "transfer_money", "h", "v1",
            ),
            REASON_EXPIRED,
        )

    def test_confirmation_envelope_survives_source_retreat(self):
        clock = FakeClock(1000.0)
        backend = self.create(clock=clock)
        with backend.transaction():
            token = backend.confirmations.issue(
                "transfer_money", "h", "v1"
            )
        clock.advance(301.0)
        self.assertEqual(
            self._reason(
                backend.confirmations.check, token,
                "transfer_money", "h", "v1",
            ),
            REASON_EXPIRED,
        )
        clock.set(1100.0)  # unreliable source jumps backward
        self.assertEqual(
            self._reason(
                backend.confirmations.check, token,
                "transfer_money", "h", "v1",
            ),
            REASON_EXPIRED,
        )

    def test_confirmation_purge_and_clear_counts(self):
        mem, sql = self._pair()
        mem.confirmations.issue("transfer_money", "h", "v1")
        mem.confirmations.issue("transfer_money", "h", "v1")
        mem.confirmations.issue("transfer_money", "h", "v2")
        with sql.transaction():
            sql.confirmations.issue("transfer_money", "h", "v1")
            sql.confirmations.issue("transfer_money", "h", "v1")
            sql.confirmations.issue("transfer_money", "h", "v2")
        self.assertEqual(sql.confirmations.pending_count(), 3)
        self.assertEqual(
            sql.confirmations.pending_count(),
            mem.confirmations.pending_count(),
        )
        with sql.transaction():
            purged = sql.confirmations.purge_version("v1")
        self.assertEqual(purged, 2)
        self.assertEqual(
            purged, mem.confirmations.purge_version("v1")
        )
        self.assertEqual(sql.confirmations.pending_count(), 1)
        with sql.transaction():
            cleared = sql.confirmations.clear()
        self.assertEqual(cleared, 1)
        self.assertEqual(cleared, mem.confirmations.clear())
        self.assertEqual(sql.confirmations.pending_count(), 0)

    def test_count_version_matches_purge_parity(self):
        mem, sql = self._pair()
        mem.confirmations.issue("transfer_money", "h", "v1")
        mem.confirmations.issue("transfer_money", "h", "v1")
        mem.confirmations.issue("transfer_money", "h", "v2")
        with sql.transaction():
            sql.confirmations.issue("transfer_money", "h", "v1")
            sql.confirmations.issue("transfer_money", "h", "v1")
            sql.confirmations.issue("transfer_money", "h", "v2")
        for version, expected in (("v1", 2), ("v2", 1), ("v9", 0)):
            self.assertEqual(
                sql.confirmations.count_version(version), expected
            )
            self.assertEqual(
                mem.confirmations.count_version(version), expected
            )
        # Read-only on both: purge still removes the counted tokens.
        with sql.transaction():
            purged = sql.confirmations.purge_version("v1")
        self.assertEqual(purged, 2)
        self.assertEqual(mem.confirmations.purge_version("v1"), 2)
        self.assertEqual(sql.confirmations.count_version("v1"), 0)

    def test_ledger_journal_parity(self):
        mem, sql = self._pair()
        mem_mutator = LedgerMutator(mem.ledger)
        mem_mutator.apply_transfer("alice", "bob", 100)
        mem.journal.append_transfer("alice", "bob", 100)
        with sql.transaction():
            SQLiteMutator(sql.ledger).apply_transfer(
                "alice", "bob", 100
            )
            sql.journal.append_transfer("alice", "bob", 100)
        with self.assertRaises(LedgerError):
            mem_mutator.apply_transfer("alice", "bob", 10 ** 9)
        with sql.transaction():
            with self.assertRaises(LedgerError):
                SQLiteMutator(sql.ledger).apply_transfer(
                    "alice", "bob", 10 ** 9
                )
        self.assertEqual(
            sql.ledger.snapshot(), mem.ledger.snapshot()
        )
        self.assertEqual(
            [
                (e.seq, e.action, e.source, e.target, e.amount)
                for e in sql.journal.entries()
            ],
            [
                (e.seq, e.action, e.source, e.target, e.amount)
                for e in mem.journal.entries()
            ],
        )

    def test_audit_record_bytes_identical(self):
        mem = MemoryBackend(
            policy=make_policy(), balances={"alice": 10000},
            clock=FakeClock(2000.0),
        )
        sql = self.create(clock=FakeClock(2000.0))
        fields = {
            "kind": "decision",
            "actor": "agent",
            "action": "transfer_money",
            "arg_hash": "abc",
            "policy_version": "v1",
            "decision": "confirmation_required",
            "reason": "ok",
            "token_id": "deadbeef",
            "extra": {"nested": [1, {"k": "v"}]},
        }
        mem_record = mem.audit.append(**fields)
        with sql.transaction():
            sql_record = sql.audit.append(**fields)
        self.assertEqual(
            canonicalize(sql_record), canonicalize(mem_record)
        )
        mem_genesis, sql_genesis = (
            mem.audit.records[0],
            sql.audit.records[0],
        )
        self.assertEqual(
            canonicalize(sql_genesis), canonicalize(mem_genesis)
        )
        mem_export = os.path.join(self.tmp.name, "mem.jsonl")
        sql_export = os.path.join(self.tmp.name, "sql.jsonl")
        mem_report = mem.audit.export_jsonl(mem_export)
        sql_report = sql.audit.export_jsonl(sql_export)
        self.assertEqual(sql_report["records"], mem_report["records"])
        with open(mem_export, "rb") as handle:
            mem_blob = handle.read()
        with open(sql_export, "rb") as handle:
            sql_blob = handle.read()
        self.assertEqual(sql_blob, mem_blob)
        self.assertEqual(sql_report["sha256"], mem_report["sha256"])
        self.assertTrue(verify_export(sql_export)[0])

    def test_audit_isolation_parity(self):
        mem, sql = self._pair()
        extra = {"nested": [1, 2]}
        mem_record = mem.audit.append(
            kind="decision", actor="x", action="get_balance",
            arg_hash="h", policy_version="v1", decision="allowed",
            reason="ok", extra={"nested": [1, 2]},
        )
        with sql.transaction():
            sql_record = sql.audit.append(
                kind="decision", actor="x", action="get_balance",
                arg_hash="h", policy_version="v1",
                decision="allowed", reason="ok", extra=extra,
            )
        extra["nested"].append(3)
        mem_record["extra"]["nested"].append(4)
        sql_record["extra"]["nested"].append(4)
        for record in mem.audit.records:
            if record["kind"] == "decision":
                self.assertEqual(record["extra"], {"nested": [1, 2]})
        for record in sql.audit.records:
            if record["kind"] == "decision":
                self.assertEqual(record["extra"], {"nested": [1, 2]})
        self.assertTrue(mem.audit.verify()[0])
        self.assertTrue(sql.audit.verify()[0])

    def test_mutator_accepted_by_tools_gate(self):
        self.assertTrue(issubclass(SQLiteMutator, LedgerMutator))
        backend = self.create()
        with backend.transaction():
            result = transfer_money(
                SQLiteMutator(backend.ledger),
                "alice", "bob", 250,
            )
        self.assertEqual(result, (9750, 250))
        self.assertEqual(
            backend.ledger.snapshot(), {"alice": 9750, "bob": 250}
        )

    def test_fault_hooks_fire_inside_transaction(self):
        backend = self.create()
        backend.ledger.fault_hook = lambda: 1 / 0
        with self.assertRaises(ZeroDivisionError):
            with backend.transaction():
                SQLiteMutator(backend.ledger).apply_transfer(
                    "alice", "bob", 10
                )
        self.assertEqual(backend.ledger.snapshot(), {"alice": 10000})

        def boom(kind):
            raise AuditError("boom", {"kind": kind})

        backend.audit.fault_hook = boom
        with self.assertRaises(AuditError):
            with backend.transaction():
                backend.audit.append(
                    kind="decision", actor="x",
                    action="get_balance", arg_hash="h",
                    policy_version="v1", decision="allowed",
                    reason="ok",
                )
        self.assertEqual(len(backend.audit), 1)

    def test_ttl_validation_matches_store(self):
        bad_values = (
            float("inf"), float("nan"), 0, -1, True, "300",
            None.__class__,
        )
        for index, bad in enumerate(bad_values):
            with self.assertRaises(ValueError):
                SQLiteBackend.create(
                    self.path("ttl-bad%d.db" % index),
                    policy=make_policy(),
                    balances={"alice": 10000},
                    ttl_seconds=bad,
                )
            self.assertFalse(
                os.path.exists(self.path("ttl-bad%d.db" % index))
            )
        backend = self.create(name="ttl-ok.db", ttl_seconds=10 ** 9)
        self.assertEqual(backend._ttl, 10 ** 9)


if __name__ == "__main__":
    unittest.main()
