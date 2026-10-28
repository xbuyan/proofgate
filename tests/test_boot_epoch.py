"""Tests for S3 boot-epoch advancement (A2.4).

Every successful ``SQLiteBackend.open()`` of a verified database is
one boot: ``boot_epoch`` advances exactly once and the advancement is
recorded in the existing audit chain. Refused opens leave the epoch
and the chain untouched.
"""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.policy import Policy
from proofgate.sqlite_backend import SQLiteBackend
from proofgate.verify import VerificationError


def make_policy(**overrides):
    params = {
        "version": "v1",
        "per_transfer_cap": 500,
        "daily_cap": 1000,
        "allowed_targets": ("bob", "carol"),
    }
    params.update(overrides)
    return Policy.create(**params)


class BootEpochCase(unittest.TestCase):
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
        backend.close()
        return self.path(name)

    def open(self, name="g.db"):
        backend = SQLiteBackend.open(self.path(name))
        self._backends.append(backend)
        return backend

    def epoch(self, name="g.db"):
        raw = sqlite3.connect(self.path(name))
        try:
            return raw.execute(
                "SELECT value FROM counters WHERE name = 'boot_epoch'"
            ).fetchone()[0]
        finally:
            raw.close()

    def audit_state(self, name="g.db"):
        # The audit store allocates sequences from the chain head,
        # not from a counter: capture row count plus head identity.
        raw = sqlite3.connect(self.path(name))
        try:
            rows = raw.execute(
                "SELECT COUNT(*) FROM audit"
            ).fetchone()[0]
            head = raw.execute(
                "SELECT seq, record_hash FROM audit "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        finally:
            raw.close()
        return rows, head[0], head[1]

    def file_bytes(self, name="g.db"):
        with open(self.path(name), "rb") as handle:
            return handle.read()


class BootEpochTests(BootEpochCase):
    def test_first_open_advances_zero_to_one_with_evidence(self):
        self.create()
        backend = self.open()
        self.assertEqual(self.epoch(), 1)
        records = backend.audit.records
        self.assertEqual(len(records), 2)
        boot = records[1]
        self.assertEqual(boot["kind"], "boot")
        self.assertEqual(boot["action"], "startup")
        self.assertEqual(boot["decision"], "recorded")
        self.assertEqual(
            (boot["extra"]["prior_epoch"],
             boot["extra"]["new_epoch"]),
            (0, 1),
        )
        ok, _ = backend.audit.verify()
        self.assertTrue(ok)

    def test_reopen_advances_monotonically(self):
        self.create()
        backend = self.open()
        backend.close()
        backend = self.open()
        self.assertEqual(self.epoch(), 2)
        records = backend.audit.records
        self.assertEqual(len(records), 3)
        self.assertEqual(
            [r["kind"] for r in records],
            ["genesis", "boot", "boot"],
        )
        self.assertEqual(
            [(r["extra"]["prior_epoch"], r["extra"]["new_epoch"])
             for r in records[1:]],
            [(0, 1), (1, 2)],
        )
        ok, _ = backend.audit.verify()
        self.assertTrue(ok)

    def test_failed_open_leaves_epoch_and_chain_intact(self):
        self.create()
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "UPDATE counters SET value = -5 "
                "WHERE name = 'daily_spent'"
            )
            raw.commit()
        finally:
            raw.close()
        before = self.file_bytes()
        with self.assertRaises(VerificationError):
            SQLiteBackend.open(self.path())
        self.assertEqual(self.file_bytes(), before)
        self.assertEqual(self.epoch(), 0)

    def test_counter_failure_rolls_back_evidence(self):
        self.create()
        genesis = self.audit_state()
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "CREATE TRIGGER t_abort_boot BEFORE UPDATE "
                "ON counters WHEN NEW.name = 'boot_epoch' "
                "BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
            raw.commit()
        finally:
            raw.close()
        # RAISE(ABORT, ...) reports SQLITE_CONSTRAINT, which Python
        # maps to IntegrityError (not OperationalError).
        with self.assertRaises(sqlite3.IntegrityError):
            SQLiteBackend.open(self.path())
        self.assertEqual(self.epoch(), 0)
        self.assertEqual(genesis[:2], (1, 1))
        self.assertEqual(self.audit_state(), genesis)
        # Retry after removing the fault advances exactly once.
        raw = sqlite3.connect(self.path())
        try:
            raw.execute("DROP TRIGGER t_abort_boot")
            raw.commit()
        finally:
            raw.close()
        backend = self.open()
        self.assertEqual(self.epoch(), 1)
        records = backend.audit.records
        self.assertEqual(len(records), 2)
        self.assertEqual(
            (records[1]["extra"]["prior_epoch"],
             records[1]["extra"]["new_epoch"]),
            (0, 1),
        )
        ok, _ = backend.audit.verify()
        self.assertTrue(ok)

    def test_evidence_failure_rolls_back_counter(self):
        self.create()
        genesis = self.audit_state()
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "CREATE TRIGGER t_abort_audit BEFORE INSERT "
                "ON audit WHEN NEW.kind = 'boot' "
                "BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
            raw.commit()
        finally:
            raw.close()
        with self.assertRaises(sqlite3.IntegrityError):
            SQLiteBackend.open(self.path())
        self.assertEqual(self.epoch(), 0)
        self.assertEqual(genesis[:2], (1, 1))
        self.assertEqual(self.audit_state(), genesis)
        # Retry after removing the fault advances exactly once.
        raw = sqlite3.connect(self.path())
        try:
            raw.execute("DROP TRIGGER t_abort_audit")
            raw.commit()
        finally:
            raw.close()
        backend = self.open()
        self.assertEqual(self.epoch(), 1)
        self.assertEqual(len(backend.audit.records), 2)
        ok, _ = backend.audit.verify()
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
