"""Startup verification tests (A2.4 S2).

Every negative test proves three things: ``open()`` raises
``VerificationError`` with the expected category, the database file is
byte-identical afterwards (verification never writes), and no usable
backend escapes. Corruption is crafted with direct SQL against
temporary files only.
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.enforcement import Gate
from proofgate.policy import Policy
from proofgate.sqlite_backend import (
    SQLiteBackend,
    _REQUIRED_TABLES,
)
from proofgate.sqlite_backend import _Mutator as SQLiteMutator
from proofgate.verify import VerificationError, verify_database


def make_policy():
    return Policy.create(
        version="v1", per_transfer_cap=500, daily_cap=1000,
        allowed_targets=("bob", "carol"),
    )


class VerifyCase(unittest.TestCase):
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

    def make_valid_database(self, name="g.db"):
        """Build a gate-consistent database: transfer plus full trail."""
        backend = self.create(name=name)
        with backend.transaction():
            SQLiteMutator(backend.ledger).apply_transfer(
                "alice", "bob", 100
            )
            backend.journal.append_transfer("alice", "bob", 100)
            backend.audit.append(
                kind="decision", actor="agent",
                action="transfer_money", arg_hash="h",
                policy_version="v1",
                decision="confirmation_required", reason="ok",
                token_id="deadbeef", extra={},
            )
            backend.audit.append(
                kind="authorized", actor="agent",
                action="transfer_money", arg_hash="h",
                policy_version="v1", decision="authorized",
                reason="ok", token_id="deadbeef", extra={},
            )
            backend.audit.append(
                kind="outcome", actor="agent",
                action="transfer_money", arg_hash="h",
                policy_version="v1", decision="allowed",
                reason="ok", token_id="deadbeef",
                extra={"journal_seq": 1},
            )
            backend.confirmations.issue("transfer_money", "h", "v1")
        backend.close()
        return self.path(name)

    def corrupt(self, name, statements):
        raw = sqlite3.connect(self.path(name))
        try:
            for sql, params in statements:
                raw.execute(sql, params or ())
            raw.commit()
        finally:
            raw.close()

    def file_bytes(self, name="g.db"):
        with open(self.path(name), "rb") as handle:
            return handle.read()

    def assert_refused_unmodified(self, name, category):
        before = self.file_bytes(name)
        with self.assertRaises(VerificationError) as caught:
            SQLiteBackend.open(self.path(name))
        self.assertEqual(caught.exception.category, category)
        with open(self.path(name), "rb") as handle:
            self.assertEqual(handle.read(), before)
        return caught.exception


class ValidDatabaseTests(VerifyCase):
    def test_valid_database_opens_with_summary(self):
        self.make_valid_database()
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        raw = sqlite3.connect(self.path())
        try:
            summary = verify_database(raw, "3", _REQUIRED_TABLES)
        finally:
            raw.close()
        self.assertEqual(summary["schema_version"], "3")
        self.assertEqual(summary["tables"], 9)
        self.assertEqual(summary["opening_accounts"], 1)
        # The open above is one boot (S3): epoch 0 -> 1.
        self.assertEqual(summary["boot_epoch"], 1)
        self.assertEqual(summary["daily_spent"], 0)
        self.assertEqual(summary["policy_version"], "v1")
        self.assertEqual(summary["retired_versions"], 0)
        self.assertEqual(summary["ledger_accounts"], 2)
        self.assertEqual(summary["confirmations"], 1)
        self.assertEqual(summary["operations"], 0)
        self.assertEqual(summary["journal_entries"], 1)
        self.assertEqual(summary["audit_records"], 5)


class IntegrityTests(VerifyCase):
    def test_garbage_file_refused_direct(self):
        with open(self.path(), "wb") as handle:
            handle.write(b"not a database" * 8)
        before = self.file_bytes()
        raw = sqlite3.connect(self.path())
        try:
            with self.assertRaises(VerificationError) as caught:
                verify_database(raw, "3", _REQUIRED_TABLES)
        finally:
            raw.close()
        self.assertEqual(caught.exception.category, "sqlite_integrity")
        self.assertEqual(self.file_bytes(), before)


class MetadataTests(VerifyCase):
    def test_missing_opening_balances_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("DELETE FROM meta WHERE key = 'opening_balances'", None),
        ])
        self.assert_refused_unmodified("g.db", "metadata")

    def test_malformed_opening_balances_refused(self):
        bad_values = (
            "{", '{"a": -1}', '{"a": "x"}', '{"a": true}',
            '{"": 1}', '"5"', "[]",
        )
        for index, bad in enumerate(bad_values):
            name = "bad%d.db" % index
            self.make_valid_database(name=name)
            self.corrupt(name, [
                ("UPDATE meta SET value = ? "
                 "WHERE key = 'opening_balances'", (bad,)),
            ])
            self.assert_refused_unmodified(name, "metadata")


class PolicyCounterTests(VerifyCase):
    def test_no_active_policy_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE policy_versions SET retired = 1", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "policy")
        self.assertEqual(exc.detail["active_count"], 0)

    def test_multiple_active_policies_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("DROP INDEX active_policy_unique", None),
            ("INSERT INTO policy_versions(version, per_transfer_cap, "
             "daily_cap, allowed_targets, retired) "
             "VALUES ('v2', 500, 1000, '[\"carol\"]', 0)", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "policy")
        self.assertEqual(exc.detail["active_count"], 2)

    def test_invalid_policy_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE policy_versions SET per_transfer_cap = -1", None),
        ])
        self.assert_refused_unmodified("g.db", "policy")

    def test_malformed_policy_targets_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE policy_versions SET allowed_targets = 'oops'",
             None),
        ])
        self.assert_refused_unmodified("g.db", "policy")

    def test_missing_counter_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("DELETE FROM counters WHERE name = 'daily_spent'", None),
        ])
        self.assert_refused_unmodified("g.db", "counters")

    def test_negative_counter_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE counters SET value = -5 "
             "WHERE name = 'daily_spent'", None),
        ])
        self.assert_refused_unmodified("g.db", "counters")

    def test_zero_journal_seq_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE counters SET value = 0 "
             "WHERE name = 'journal_seq'", None),
        ])
        self.assert_refused_unmodified("g.db", "counters")


class LedgerConfirmationTests(VerifyCase):
    def test_negative_ledger_balance_refused(self):
        self.make_valid_database()
        # TEXT passes the CHECK via SQLite type ordering (TEXT sorts
        # above INTEGER) yet fails semantic int validation, so this
        # reaches the ledger stage. A raw -5 would violate the CHECK
        # itself and surface at sqlite_integrity instead (quick_check
        # evaluates CHECK constraints); see the used-flag test below
        # for that documented layering.
        self.corrupt("g.db", [
            ("UPDATE ledger SET balance = 'abc' "
             "WHERE account = 'alice'", None),
        ])
        self.assert_refused_unmodified("g.db", "ledger")

    def test_empty_account_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE ledger SET account = '' "
             "WHERE account = 'alice'", None),
        ])
        self.assert_refused_unmodified("g.db", "ledger")

    def test_confirmation_bad_used_refused(self):
        self.make_valid_database()
        # used=2 violates the CHECK constraint, so V1 integrity (whose
        # quick_check evaluates CHECKs) refuses before the semantic
        # stage runs. No CHECK-clean variant exists: every value
        # Python distinguishes from {0, 1} also fails SQL IN (0, 1).
        # The confirmations stage itself is covered by the epoch,
        # expiry, and binding tests below, which do reach it.
        self.corrupt("g.db", [
            ("PRAGMA ignore_check_constraints=ON", None),
            ("UPDATE confirmations SET used = 2", None),
        ])
        self.assert_refused_unmodified("g.db", "sqlite_integrity")

    def test_confirmation_negative_epoch_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE confirmations SET epoch = -1", None),
        ])
        self.assert_refused_unmodified("g.db", "confirmations")

    def test_confirmation_inverted_expiry_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE confirmations SET expires_at = issued_at - 1",
             None),
        ])
        self.assert_refused_unmodified("g.db", "confirmations")

    def test_confirmation_empty_token_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE confirmations SET token = ''", None),
        ])
        self.assert_refused_unmodified("g.db", "confirmations")


class OperationTests(VerifyCase):
    def insert_op(self, name, **overrides):
        row = {
            "op_key": "op-1",
            "action": "transfer_money",
            "arg_hash": "h",
            "actor": "agent",
            "status": "pending",
            "receipt_json": None,
            "created_epoch": 1,
            "updated_epoch": 1,
        }
        row.update(overrides)
        self.corrupt(name, [
            ("INSERT INTO operations(op_key, action, arg_hash, "
             "actor, status, receipt_json, created_epoch, "
             "updated_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
             (row["op_key"], row["action"], row["arg_hash"],
              row["actor"], row["status"], row["receipt_json"],
              row["created_epoch"], row["updated_epoch"])),
        ])

    def test_valid_operation_opens(self):
        self.make_valid_database()
        self.insert_op("g.db")
        raw = sqlite3.connect(self.path())
        try:
            summary = verify_database(raw, "3", _REQUIRED_TABLES)
        finally:
            raw.close()
        self.assertEqual(summary["operations"], 1)
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        record = backend.get_operation("op-1")
        self.assertEqual(record["status"], "pending")

    def test_bad_key_refused(self):
        self.make_valid_database()
        self.insert_op("g.db", op_key="has space")
        self.assert_refused_unmodified("g.db", "operations")

    def test_bad_binding_refused(self):
        self.make_valid_database()
        self.insert_op("g.db", action="")
        self.assert_refused_unmodified("g.db", "operations")

    def test_pending_receipt_refused(self):
        self.make_valid_database()
        self.insert_op("g.db", receipt_json='"surprise"')
        self.assert_refused_unmodified("g.db", "operations")

    def test_bad_receipt_refused(self):
        self.make_valid_database()
        self.insert_op(
            "g.db", status="committed", receipt_json="not-json"
        )
        self.assert_refused_unmodified("g.db", "operations")

    def test_committed_null_receipt_refused(self):
        self.make_valid_database()
        self.insert_op("g.db", status="committed")
        self.assert_refused_unmodified("g.db", "operations")

    def test_bad_epoch_refused(self):
        self.make_valid_database()
        self.insert_op("g.db", created_epoch=-1)
        self.assert_refused_unmodified("g.db", "operations")

    def test_dangling_op_link_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE confirmations SET op_key = 'ghost'", None),
        ])
        self.assert_refused_unmodified("g.db", "operations")

    def make_committed_op_database(self, name="g.db", key="op-1"):
        """Build a database with one genuine committed operation."""
        backend = self.create(name=name)
        gate = Gate(policy=make_policy(), storage=backend)
        initial = gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": 100},
            "idempotency_key": key,
        })
        allowed = gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": 100},
            "confirmation": initial["confirmation"],
            "idempotency_key": key,
        })
        self.assertEqual(allowed["status"], "allowed")
        backend.close()
        return self.path(name)

    def tamper_receipt(self, name, key, **changes):
        raw = sqlite3.connect(self.path(name))
        try:
            blob = raw.execute(
                "SELECT receipt_json FROM operations "
                "WHERE op_key = ?",
                (key,),
            ).fetchone()[0]
            receipt = json.loads(blob)
            receipt.update(changes)
            raw.execute(
                "UPDATE operations SET receipt_json = ? "
                "WHERE op_key = ?",
                (json.dumps(receipt), key),
            )
            raw.commit()
        finally:
            raw.close()

    def test_committed_operation_verifies(self):
        self.make_committed_op_database()
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        record = backend.get_operation("op-1")
        self.assertEqual(record["status"], "committed")
        raw = sqlite3.connect(self.path())
        try:
            summary = verify_database(raw, "3", _REQUIRED_TABLES)
        finally:
            raw.close()
        self.assertEqual(summary["operations"], 1)

    def test_altered_receipt_amount_refused(self):
        self.make_committed_op_database()
        self.tamper_receipt("g.db", "op-1", amount=999)
        exc = self.assert_refused_unmodified(
            "g.db", "operation_evidence"
        )
        # Amount tampering breaks the fingerprint first: the
        # receipt's own arguments no longer hash to the binding.
        self.assertEqual(exc.detail["problem"], "fingerprint_mismatch")

    def test_consistent_amount_tamper_refused(self):
        # Tamper journal, ledger, and receipt together so replay,
        # cross-check, and value comparisons all still agree: only
        # the fingerprint recomputation can catch it.
        self.make_committed_op_database()
        self.tamper_receipt("g.db", "op-1", amount=50)
        self.corrupt("g.db", [
            ("UPDATE journal SET amount = 50 WHERE seq = 1", None),
            ("UPDATE ledger SET balance = 9950 "
             "WHERE account = 'alice'", None),
            ("UPDATE ledger SET balance = 50 "
             "WHERE account = 'bob'", None),
        ])
        exc = self.assert_refused_unmodified(
            "g.db", "operation_evidence"
        )
        self.assertEqual(exc.detail["problem"], "fingerprint_mismatch")

    def test_altered_receipt_seq_refused(self):
        self.make_committed_op_database()
        self.tamper_receipt("g.db", "op-1", journal_seq=99)
        exc = self.assert_refused_unmodified(
            "g.db", "operation_evidence"
        )
        self.assertEqual(exc.detail["problem"], "journal_mismatch")

    def test_altered_receipt_balances_refused(self):
        self.make_committed_op_database()
        self.tamper_receipt(
            "g.db", "op-1", source_balance=1, target_balance=2
        )
        exc = self.assert_refused_unmodified(
            "g.db", "operation_evidence"
        )
        self.assertEqual(exc.detail["problem"], "outcome_missing")

    def test_empty_receipt_dict_refused(self):
        self.make_committed_op_database()
        self.corrupt("g.db", [
            ("UPDATE operations SET receipt_json = '{}' "
             "WHERE op_key = 'op-1'", None),
        ])
        exc = self.assert_refused_unmodified(
            "g.db", "operation_evidence"
        )
        self.assertEqual(exc.detail["problem"], "bad_receipt_shape")


class JournalTests(VerifyCase):
    def test_journal_gap_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("INSERT INTO journal(seq, action, source, target, amount) "
             "VALUES (5, 'transfer_money', 'alice', 'dave', 10)", None),
        ])
        self.assert_refused_unmodified("g.db", "journal")

    def test_journal_counter_drift_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE counters SET value = 99 "
             "WHERE name = 'journal_seq'", None),
        ])
        self.assert_refused_unmodified("g.db", "journal")

    def test_journal_bad_row_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE journal SET amount = 0 WHERE seq = 1", None),
        ])
        self.assert_refused_unmodified("g.db", "journal")


class AuditTests(VerifyCase):
    def test_empty_audit_refused_without_regenesis(self):
        self.make_valid_database()
        self.corrupt("g.db", [("DELETE FROM audit", None)])
        exc = self.assert_refused_unmodified("g.db", "audit")
        self.assertEqual(exc.detail["problem"], "empty_chain")
        raw = sqlite3.connect(self.path())
        try:
            count = raw.execute(
                "SELECT COUNT(*) FROM audit"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(count, 0)

    def test_bad_genesis_kind_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE audit SET kind = 'decision' WHERE seq = 1", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "audit")
        self.assertEqual(exc.detail["problem"], "bad_genesis")

    def test_bad_genesis_prev_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE audit SET prev_hash = 'X' WHERE seq = 1", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "audit")
        self.assertEqual(exc.detail["problem"], "bad_genesis")

    def test_audit_middle_tamper_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE audit SET reason = 'evil' WHERE seq = 3", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "audit")
        self.assertEqual(exc.detail["problem"], "bad_hash")
        self.assertEqual(exc.detail["index"], 2)

    def test_audit_last_tamper_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE audit SET reason = 'evil' WHERE seq = 4", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "audit")
        self.assertEqual(exc.detail["problem"], "bad_hash")
        self.assertEqual(exc.detail["index"], 3)


class ConsistencyTests(VerifyCase):
    def test_reconcile_break_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("UPDATE ledger SET balance = 1 "
             "WHERE account = 'alice'", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "reconcile")
        self.assertIn("alice", exc.detail["mismatched_accounts"])

    def test_cross_check_gap_refused(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("INSERT INTO journal(seq, action, source, target, amount) "
             "VALUES (2, 'transfer_money', 'alice', 'carol', 50)", None),
            ("UPDATE counters SET value = 3 "
             "WHERE name = 'journal_seq'", None),
            ("UPDATE ledger SET balance = 9850 "
             "WHERE account = 'alice'", None),
            ("INSERT INTO ledger(account, balance) "
             "VALUES ('carol', 50)", None),
        ])
        exc = self.assert_refused_unmodified("g.db", "cross_check")
        self.assertEqual(exc.detail["gaps"], [2])

    def test_orphan_outcome_refused(self):
        self.make_valid_database()
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        with backend.transaction():
            backend.audit.append(
                kind="outcome", actor="agent",
                action="transfer_money", arg_hash="h",
                policy_version="v1", decision="allowed",
                reason="ok", token_id="deadbeef",
                extra={"journal_seq": 99},
            )
        backend.close()
        exc = self.assert_refused_unmodified("g.db", "cross_check")
        self.assertEqual(exc.detail["orphans"], [99])

    def test_repair_then_open_succeeds(self):
        self.make_valid_database()
        self.corrupt("g.db", [
            ("DELETE FROM journal WHERE seq = 1", None),
        ])
        self.assert_refused_unmodified("g.db", "journal")
        self.corrupt("g.db", [
            ("INSERT INTO journal(seq, action, source, target, amount) "
             "VALUES (1, 'transfer_money', 'alice', 'bob', 100)", None),
        ])
        backend = SQLiteBackend.open(self.path())
        self._backends.append(backend)
        self.assertEqual(backend.get_policy().version, "v1")


if __name__ == "__main__":
    unittest.main()
