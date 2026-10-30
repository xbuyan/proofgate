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

from proofgate.canonical import arg_hash
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


class KeyingStartupTests(VerifyCase):
    """Slice B Phase 3: keying invariants enforced at startup."""

    ARGS = {"source": "alice", "target": "bob", "amount": 100}

    def gate_pair(self, name="g.db"):
        backend = self.create(name=name)
        gate = Gate(policy=make_policy(), storage=backend)
        return gate, backend

    def keyed_transfer(self, gate, key, args=None):
        args = dict(args or self.ARGS)
        initial = gate.gate({
            "action": "transfer_money", "args": args,
            "idempotency_key": key,
        })
        self.assertEqual(initial["status"], "confirmation_required")
        allowed = gate.gate({
            "action": "transfer_money", "args": args,
            "confirmation": initial["confirmation"],
            "idempotency_key": key,
        })
        self.assertEqual(allowed["status"], "allowed")
        return allowed

    def keyless_transfer(self, gate, args=None):
        args = dict(args or self.ARGS)
        initial = gate.gate({
            "action": "transfer_money", "args": args,
        })
        self.assertEqual(initial["status"], "confirmation_required")
        allowed = gate.gate({
            "action": "transfer_money", "args": args,
            "confirmation": initial["confirmation"],
        })
        self.assertEqual(allowed["status"], "allowed")
        return allowed

    def build_keying_db(self, name, specs):
        """Craft a chain-valid DB with explicit OUTCOME markers.

        Each spec describes one transfer execution: ``marker`` is
        "keyed", "keyless", "legacy", or a custom extra overlay dict;
        ``key`` registers an operation row (None for OUTCOME-only);
        ``receipt`` "new"/"legacy" completes it, None leaves pending.
        A keyed marker uses ``marker_key`` when given, else ``key``.
        Evidence crafting only: no keying rules are enforced here.
        """
        backend = self.create(name=name)
        digest = arg_hash(dict(self.ARGS))
        with backend.transaction():
            for spec in specs:
                SQLiteMutator(backend.ledger).apply_transfer(
                    "alice", "bob", 100
                )
                entry = backend.journal.append_transfer(
                    "alice", "bob", 100
                )
                backend.audit.append(
                    kind="decision", actor="agent",
                    action="transfer_money", arg_hash=digest,
                    policy_version="v1",
                    decision="confirmation_required", reason="ok",
                    token_id="deadbeef", extra={},
                )
                backend.audit.append(
                    kind="authorized", actor="agent",
                    action="transfer_money", arg_hash=digest,
                    policy_version="v1", decision="authorized",
                    reason="ok", token_id="deadbeef", extra={},
                )
                extra = {
                    "journal_seq": entry.seq,
                    "source_balance": backend.ledger.balance("alice"),
                    "target_balance": backend.ledger.balance("bob"),
                }
                marker = spec.get("marker", "legacy")
                key = spec.get("key")
                if marker == "keyed":
                    extra["keyed"] = True
                    extra["op_key"] = spec.get("marker_key", key)
                elif marker == "keyless":
                    extra["keyed"] = False
                elif isinstance(marker, dict):
                    extra.update(marker)
                outcome = backend.audit.append(
                    kind="outcome", actor="agent",
                    action="transfer_money", arg_hash=digest,
                    policy_version="v1", decision="allowed",
                    reason="ok", token_id="deadbeef", extra=extra,
                )
                mode = spec.get("receipt")
                if mode is not None and key is None:
                    raise AssertionError(
                        "keying spec needs key for receipt/op"
                    )
                if key is not None and mode is not None:
                    receipt = {
                        "action": "transfer_money", "source": "alice",
                        "target": "bob", "amount": 100,
                        "journal_seq": entry.seq,
                        "source_balance": extra["source_balance"],
                        "target_balance": extra["target_balance"],
                        "policy_version": "v1",
                    }
                    if mode == "new":
                        receipt["op_key"] = key
                        receipt["audit_seq"] = outcome["seq"]
                    backend.register_operation(
                        key, "transfer_money", digest, "agent"
                    )
                    backend.complete_operation(key, receipt)
                elif key is not None:
                    backend.register_operation(
                        key, "transfer_money", digest, "agent"
                    )
                backend.confirmations.issue(
                    "transfer_money", digest, "v1"
                )
        backend.close()
        return self.path(name)

    def boot_epoch(self, name):
        raw = sqlite3.connect(self.path(name))
        try:
            row = raw.execute(
                "SELECT value FROM counters WHERE name = 'boot_epoch'"
            ).fetchone()
        finally:
            raw.close()
        return row[0]

    def rewrite_receipt(self, name, key, mutate):
        raw = sqlite3.connect(self.path(name))
        try:
            row = raw.execute(
                "SELECT receipt_json FROM operations WHERE op_key = ?",
                (key,),
            ).fetchone()
            receipt = json.loads(row[0])
            mutate(receipt)
            raw.execute(
                "UPDATE operations SET receipt_json = ? "
                "WHERE op_key = ?",
                (json.dumps(receipt), key),
            )
            raw.commit()
        finally:
            raw.close()

    def assert_keying_refused(self, name, problem):
        epoch = self.boot_epoch(name)
        exc = self.assert_refused_unmodified(name, "operation_evidence")
        self.assertEqual(exc.detail["problem"], problem)
        self.assertEqual(self.boot_epoch(name), epoch)
        return exc

    def test_keyed_history_opens(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "ka-1")
        self.keyed_transfer(gate, "ka-2", {
            "source": "alice", "target": "carol", "amount": 50,
        })
        backend.close()
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        self.assertEqual(self.boot_epoch("g.db"), 1)

    def test_keyless_history_opens(self):
        gate, backend = self.gate_pair()
        self.keyless_transfer(gate)
        self.keyless_transfer(gate)
        backend.close()
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        self.assertEqual(self.boot_epoch("g.db"), 1)

    def test_mixed_legacy_keyed_opens(self):
        self.build_keying_db("g.db", [
            {"marker": "legacy"},
            {"marker": "legacy", "key": "lx", "receipt": "legacy"},
            {"marker": "keyed", "key": "kx", "receipt": "new"},
        ])
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        self.assertEqual(self.boot_epoch("g.db"), 1)

    def test_mixed_legacy_keyless_opens(self):
        self.build_keying_db("g.db", [
            {"marker": "legacy", "key": "lx", "receipt": "legacy"},
            {"marker": "keyless"},
        ])
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        self.assertEqual(self.boot_epoch("g.db"), 1)

    def test_pending_keyless_coexistence_opens(self):
        gate, backend = self.gate_pair()
        initial = gate.gate({
            "action": "transfer_money", "args": dict(self.ARGS),
            "idempotency_key": "kp-1",
        })
        self.assertEqual(initial["status"], "confirmation_required")
        self.keyless_transfer(gate)
        backend.close()
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        self.assertEqual(self.boot_epoch("g.db"), 1)

    def test_same_fingerprint_distinct_executions_open(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "ks-1")
        self.keyed_transfer(gate, "ks-2")
        backend.close()
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        self.assertEqual(self.boot_epoch("g.db"), 1)

    def test_malformed_marker_refused(self):
        overlays = [
            {"keyed": "yes"},
            {"keyed": True},
            {"keyed": False, "op_key": "k"},
        ]
        for index, overlay in enumerate(overlays):
            with self.subTest(overlay=overlay):
                name = "m-%d.db" % index
                self.build_keying_db(name, [{"marker": overlay}])
                self.assert_keying_refused(name, "keying_malformed")

    def test_malformed_receipt_pair_refused(self):
        def drop_seq(receipt):
            receipt.pop("audit_seq")

        def drop_key(receipt):
            receipt.pop("op_key")

        for index, mutate in enumerate((drop_seq, drop_key)):
            with self.subTest(index=index):
                name = "p-%d.db" % index
                gate, backend = self.gate_pair(name)
                self.keyed_transfer(gate, "k")
                backend.close()
                self.rewrite_receipt(name, "k", mutate)
                self.assert_keying_refused(
                    name, "receipt_keying_malformed"
                )

    def test_deleted_record_refused(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "k")
        backend.close()
        self.corrupt("g.db", [
            ("DELETE FROM operations WHERE op_key = ?", ("k",)),
            ("UPDATE confirmations SET op_key = NULL "
             "WHERE op_key = ?", ("k",)),
        ])
        self.assert_keying_refused("g.db", "outcome_orphaned")

    def test_keyed_pending_refused(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "k")
        backend.close()
        self.corrupt("g.db", [
            ("UPDATE operations SET status = 'pending', "
             "receipt_json = NULL WHERE op_key = ?", ("k",)),
        ])
        self.assert_keying_refused("g.db", "keyed_pending")

    def test_wrong_audit_seq_refused(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "k")
        backend.close()
        self.rewrite_receipt(
            "g.db", "k", lambda r: r.update(audit_seq=999)
        )
        self.assert_keying_refused("g.db", "receipt_position_mismatch")

    def test_wrong_op_key_refused(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "k")
        backend.close()
        self.rewrite_receipt(
            "g.db", "k", lambda r: r.update(op_key="intruder")
        )
        self.assert_keying_refused("g.db", "receipt_key_mismatch")

    def test_dual_position_claim_refused(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "k1")
        self.keyed_transfer(gate, "k2")
        backend.close()
        raw = sqlite3.connect(self.path())
        try:
            seqs = [
                row[0] for row in raw.execute(
                    "SELECT seq FROM audit WHERE kind = 'outcome' "
                    "AND decision = 'allowed' ORDER BY seq"
                )
            ]
        finally:
            raw.close()
        self.rewrite_receipt(
            "g.db", "k2", lambda r: r.update(audit_seq=seqs[0])
        )
        self.assert_keying_refused("g.db", "receipt_position_mismatch")

    def test_dual_outcome_claim_refused(self):
        self.build_keying_db("g.db", [
            {"marker": "keyed", "key": "k", "receipt": "new"},
            {"marker": "keyed", "marker_key": "k"},
        ])
        self.assert_keying_refused("g.db", "receipt_position_mismatch")

    def test_keyless_contradiction_refused(self):
        self.build_keying_db("g.db", [
            {"marker": "keyless", "key": "kc", "receipt": "legacy"},
        ])
        self.assert_keying_refused("g.db", "keyless_contradiction")

    def test_checkpoint_untouched_on_keying_refusal(self):
        gate, backend = self.gate_pair()
        self.keyed_transfer(gate, "k")
        raw = sqlite3.connect(self.path())
        try:
            head = raw.execute(
                "SELECT seq, record_hash FROM audit "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        finally:
            raw.close()
        backend.checkpoint(
            self.path("c.json"), deployment_id="test-deploy",
            expected_seq=head[0], expected_hash=head[1],
        )
        backend.close()
        with open(self.path("c.json"), "rb") as handle:
            before = handle.read()
        self.rewrite_receipt(
            "g.db", "k", lambda r: r.update(audit_seq=999)
        )
        with self.assertRaises(VerificationError) as caught:
            SQLiteBackend.open(
                self.path(), checkpoint_path=self.path("c.json"),
                deployment_id="test-deploy",
            )
        self.assertEqual(
            caught.exception.category, "operation_evidence"
        )
        with open(self.path("c.json"), "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_valid_open_after_refusal(self):
        gate, backend = self.gate_pair("bad.db")
        self.keyed_transfer(gate, "k")
        backend.close()
        self.rewrite_receipt(
            "bad.db", "k", lambda r: r.update(audit_seq=999)
        )
        with self.assertRaises(VerificationError):
            SQLiteBackend.open(self.path("bad.db"))
        gate2, backend2 = self.gate_pair("good.db")
        self.keyed_transfer(gate2, "g")
        backend2.close()
        reopened = SQLiteBackend.open(self.path("good.db"))
        self._backends.append(reopened)
        self.assertEqual(self.boot_epoch("good.db"), 1)


if __name__ == "__main__":
    unittest.main()
