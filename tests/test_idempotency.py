"""Keyed idempotency tests: at-most-once synthetic transfers.

A caller-supplied ``idempotency_key`` plus the action/canonical-args
fingerprint names one intended operation. Retries return the stored
receipt instead of executing again, across lost responses, expiry,
and restarts. Keyless behavior is unchanged.
"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.audit import AuditError
from proofgate.canonical import arg_hash
from proofgate.enforcement import Gate
from proofgate.policy import Policy
from proofgate.sqlite_backend import SQLiteBackend
from proofgate.sqlite_backend import _Mutator as SQLiteMutator


def make_policy(**overrides):
    params = {
        "version": "v1",
        "per_transfer_cap": 500,
        "daily_cap": 1000,
        "allowed_targets": ("bob", "carol"),
    }
    params.update(overrides)
    return Policy.create(**params)


def args(amount=100, target="bob"):
    return {"source": "alice", "target": target, "amount": amount}


class FakeClock:
    def __init__(self, value=1000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class IdempotencyCase(unittest.TestCase):
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

    def make_gate(self, name="g.db", policy=None, balances=None):
        policy = policy if policy is not None else make_policy()
        balances = (
            balances if balances is not None else {"alice": 10000}
        )
        backend = SQLiteBackend.create(
            self.path(name), policy=policy, balances=balances
        )
        self._backends.append(backend)
        return Gate(policy=policy, storage=backend), backend

    def reopen(self, backend, name="g.db"):
        backend.close()
        reopened = SQLiteBackend.open(self.path(name))
        self._backends.append(reopened)
        return (
            Gate(policy=reopened.get_policy(), storage=reopened),
            reopened,
        )

    def make_memory_gate(self, clock=None):
        return Gate(
            policy=make_policy(), balances={"alice": 10000},
            clock=clock,
        )

    def initial(self, gate, key=None, **kwargs):
        params = {"amount": 100, "target": "bob"}
        params.update(kwargs)
        request = {
            "action": "transfer_money", "args": args(**params),
        }
        if key is not None:
            request["idempotency_key"] = key
        return gate.gate(request)

    def redeem(self, gate, token, key=None, **kwargs):
        params = {"amount": 100, "target": "bob"}
        params.update(kwargs)
        request = {
            "action": "transfer_money", "args": args(**params),
            "confirmation": token,
        }
        if key is not None:
            request["idempotency_key"] = key
        return gate.gate(request)

    def kinds(self, gate):
        return [r["kind"] for r in gate.audit_records()]

    def decisions(self, gate):
        return [
            (r["kind"], r["decision"])
            for r in gate.audit_records()
        ]


class SequentialDuplicateTests(IdempotencyCase):
    def test_sequential_duplicate_returns_stored_receipt(self):
        gate, _ = self.make_gate()
        first = self.initial(gate, "op-1")
        token = first["confirmation"]
        allowed = self.redeem(gate, token, "op-1")
        self.assertEqual(allowed["status"], "allowed")
        self.assertNotIn("duplicate", allowed)
        again = self.initial(gate, "op-1")
        self.assertEqual(again["status"], "allowed")
        self.assertEqual(again["reason"], "ok")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["receipt"], allowed["receipt"])
        # Exactly one execution behind both responses.
        self.assertEqual(len(gate.journal_entries()), 1)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        authorized = [
            r for r in gate.audit_records()
            if r["kind"] == "authorized"
        ]
        outcomes = [
            r for r in gate.audit_records()
            if r["kind"] == "outcome"
        ]
        self.assertEqual(len(authorized), 1)
        self.assertEqual(len(outcomes), 1)
        duplicates = [
            r for r in gate.audit_records()
            if r["decision"] == "duplicate"
        ]
        self.assertEqual(len(duplicates), 1)

    def test_second_token_after_commit_returns_outcome(self):
        gate, _ = self.make_gate()
        first = self.initial(gate, "op-2")
        second = self.initial(gate, "op-2")
        self.assertEqual(first["status"], "confirmation_required")
        self.assertEqual(second["status"], "confirmation_required")
        self.assertNotEqual(
            first["confirmation"], second["confirmation"]
        )
        allowed = self.redeem(gate, first["confirmation"], "op-2")
        self.assertEqual(allowed["status"], "allowed")
        # The other live token now resolves to the same outcome.
        replay = self.redeem(gate, second["confirmation"], "op-2")
        self.assertEqual(replay["status"], "allowed")
        self.assertTrue(replay["duplicate"])
        self.assertEqual(replay["receipt"], allowed["receipt"])
        self.assertEqual(len(gate.journal_entries()), 1)

    def test_pending_resumes_without_new_registration(self):
        gate, _ = self.make_gate()
        first = self.initial(gate, "op-3")
        status = gate.operation_status("op-3")
        self.assertEqual(status["status"], "pending")
        second = self.initial(gate, "op-3")
        self.assertEqual(second["status"], "confirmation_required")
        allowed = self.redeem(gate, second["confirmation"], "op-3")
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(len(gate.journal_entries()), 1)
        # The first token resolves to the same committed outcome.
        replay = self.redeem(gate, first["confirmation"], "op-3")
        self.assertEqual(replay["status"], "allowed")
        self.assertTrue(replay["duplicate"])
        self.assertEqual(replay["receipt"], allowed["receipt"])

    def test_committed_duplicate_ignores_later_policy(self):
        gate, _ = self.make_gate()
        token = self.initial(gate, "op-4")["confirmation"]
        allowed = self.redeem(gate, token, "op-4")
        self.assertEqual(allowed["status"], "allowed")
        updated = gate.update_policy(make_policy(
            version="v2", per_transfer_cap=10,
        ))
        self.assertEqual(updated["status"], "policy_updated")
        # Live policy would deny a fresh 100-transfer, but the
        # committed outcome is historical fact, not a new attempt.
        again = self.initial(gate, "op-4")
        self.assertEqual(again["status"], "allowed")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["receipt"], allowed["receipt"])


class ConflictTests(IdempotencyCase):
    def test_same_key_different_args_conflicts(self):
        gate, _ = self.make_gate()
        token = self.initial(gate, "op-5")["confirmation"]
        allowed = self.redeem(gate, token, "op-5")
        self.assertEqual(allowed["status"], "allowed")
        equivalent = self.initial(gate, "op-5", amount=200)
        self.assertEqual(equivalent["status"], "denied")
        self.assertEqual(
            equivalent["reason"], "operation_conflict"
        )
        self.assertEqual(len(gate.journal_entries()), 1)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        other_target = self.initial(gate, "op-5", target="carol")
        self.assertEqual(other_target["reason"], "operation_conflict")
        self.assertEqual(len(gate.journal_entries()), 1)

    def test_conflict_before_any_execution(self):
        gate, _ = self.make_gate()
        first = self.initial(gate, "op-6")
        self.assertEqual(first["status"], "confirmation_required")
        clash = self.initial(gate, "op-6", amount=50)
        self.assertEqual(clash["status"], "denied")
        self.assertEqual(clash["reason"], "operation_conflict")
        # The pending operation is undisturbed and still resumable.
        self.assertEqual(
            gate.operation_status("op-6")["status"], "pending"
        )
        allowed = self.redeem(gate, first["confirmation"], "op-6")
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(len(gate.journal_entries()), 1)

    def test_token_key_mismatch_conflicts(self):
        gate, _ = self.make_gate()
        token = self.initial(gate, "op-7")["confirmation"]
        clash = self.redeem(gate, token, "op-other")
        self.assertEqual(clash["status"], "denied")
        self.assertEqual(clash["reason"], "operation_conflict")
        self.assertEqual(len(gate.journal_entries()), 0)
        self.assertEqual(
            gate.operation_status("op-other")["status"], "not_found"
        )
        # The original operation still resumes cleanly.
        allowed = self.redeem(gate, token, "op-7")
        self.assertEqual(allowed["status"], "allowed")

    def test_query_conflict_with_fingerprint(self):
        gate, _ = self.make_gate()
        token = self.initial(gate, "op-8")["confirmation"]
        self.redeem(gate, token, "op-8")
        match = gate.operation_status("op-8", "transfer_money",
                                       args())
        self.assertEqual(match["status"], "committed")
        clash = gate.operation_status(
            "op-8", "transfer_money", args(amount=7)
        )
        self.assertEqual(clash["status"], "conflict")


class RestartExpiryTests(IdempotencyCase):
    def test_duplicate_after_restart(self):
        gate, backend = self.make_gate()
        token = self.initial(gate, "op-9")["confirmation"]
        allowed = self.redeem(gate, token, "op-9")
        self.assertEqual(allowed["status"], "allowed")
        gate2, _ = self.reopen(backend)
        status = gate2.operation_status("op-9")
        self.assertEqual(status["status"], "committed")
        self.assertEqual(status["receipt"], allowed["receipt"])
        again = self.initial(gate2, "op-9")
        self.assertEqual(again["status"], "allowed")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["receipt"], allowed["receipt"])
        self.assertEqual(len(gate2.journal_entries()), 1)
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

    def test_stale_token_fresh_resume_after_restart(self):
        gate, backend = self.make_gate()
        old = self.initial(gate, "op-10")["confirmation"]
        gate2, _ = self.reopen(backend)
        stale = self.redeem(gate2, old, "op-10")
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")
        self.assertEqual(
            gate2.operation_status("op-10")["status"], "pending"
        )
        fresh = self.initial(gate2, "op-10")["confirmation"]
        allowed = self.redeem(gate2, fresh, "op-10")
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(len(gate2.journal_entries()), 1)

    def test_duplicate_after_confirmation_expiry(self):
        clock = FakeClock()
        gate = self.make_memory_gate(clock=clock)
        token = self.initial(gate, "op-11")["confirmation"]
        clock.advance(301.0)
        expired = self.redeem(gate, token, "op-11")
        self.assertEqual(expired["reason"], "confirmation_expired")
        fresh = self.initial(gate, "op-11")["confirmation"]
        allowed = self.redeem(gate, fresh, "op-11")
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(len(gate.journal_entries()), 1)


class TamperedReceiptTests(IdempotencyCase):
    def commit(self, gate, key):
        token = self.initial(gate, key)["confirmation"]
        allowed = self.redeem(gate, token, key)
        self.assertEqual(allowed["status"], "allowed")
        return allowed["receipt"]

    def tamper_receipt(self, key, **changes):
        raw = sqlite3.connect(self.path())
        try:
            blob = raw.execute(
                "SELECT receipt_json FROM operations "
                "WHERE op_key = ?",
                (key,),
            ).fetchone()[0]
            receipt = json.loads(blob)
            receipt.update(changes)
            tampered = json.dumps(receipt)
            raw.execute(
                "UPDATE operations SET receipt_json = ? "
                "WHERE op_key = ?",
                (tampered, key),
            )
            raw.commit()
        finally:
            raw.close()
        return tampered

    def test_query_tampered_receipt_fails_closed(self):
        gate, _ = self.make_gate()
        self.commit(gate, "op-t1")
        self.tamper_receipt("op-t1", amount=999)
        ledger_before = gate.ledger_snapshot()
        journal_before = len(gate.journal_entries())
        audit_before = len(gate.audit_records())
        failed = gate.operation_status("op-t1")
        self.assertEqual(failed["status"], "error")
        self.assertEqual(
            failed["reason"], "operation_unverifiable"
        )
        self.assertEqual(gate.ledger_snapshot(), ledger_before)
        self.assertEqual(len(gate.journal_entries()), journal_before)
        self.assertEqual(len(gate.audit_records()), audit_before)
        self.assertFalse(gate.status()["degraded"])

    def test_duplicate_tampered_receipt_fails_closed(self):
        gate, _ = self.make_gate()
        genuine = self.commit(gate, "op-t2")
        tampered = self.tamper_receipt(
            "op-t2", source_balance=1, target_balance=2
        )
        ledger_before = gate.ledger_snapshot()
        journal_before = len(gate.journal_entries())
        audit_before = len(gate.audit_records())
        failed = self.initial(gate, "op-t2")
        self.assertEqual(failed["status"], "error")
        self.assertEqual(
            failed["reason"], "operation_unverifiable"
        )
        self.assertNotIn("receipt", failed)
        self.assertTrue(gate.status()["degraded"])
        self.assertEqual(
            gate.status()["incident"]["case"],
            "operation_unverifiable",
        )
        # No execution, no repair, no new evidence.
        self.assertEqual(gate.ledger_snapshot(), ledger_before)
        self.assertEqual(len(gate.journal_entries()), journal_before)
        self.assertEqual(len(gate.audit_records()), audit_before)
        raw = sqlite3.connect(self.path())
        try:
            blob = raw.execute(
                "SELECT receipt_json FROM operations "
                "WHERE op_key = 'op-t2'"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(blob, tampered)
        self.assertNotEqual(json.loads(blob)["source_balance"],
                             genuine["source_balance"])

    def test_query_ambiguous_outcome_fails_closed(self):
        gate, _ = self.make_gate()
        self.commit(gate, "op-t4")
        raw = sqlite3.connect(self.path())
        try:
            # A second matching OUTCOME row (chain-breaking, so
            # startup could never see it — runtime must still
            # refuse the ambiguity rather than pick a match).
            raw.execute(
                "INSERT INTO audit(kind, seq, ts, actor, action, "
                "arg_hash, policy_version, decision, reason, "
                "token_id, extra_json, prev_hash, record_hash) "
                "SELECT kind, (SELECT MAX(seq) + 1 FROM audit), "
                "ts, actor, action, arg_hash, policy_version, "
                "decision, reason, token_id, extra_json, "
                "'forged', 'forged' "
                "FROM audit WHERE kind = 'outcome' "
                "AND decision = 'allowed' LIMIT 1"
            )
            raw.commit()
        finally:
            raw.close()
        failed = gate.operation_status("op-t4")
        self.assertEqual(failed["status"], "error")
        self.assertEqual(
            failed["reason"], "operation_unverifiable"
        )


class QueryTests(IdempotencyCase):
    def test_query_lifecycle(self):
        gate, _ = self.make_gate()
        self.assertEqual(
            gate.operation_status("op-12")["status"], "not_found"
        )
        token = self.initial(gate, "op-12")["confirmation"]
        self.assertEqual(
            gate.operation_status("op-12")["status"], "pending"
        )
        allowed = self.redeem(gate, token, "op-12")
        status = gate.operation_status("op-12")
        self.assertEqual(status["status"], "committed")
        self.assertEqual(status["receipt"], allowed["receipt"])

    def test_query_never_mutates(self):
        gate, backend = self.make_gate()
        token = self.initial(gate, "op-13")["confirmation"]
        before = len(gate.audit_records())
        self.redeem(gate, token, "op-13")
        mid = len(gate.audit_records())
        gate2, _ = self.reopen(backend)
        records_before = len(gate2.audit_records())
        gate2.operation_status("op-13")
        gate2.operation_status("missing-key")
        gate2.operation_status("op-13", "transfer_money", args())
        self.assertEqual(len(gate2.audit_records()), records_before)
        # Sanity on the fixture arithmetic, not on the query: the
        # initial call appended one decision record (before), the
        # redeem appended exactly authorized + outcome.
        self.assertEqual(mid, before + 2)

    def test_query_validates_key_and_fingerprint(self):
        gate, _ = self.make_gate()
        for bad in ("", "has space", "x" * 129, None, 42, b"op"):
            with self.assertRaises(ValueError):
                gate.operation_status(bad)
        with self.assertRaises(ValueError):
            gate.operation_status("op-14", "get_balance", args())
        with self.assertRaises(ValueError):
            gate.operation_status("op-14", "transfer_money")
        with self.assertRaises(ValueError):
            gate.operation_status(
                "op-14", "transfer_money", {"bogus": 1}
            )

    def test_query_corrupt_receipt_fails_closed(self):
        gate, _ = self.make_gate()
        token = self.initial(gate, "op-15")["confirmation"]
        self.redeem(gate, token, "op-15")
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "UPDATE operations SET receipt_json = 'not-json' "
                "WHERE op_key = 'op-15'"
            )
            raw.commit()
        finally:
            raw.close()
        ledger_before = gate.ledger_snapshot()
        journal_before = len(gate.journal_entries())
        audit_before = len(gate.audit_records())
        failed = gate.operation_status("op-15")
        self.assertEqual(failed["status"], "error")
        self.assertEqual(
            failed["reason"], "operation_unverifiable"
        )
        self.assertNotEqual(failed["status"], "not_found")
        # The failed query mutated nothing observable.
        self.assertEqual(gate.ledger_snapshot(), ledger_before)
        self.assertEqual(len(gate.journal_entries()), journal_before)
        self.assertEqual(len(gate.audit_records()), audit_before)
        raw = sqlite3.connect(self.path())
        try:
            blob = raw.execute(
                "SELECT receipt_json FROM operations "
                "WHERE op_key = 'op-15'"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(blob, "not-json")

    def test_query_closed_backend_errors(self):
        gate, backend = self.make_gate()
        self.initial(gate, "op-16")
        backend.close()
        failed = gate.operation_status("op-16")
        self.assertEqual(failed["status"], "error")
        self.assertEqual(failed["reason"], "storage_unavailable")


class KeyValidationTests(IdempotencyCase):
    def test_malformed_keys_rejected(self):
        gate, _ = self.make_gate()
        for bad in ("", "has space", "semi;colon", "x" * 129):
            response = gate.gate({
                "action": "transfer_money", "args": args(),
                "idempotency_key": bad,
            })
            self.assertEqual(response["status"], "denied")
            self.assertEqual(
                response["reason"], "invalid_arguments"
            )
        for bad in (None.__class__, 42, b"op-17", ["op-17"]):
            response = gate.gate({
                "action": "transfer_money", "args": args(),
                "idempotency_key": bad,
            })
            self.assertEqual(response["status"], "denied")

    def test_key_on_read_rejected(self):
        gate, _ = self.make_gate()
        response = gate.gate({
            "action": "get_balance", "args": {"account": "alice"},
            "idempotency_key": "op-18",
        })
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "invalid_arguments")

    def test_keyless_requests_unchanged(self):
        gate, _ = self.make_gate()
        initial = gate.gate({
            "action": "transfer_money", "args": args(),
        })
        self.assertEqual(initial["status"], "confirmation_required")
        self.assertNotIn("duplicate", initial)
        allowed = gate.gate({
            "action": "transfer_money", "args": args(),
            "confirmation": initial["confirmation"],
        })
        self.assertEqual(allowed["status"], "allowed")
        self.assertNotIn("duplicate", allowed)
        self.assertNotIn("idempotency_key", allowed.get("receipt", {}))


class ResetTests(IdempotencyCase):
    def test_reset_preserves_operations(self):
        gate, backend = self.make_gate()
        token = self.initial(gate, "op-19")["confirmation"]
        allowed = self.redeem(gate, token, "op-19")
        self.assertEqual(allowed["status"], "allowed")

        def fail_updated(kind):
            if kind == "policy_updated":
                raise AuditError("audit_unavailable")

        backend.audit.fault_hook = fail_updated
        result = gate.update_policy(make_policy(version="v2"))
        self.assertEqual(result["reason"], "audit_unavailable")
        self.assertTrue(gate.status()["degraded"])
        backend.audit.fault_hook = None
        cleared = gate.operator_reset()
        self.assertEqual(cleared["status"], "reset")
        # Tokens are wiped but the committed outcome survives.
        gone = self.redeem(gate, token, "op-19")
        self.assertEqual(gone["reason"], "invalid_confirmation")
        status = gate.operation_status("op-19")
        self.assertEqual(status["status"], "committed")
        self.assertEqual(status["receipt"], allowed["receipt"])
        again = self.initial(gate, "op-19")
        self.assertEqual(again["status"], "allowed")
        self.assertTrue(again["duplicate"])


class RollbackTests(IdempotencyCase):
    def test_statement_failure_rolls_back_keyed(self):
        gate, backend = self.make_gate()
        token = self.initial(gate, "op-20")["confirmation"]
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "CREATE TRIGGER t_abort_journal BEFORE INSERT "
                "ON journal "
                "BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
            raw.commit()
        finally:
            raw.close()
        response = self.redeem(gate, token, "op-20")
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        raw = sqlite3.connect(self.path())
        try:
            raw.execute("DROP TRIGGER t_abort_journal")
            raw.commit()
        finally:
            raw.close()
        gate2, _ = self.reopen(backend)
        self.assertEqual(
            gate2.operation_status("op-20")["status"], "pending"
        )
        fresh = self.initial(gate2, "op-20")["confirmation"]
        allowed = self.redeem(gate2, fresh, "op-20")
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(len(gate2.journal_entries()), 1)
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

    def test_operation_writes_roll_back_atomically(self):
        _, backend = self.make_gate()
        with self.assertRaises(RuntimeError):
            with backend.transaction():
                backend.register_operation(
                    "op-21", "transfer_money", "h", "agent"
                )
                raise RuntimeError("injected")
        self.assertIsNone(backend.get_operation("op-21"))
        with backend.transaction():
            backend.register_operation(
                "op-22", "transfer_money", "h", "agent"
            )
        with self.assertRaises(RuntimeError):
            with backend.transaction():
                backend.complete_operation("op-22", {"ok": True})
                raise RuntimeError("injected")
        record = backend.get_operation("op-22")
        self.assertEqual(record["status"], "pending")
        self.assertIsNone(record["receipt"])


class ConcurrencyTests(IdempotencyCase):
    def test_same_key_serialized(self):
        gate = self.make_memory_gate()
        count = 8
        barrier = threading.Barrier(count)
        results = [None] * count

        def worker(index):
            barrier.wait()
            initial = self.initial(gate, "op-23")
            if initial["status"] == "confirmation_required":
                token = initial["confirmation"]
                results[index] = self.redeem(gate, token, "op-23")
            else:
                # Lost the race after commit: already the outcome.
                results[index] = initial

        threads = [
            threading.Thread(target=worker, args=(index,))
            for index in range(count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for response in results:
            self.assertEqual(response["status"], "allowed")
        receipts = [response["receipt"] for response in results]
        for receipt in receipts:
            self.assertEqual(receipt, receipts[0])
        self.assertEqual(len(gate.journal_entries()), 1)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )


class KeyingIntegrationTests(IdempotencyCase):
    """Slice B Phase 2: markers, receipt identity and position."""

    def keyed_transfer(self, gate, key):
        token = self.initial(gate, key)["confirmation"]
        allowed = self.redeem(gate, token, key)
        self.assertEqual(allowed["status"], "allowed")
        return allowed

    def allowed_outcomes(self, gate):
        return [
            r for r in gate.audit_records()
            if r["kind"] == "outcome" and r["decision"] == "allowed"
        ]

    def tamper_cases(self):
        return [
            ("wrong_seq", lambda r: r.update(audit_seq=999)),
            ("wrong_key", lambda r: r.update(op_key="intruder")),
            ("missing_seq", lambda r: r.pop("audit_seq")),
            ("missing_key", lambda r: r.pop("op_key")),
        ]

    def tamper_stored_receipt(self, name, key, mutate):
        conn = sqlite3.connect(self.path(name))
        try:
            row = conn.execute(
                "SELECT receipt_json FROM operations WHERE op_key = ?",
                (key,),
            ).fetchone()
            receipt = json.loads(row[0])
            mutate(receipt)
            conn.execute(
                "UPDATE operations SET receipt_json = ? "
                "WHERE op_key = ?",
                (json.dumps(receipt), key),
            )
            conn.commit()
        finally:
            conn.close()

    def craft_legacy_committed(self, gate, key):
        token = self.initial(gate)["confirmation"]
        self.redeem(gate, token)
        outcome = self.allowed_outcomes(gate)[-1]
        receipt = {
            "action": "transfer_money", "source": "alice",
            "target": "bob", "amount": 100,
            "journal_seq": outcome["extra"]["journal_seq"],
            "source_balance": outcome["extra"]["source_balance"],
            "target_balance": outcome["extra"]["target_balance"],
            "policy_version": outcome["policy_version"],
        }
        storage = gate._storage
        with storage.transaction():
            storage.register_operation(
                key, "transfer_money", outcome["arg_hash"], "agent"
            )
            storage.complete_operation(key, receipt)
        return receipt

    def craft_legacy_committed_sqlite(self, backend, key):
        """Build a genuinely legacy committed operation (SQLite).

        All evidence is pre-Slice-B shape: the OUTCOME extra holds
        only journal/ledger fields (no keyed marker) and the receipt
        holds neither op_key nor audit_seq. Backend API only.
        """
        digest = arg_hash(args())
        with backend.transaction():
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
            backend.audit.append(
                kind="outcome", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1", decision="allowed",
                reason="ok", token_id="deadbeef",
                extra={
                    "journal_seq": entry.seq,
                    "source_balance": backend.ledger.balance("alice"),
                    "target_balance": backend.ledger.balance("bob"),
                },
            )
            receipt = {
                "action": "transfer_money", "source": "alice",
                "target": "bob", "amount": 100,
                "journal_seq": entry.seq,
                "source_balance": backend.ledger.balance("alice"),
                "target_balance": backend.ledger.balance("bob"),
                "policy_version": "v1",
            }
            backend.register_operation(
                key, "transfer_money", digest, "agent"
            )
            backend.complete_operation(key, receipt)
            backend.confirmations.issue(
                "transfer_money", digest, "v1"
            )
        return receipt

    def corrupt_append_seq(self, gate):
        original = gate._audit.append

        def bad_seq_append(*args, **kwargs):
            record = original(*args, **kwargs)
            return dict(record, seq="bad")

        gate._audit.append = bad_seq_append
        return original

    def test_keyed_marker_and_receipt_memory(self):
        gate = self.make_memory_gate()
        allowed = self.keyed_transfer(gate, "km-1")
        (outcome,) = self.allowed_outcomes(gate)
        self.assertTrue(outcome["extra"]["keyed"])
        self.assertEqual(outcome["extra"]["op_key"], "km-1")
        receipt = allowed["receipt"]
        self.assertEqual(receipt["op_key"], "km-1")
        self.assertEqual(receipt["audit_seq"], outcome["seq"])
        stored = gate.operation_status("km-1")
        self.assertEqual(stored["status"], "committed")
        self.assertEqual(stored["receipt"], receipt)

    def test_keyless_marker_memory(self):
        gate = self.make_memory_gate()
        token = self.initial(gate)["confirmation"]
        allowed = self.redeem(gate, token)
        (outcome,) = self.allowed_outcomes(gate)
        self.assertFalse(outcome["extra"]["keyed"])
        self.assertNotIn("op_key", outcome["extra"])
        self.assertEqual(
            set(allowed["receipt"]),
            {"action", "source", "target", "amount", "journal_seq",
             "source_balance", "target_balance", "policy_version"},
        )

    def test_keyed_marker_and_receipt_sqlite(self):
        gate, backend = self.make_gate()
        allowed = self.keyed_transfer(gate, "ks-1")
        (outcome,) = self.allowed_outcomes(gate)
        self.assertTrue(outcome["extra"]["keyed"])
        self.assertEqual(outcome["extra"]["op_key"], "ks-1")
        self.assertEqual(allowed["receipt"]["op_key"], "ks-1")
        self.assertEqual(allowed["receipt"]["audit_seq"], outcome["seq"])
        gate2, _ = self.reopen(backend)
        stored = gate2.operation_status("ks-1")
        self.assertEqual(stored["status"], "committed")
        self.assertEqual(stored["receipt"], allowed["receipt"])

    def test_keyless_marker_sqlite(self):
        gate, _ = self.make_gate()
        token = self.initial(gate)["confirmation"]
        allowed = self.redeem(gate, token)
        (outcome,) = self.allowed_outcomes(gate)
        self.assertFalse(outcome["extra"]["keyed"])
        self.assertNotIn("op_key", outcome["extra"])
        self.assertNotIn("op_key", allowed["receipt"])
        self.assertNotIn("audit_seq", allowed["receipt"])

    def test_duplicate_preserves_stored_pair(self):
        gates = [
            self.make_memory_gate(),
            self.make_gate(name="kd.db")[0],
        ]
        for index, gate in enumerate(gates):
            with self.subTest(backend=index):
                key = "kd-%d" % index
                allowed = self.keyed_transfer(gate, key)
                again = self.initial(gate, key)
                self.assertTrue(again["duplicate"])
                self.assertEqual(again["receipt"], allowed["receipt"])
                self.assertEqual(
                    again["receipt"]["op_key"], key
                )
                self.assertEqual(
                    again["receipt"]["audit_seq"],
                    allowed["receipt"]["audit_seq"],
                )
                self.assertEqual(len(gate.journal_entries()), 1)

    def test_legacy_receipt_compatible_memory(self):
        gate = self.make_memory_gate()
        legacy = self.craft_legacy_committed(gate, "kl-m")
        stored = gate.operation_status("kl-m")
        self.assertEqual(stored["status"], "committed")
        self.assertEqual(stored["receipt"], legacy)
        again = self.initial(gate, "kl-m")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["receipt"], legacy)

    def test_legacy_receipt_compatible_sqlite(self):
        _, backend = self.make_gate()
        legacy = self.craft_legacy_committed_sqlite(backend, "kl-s")
        gate2, _ = self.reopen(backend)
        outcomes = [
            record for record in gate2.audit_records()
            if record["kind"] == "outcome"
            and record["decision"] == "allowed"
        ]
        (outcome,) = outcomes
        self.assertNotIn("keyed", outcome["extra"])
        stored = gate2.operation_status("kl-s")
        self.assertEqual(stored["status"], "committed")
        self.assertEqual(stored["receipt"], legacy)
        self.assertNotIn("op_key", stored["receipt"])
        self.assertNotIn("audit_seq", stored["receipt"])

    def test_tampered_pair_memory(self):
        for name, mutate in self.tamper_cases():
            with self.subTest(case=name):
                gate = self.make_memory_gate()
                self.keyed_transfer(gate, "kt-m")
                mutate(gate._storage._operations["kt-m"]["receipt"])
                status = gate.operation_status("kt-m")
                self.assertEqual(status["status"], "error")
                self.assertEqual(
                    status["reason"], "operation_unverifiable"
                )
                self.assertFalse(gate.status()["degraded"])
                again = self.initial(gate, "kt-m")
                self.assertEqual(again["status"], "error")
                self.assertEqual(
                    again["reason"], "operation_unverifiable"
                )
                self.assertTrue(gate.status()["degraded"])
                self.assertEqual(len(gate.journal_entries()), 1)
                refused = self.initial(gate)
                self.assertEqual(refused["reason"], "degraded")

    def test_tampered_pair_sqlite(self):
        for index, (name, mutate) in enumerate(self.tamper_cases()):
            with self.subTest(case=name):
                db = "kt-s-%d.db" % index
                gate, _ = self.make_gate(name=db)
                self.keyed_transfer(gate, "kt-s")
                # Mid-session tamper through a second connection;
                # the backend stays open, so this exercises runtime
                # detection (startup verification never runs here).
                self.tamper_stored_receipt(db, "kt-s", mutate)
                status = gate.operation_status("kt-s")
                self.assertEqual(status["status"], "error")
                self.assertEqual(
                    status["reason"], "operation_unverifiable"
                )
                self.assertFalse(gate.status()["degraded"])
                again = self.initial(gate, "kt-s")
                self.assertEqual(again["status"], "error")
                self.assertEqual(
                    again["reason"], "operation_unverifiable"
                )
                self.assertTrue(gate.status()["degraded"])
                self.assertEqual(len(gate.journal_entries()), 1)
                refused = self.initial(gate)
                self.assertEqual(refused["reason"], "degraded")

    def test_malformed_seq_memory(self):
        gate = self.make_memory_gate()
        token = self.initial(gate, "kq-m")["confirmation"]
        original = self.corrupt_append_seq(gate)
        try:
            response = self.redeem(gate, token, "kq-m")
        finally:
            gate._audit.append = original
        self.assertEqual(
            response["status"], "executed_recording_failed"
        )
        self.assertEqual(response["reason"], "outcome_unrecorded")
        self.assertTrue(gate.status()["degraded"])
        pending = gate.operation_status("kq-m")
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(len(gate.journal_entries()), 1)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

    def test_malformed_seq_sqlite(self):
        gate, _ = self.make_gate()
        token = self.initial(gate, "kq-s")["confirmation"]
        original = self.corrupt_append_seq(gate)
        try:
            response = self.redeem(gate, token, "kq-s")
        finally:
            gate._audit.append = original
        self.assertEqual(
            response["status"], "executed_recording_failed"
        )
        self.assertEqual(response["reason"], "outcome_unrecorded")
        self.assertTrue(gate.status()["degraded"])
        pending = gate.operation_status("kq-s")
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(len(gate.journal_entries()), 1)


if __name__ == "__main__":
    unittest.main()
