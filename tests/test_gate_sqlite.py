"""Gate + SQLite integration tests (A2.3).

Durable transfers and policy updates through ``Gate(storage=...)``,
close/reopen persistence, and the storage-error boundary. Storage
faults are injected with real SQLite triggers (no mocks, no timing);
commit-uncertainty marking is unit-tested against the real
transaction exit path with a stub connection.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.audit import AuditError
from proofgate.enforcement import Gate, _with_storage_boundary
from proofgate.policy import Policy
from proofgate.sqlite_backend import (
    SQLiteBackend,
    SQLiteBackendError,
    _CommitUncertainError,
    _Transaction,
)


def make_policy(version="v1", targets=("bob", "carol")):
    return Policy.create(
        version=version, per_transfer_cap=500, daily_cap=1000,
        allowed_targets=targets,
    )


def args(amount=100, target="bob"):
    return {"source": "alice", "target": target, "amount": amount}


def do_initial(testcase, gate, **kwargs):
    params = {"amount": 100, "target": "bob"}
    params.update(kwargs)
    response = gate.gate(
        {"action": "transfer_money", "args": args(**params)}
    )
    testcase.assertEqual(response["status"], "confirmation_required")
    return response["confirmation"]


def do_redeem(gate, token, **kwargs):
    params = {"amount": 100, "target": "bob"}
    params.update(kwargs)
    return gate.gate({
        "action": "transfer_money", "args": args(**params),
        "confirmation": token,
    })


def kinds(gate):
    return [r["kind"] for r in gate.audit_records()]


class GateSQLiteCase(unittest.TestCase):
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

    def abort_on(self, name, table, operation, when=""):
        trigger = (
            "CREATE TRIGGER t_injected BEFORE %s ON %s %s "
            "BEGIN SELECT RAISE(ABORT, 'injected storage fault'); END"
            % (operation, table, when)
        )
        raw = sqlite3.connect(self.path(name))
        try:
            raw.execute(trigger)
            raw.commit()
        finally:
            raw.close()

    def drop_trigger(self, name):
        raw = sqlite3.connect(self.path(name))
        try:
            raw.execute("DROP TRIGGER t_injected")
            raw.commit()
        finally:
            raw.close()


class DurableTransferTests(GateSQLiteCase):
    def test_transfer_success_persists_after_reopen(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "allowed")
        self.assertEqual(response["receipt"]["journal_seq"], 1)
        gate2, _ = self.reopen(backend)
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        self.assertEqual(len(gate2.journal_entries()), 1)
        self.assertEqual(
            kinds(gate2),
            ["genesis", "decision", "authorized", "outcome", "boot"],
        )
        status = gate2.status()
        self.assertEqual(status["daily_spent"], 100)
        self.assertEqual(status["policy_version"], "v1")
        self.assertFalse(status["degraded"])
        health = gate2.check_health()
        self.assertTrue(health["reconcile"]["clean"])
        self.assertTrue(health["cross_check"]["clean"])
        self.assertTrue(health["audit"]["ok"])

    def test_denial_persists_without_mutation(self):
        gate, backend = self.make_gate()
        denied = gate.gate(
            {"action": "transfer_money", "args": args(amount=600)}
        )
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(denied["reason"], "policy_limit_exceeded")
        gate2, _ = self.reopen(backend)
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate2.journal_entries()), 0)
        self.assertEqual(
            kinds(gate2), ["genesis", "decision", "boot"]
        )
        self.assertEqual(gate2.status()["daily_spent"], 0)

    def test_replay_rejected_after_reopen(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        self.assertEqual(do_redeem(gate, token)["status"], "allowed")
        gate2, _ = self.reopen(backend)
        replay = gate2.gate({
            "action": "transfer_money", "args": args(),
            "confirmation": token,
        })
        self.assertEqual(replay["status"], "denied")
        self.assertEqual(replay["reason"], "confirmation_reused")
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )


class DurablePolicyTests(GateSQLiteCase):
    def test_policy_update_persists_after_reopen(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        result = gate.update_policy(
            make_policy(version="v2", targets=("carol",))
        )
        self.assertEqual(result["status"], "policy_updated")
        self.assertEqual(result["purged"], 1)
        gate2, _ = self.reopen(backend)
        self.assertEqual(gate2.status()["policy_version"], "v2")
        self.assertEqual(gate2.status()["daily_spent"], 0)
        reuse = gate2.update_policy(make_policy(version="v1"))
        self.assertEqual(reuse["reason"], "version_reused")
        gone = gate2.gate({
            "action": "transfer_money", "args": args(),
            "confirmation": token,
        })
        self.assertEqual(gone["reason"], "invalid_confirmation")
        token2 = do_initial(self, gate2, target="carol")
        allowed = gate2.gate({
            "action": "transfer_money", "args": args(target="carol"),
            "confirmation": token2,
        })
        self.assertEqual(allowed["status"], "allowed")

    def test_failed_policy_update_consistent_after_reopen(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)

        def fail_updated(kind):
            if kind == "policy_updated":
                raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail_updated
        result = gate.update_policy(
            make_policy(version="v2", targets=("carol",))
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "audit_unavailable")
        self.assertEqual(gate.status()["policy_version"], "v1")
        self.assertTrue(gate.status()["degraded"])
        gate2, _ = self.reopen(backend)
        # Atomicity: no purge happened, so the old token survives and
        # redeems under v1 on the reopened (non-degraded) gate.
        self.assertEqual(gate2.status()["policy_version"], "v1")
        self.assertEqual(gate2.status()["daily_spent"], 0)
        redeemed = do_redeem(gate2, token)
        self.assertEqual(redeemed["status"], "allowed")
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )


class ConstructionTests(GateSQLiteCase):
    def test_mismatched_construction_policy_rejected(self):
        gate, backend = self.make_gate()
        with self.assertRaises(ValueError):
            Gate(policy=make_policy(version="v2"), storage=backend)
        self.assertEqual(gate.status()["policy_version"], "v1")


class StorageFailureTests(GateSQLiteCase):
    def test_authorized_audit_failure_rolls_back(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        self.abort_on(
            "g.db", "audit", "INSERT",
            "WHEN NEW.kind = 'authorized'",
        )
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        status = gate.status()
        self.assertTrue(status["degraded"])
        self.assertEqual(
            status["incident"]["case"], "storage_unavailable"
        )
        gate2, _ = self.reopen(backend)
        self.assertEqual(
            kinds(gate2), ["genesis", "decision", "boot"]
        )
        self.assertEqual(len(gate2.journal_entries()), 0)
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})

    def test_consume_failure_rolls_back_and_token_survives(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        self.abort_on("g.db", "confirmations", "UPDATE")
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        gate2, _ = self.reopen(backend)
        self.assertEqual(
            kinds(gate2), ["genesis", "decision", "boot"]
        )
        # Retry after removing the fault succeeds with the SAME token:
        # consumption was rolled back, so no retry hazard exists.
        self.drop_trigger("g.db")
        retry = do_redeem(gate2, token)
        self.assertEqual(retry["status"], "allowed")

    def test_journal_failure_rolls_back(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        self.abort_on("g.db", "journal", "INSERT")
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        gate2, _ = self.reopen(backend)
        self.assertEqual(
            kinds(gate2), ["genesis", "decision", "boot"]
        )
        self.assertEqual(len(gate2.journal_entries()), 0)
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(gate2.status()["daily_spent"], 0)

    def test_ledger_failure_is_storage_fault_not_divergence(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        # The SQLite mutator persists via INSERT OR REPLACE.
        self.abort_on("g.db", "ledger", "INSERT")
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        self.assertNotEqual(response["reason"], "execution_failed")
        incident = gate.status()["incident"]
        self.assertEqual(incident["case"], "storage_unavailable")
        gate2, _ = self.reopen(backend)
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate2.journal_entries()), 0)
        self.assertEqual(
            kinds(gate2), ["genesis", "decision", "boot"]
        )
        health = gate2.check_health()
        self.assertTrue(health["reconcile"]["clean"])

    def test_daily_counter_failure_rolls_back(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        self.abort_on(
            "g.db", "counters", "UPDATE",
            "WHEN NEW.name = 'daily_spent'",
        )
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        gate2, _ = self.reopen(backend)
        self.assertEqual(gate2.status()["daily_spent"], 0)
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate2.journal_entries()), 0)
        self.assertEqual(
            kinds(gate2), ["genesis", "decision", "boot"]
        )

    def test_outcome_audit_failure_rolls_back(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        self.abort_on(
            "g.db", "audit", "INSERT", "WHEN NEW.kind = 'outcome'"
        )
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        # Unlike the fault-hook Case C (mutation kept), a storage
        # failure rolls the mutation back: nothing executed.
        self.assertEqual(response["reason"], "storage_unavailable")
        self.assertNotEqual(response["reason"], "executed_recording_failed")
        gate2, _ = self.reopen(backend)
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate2.journal_entries()), 0)
        self.assertEqual(
            kinds(gate2), ["genesis", "decision", "boot"]
        )

    def test_issue_failure_rolls_back(self):
        gate, backend = self.make_gate()
        self.abort_on("g.db", "confirmations", "INSERT")
        response = gate.gate(
            {"action": "transfer_money", "args": args()}
        )
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        gate2, _ = self.reopen(backend)
        self.assertEqual(
            gate2.status()["pending_confirmations"], 0
        )
        self.assertEqual(kinds(gate2), ["genesis", "boot"])

    def test_deny_record_failure_rolls_back(self):
        gate, backend = self.make_gate()
        self.abort_on(
            "g.db", "audit", "INSERT", "WHEN NEW.kind = 'decision'"
        )
        response = gate.gate(
            {"action": "transfer_money", "args": args(amount=600)}
        )
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "storage_unavailable")
        self.assertNotEqual(response["reason"], "policy_limit_exceeded")
        gate2, _ = self.reopen(backend)
        self.assertEqual(kinds(gate2), ["genesis", "boot"])
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})


class BoundaryClassificationTests(GateSQLiteCase):
    def test_storage_error_maps_to_structured_result(self):
        @_with_storage_boundary
        def boom(self):
            raise sqlite3.OperationalError("injected")

        gate, _ = self.make_gate()
        response = boom(gate)
        self.assertEqual(
            response, {"status": "error", "reason": "storage_unavailable"}
        )
        status = gate.status()
        self.assertTrue(status["degraded"])
        self.assertEqual(
            status["incident"]["case"], "storage_unavailable"
        )

    def test_uncertain_commit_maps_to_outcome_uncertain(self):
        @_with_storage_boundary
        def uncertain(self):
            raise _CommitUncertainError(
                "commit failed (x); outcome uncertain"
            )

        gate, _ = self.make_gate()
        response = uncertain(gate)
        self.assertEqual(
            response, {"status": "error", "reason": "outcome_uncertain"}
        )
        self.assertNotEqual(response["reason"], "denied")
        status = gate.status()
        self.assertTrue(status["degraded"])
        self.assertEqual(status["incident"]["case"], "outcome_uncertain")

    def test_programmer_errors_propagate(self):
        @_with_storage_boundary
        def runtime(self):
            raise RuntimeError("fault-hook behavior")

        @_with_storage_boundary
        def misuse(self):
            raise SQLiteBackendError("writes require backend.transaction()")

        @_with_storage_boundary
        def type_bug(self):
            raise TypeError("bug")

        @_with_storage_boundary
        def interrupted(self):
            raise KeyboardInterrupt()

        gate, _ = self.make_gate()
        with self.assertRaises(RuntimeError):
            runtime(gate)
        with self.assertRaises(SQLiteBackendError):
            misuse(gate)
        with self.assertRaises(TypeError):
            type_bug(gate)
        with self.assertRaises(KeyboardInterrupt):
            interrupted(gate)
        self.assertFalse(gate.status()["degraded"])


class CommitUncertaintyTests(GateSQLiteCase):
    def test_commit_failure_marked_uncertain(self):
        calls = {"commit": 0, "rollback": 0}

        class ExplodingConn:
            def commit(self):
                calls["commit"] += 1
                raise sqlite3.OperationalError(
                    "injected commit failure"
                )

            def rollback(self):
                calls["rollback"] += 1

        backend = SimpleNamespace(
            _conn=ExplodingConn(), _in_transaction=True
        )
        tx = _Transaction(backend)
        with self.assertRaises(_CommitUncertainError):
            tx.__exit__(None, None, None)
        # Exactly one commit attempt: no automatic retry.
        self.assertEqual(calls, {"commit": 1, "rollback": 1})
        self.assertFalse(backend._in_transaction)

    def test_rollback_failure_marked_uncertain(self):
        class BrokenConn:
            def rollback(self):
                raise sqlite3.OperationalError("injected rollback failure")

        backend = SimpleNamespace(
            _conn=BrokenConn(), _in_transaction=True
        )
        tx = _Transaction(backend)
        with self.assertRaises(_CommitUncertainError):
            tx.__exit__(RuntimeError, RuntimeError("body"), None)
        self.assertFalse(backend._in_transaction)

    def test_interrupt_during_commit_propagates(self):
        class InterruptedConn:
            def commit(self):
                raise KeyboardInterrupt()

            def rollback(self):
                raise AssertionError("must not roll back on interrupt")

        backend = SimpleNamespace(
            _conn=InterruptedConn(), _in_transaction=True
        )
        tx = _Transaction(backend)
        with self.assertRaises(KeyboardInterrupt):
            tx.__exit__(None, None, None)
        self.assertFalse(backend._in_transaction)


if __name__ == "__main__":
    unittest.main()
