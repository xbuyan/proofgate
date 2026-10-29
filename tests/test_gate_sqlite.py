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

    def test_update_policy_rejects_oversized_cap(self):
        gate, _ = self.make_gate()
        # Bypass Policy.create validation to reach the gate's own
        # re-validation, as a hostile or buggy caller could.
        oversized = Policy(
            version="v2", per_transfer_cap=2**70, daily_cap=1000,
            allowed_targets=("bob", "carol"),
        )
        result = gate.update_policy(oversized)
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["reason"], "invalid_policy")
        self.assertEqual(gate.status()["policy_version"], "v1")
        self.assertFalse(gate.status()["degraded"])
        # Gate remains usable: a normal transfer still works.
        token = do_initial(self, gate)
        self.assertEqual(do_redeem(gate, token)["status"], "allowed")

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
        # Atomicity: no purge happened, so the old token row
        # survives unused; S4 makes it stale (issued pre-restart),
        # so the reopened gate rejects it without mutating state.
        self.assertEqual(gate2.status()["policy_version"], "v1")
        self.assertEqual(gate2.status()["daily_spent"], 0)
        self.assertEqual(
            gate2.status()["pending_confirmations"], 1
        )
        stale = do_redeem(gate2, token)
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate2.journal_entries()), 0)
        raw = sqlite3.connect(self.path())
        try:
            row = raw.execute(
                "SELECT used, epoch FROM confirmations "
                "WHERE token = ?",
                (token,),
            ).fetchone()
        finally:
            raw.close()
        self.assertEqual(tuple(row), (0, 0))


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
        # S4: the pre-restart token is stale now. Consumption
        # rollback is proven by its unused row; retry proceeds with
        # a fresh token issued in the new epoch.
        self.drop_trigger("g.db")
        stale = do_redeem(gate2, token)
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")
        raw = sqlite3.connect(self.path())
        try:
            used = raw.execute(
                "SELECT used FROM confirmations WHERE token = ?",
                (token,),
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(used, 0)
        retry = do_redeem(gate2, do_initial(self, gate2))
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


class EpochBindingTests(GateSQLiteCase):
    """S4: a confirmation dies with the boot epoch that issued it."""

    def _set_epoch(self, token, epoch):
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "UPDATE confirmations SET epoch = ? WHERE token = ?",
                (epoch, token),
            )
            raw.commit()
        finally:
            raw.close()

    def test_restart_invalidates_pending_confirmation(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        gate2, _ = self.reopen(backend)
        stale = do_redeem(gate2, token)
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")
        self.assertEqual(gate2.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate2.journal_entries()), 0)
        self.assertEqual(gate2.status()["daily_spent"], 0)

    def test_fresh_confirmation_redeems_after_restart(self):
        gate, backend = self.make_gate()
        do_initial(self, gate)
        gate2, _ = self.reopen(backend)
        fresh = do_initial(self, gate2)
        response = do_redeem(gate2, fresh)
        self.assertEqual(response["status"], "allowed")
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

    def test_same_epoch_redeem_and_replay(self):
        gate, _ = self.make_gate()
        token = do_initial(self, gate)
        self.assertEqual(do_redeem(gate, token)["status"], "allowed")
        replay = do_redeem(gate, token)
        self.assertEqual(replay["status"], "denied")
        self.assertEqual(replay["reason"], "confirmation_reused")

    def test_future_epoch_rejected(self):
        gate, _ = self.make_gate()
        token = do_initial(self, gate)
        self._set_epoch(token, 999)
        stale = do_redeem(gate, token)
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})

    def test_backdated_epoch_rejected(self):
        gate, backend = self.make_gate()
        gate2, _ = self.reopen(backend)
        token = do_initial(self, gate2)
        self._set_epoch(token, 0)
        stale = do_redeem(gate2, token)
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")

    def test_negative_epoch_rejected_fail_closed(self):
        gate, _ = self.make_gate()
        token = do_initial(self, gate)
        self._set_epoch(token, -1)
        stale = do_redeem(gate, token)
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")

    def test_null_epoch_refused_by_schema(self):
        gate, _ = self.make_gate()
        token = do_initial(self, gate)
        raw = sqlite3.connect(self.path())
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                raw.execute(
                    "UPDATE confirmations SET epoch = NULL "
                    "WHERE token = ?",
                    (token,),
                )
        finally:
            raw.close()

    def test_failed_open_preserves_epoch_and_token(self):
        gate, backend = self.make_gate()
        token = do_initial(self, gate)
        backend.close()
        self.abort_on(
            "g.db", "counters", "UPDATE",
            "WHEN NEW.name = 'boot_epoch'",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            SQLiteBackend.open(self.path())
        raw = sqlite3.connect(self.path())
        try:
            epoch = raw.execute(
                "SELECT value FROM counters WHERE name = 'boot_epoch'"
            ).fetchone()[0]
        finally:
            raw.close()
        self.assertEqual(epoch, 0)
        self.drop_trigger("g.db")
        gate2, _ = self.reopen(backend)
        stale = do_redeem(gate2, token)
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")
        fresh = do_initial(self, gate2)
        self.assertEqual(do_redeem(gate2, fresh)["status"], "allowed")


class BackupDurabilityTests(GateSQLiteCase):
    """B1: a backup taken while open captures committed transfers."""

    def _keyed_transfer(self, testcase, gate, key):
        initial = gate.gate({
            "action": "transfer_money",
            "args": args(),
            "idempotency_key": key,
        })
        testcase.assertEqual(initial["status"], "confirmation_required")
        redeemed = gate.gate({
            "action": "transfer_money",
            "args": args(),
            "confirmation": initial["confirmation"],
            "idempotency_key": key,
        })
        testcase.assertEqual(redeemed["status"], "allowed")
        return redeemed

    def test_backup_captures_committed_keyed_transfer(self):
        gate, backend = self.make_gate()
        receipt = self._keyed_transfer(
            self, gate, "backup-1"
        )["receipt"]
        backend.backup(self.path("copy.db"))
        copy_backend = SQLiteBackend.open(self.path("copy.db"))
        self._backends.append(copy_backend)
        copy_gate = Gate(
            policy=copy_backend.get_policy(), storage=copy_backend
        )
        # Independent verification through the normal startup path
        # already ran inside open(); the copy carries the transfer.
        self.assertEqual(
            copy_gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        status = copy_gate.operation_status("backup-1")
        self.assertEqual(status["status"], "committed")
        self.assertEqual(status["receipt"], receipt)
        self.assertEqual(
            copy_gate.journal_entries(), gate.journal_entries()
        )
        # Opening the copy is one boot of the copy: exactly one boot
        # record beyond the snapshotted chain, while the source chain
        # is untouched by both the backup and the copy's open.
        self.assertEqual(
            len(copy_gate.audit_records()),
            len(gate.audit_records()) + 1,
        )
        self.assertEqual(copy_gate.audit_records()[-1]["kind"], "boot")

    def test_backup_source_stays_usable_and_unchanged(self):
        gate, backend = self.make_gate()
        self._keyed_transfer(self, gate, "backup-1")
        before = (
            gate.ledger_snapshot(), gate.journal_entries(),
            len(gate.audit_records()),
        )
        backend.backup(self.path("copy.db"))
        self.assertEqual(
            (
                gate.ledger_snapshot(), gate.journal_entries(),
                len(gate.audit_records()),
            ),
            before,
        )
        # The source keeps serving after the backup.
        receipt = self._keyed_transfer(
            self, gate, "backup-2"
        )["receipt"]
        self.assertEqual(receipt["journal_seq"], 2)
        self.assertEqual(
            gate.operation_status("backup-1")["status"], "committed"
        )

    def test_backup_is_a_snapshot_not_a_link(self):
        gate, backend = self.make_gate()
        self._keyed_transfer(self, gate, "backup-1")
        backend.backup(self.path("copy.db"))
        self._keyed_transfer(self, gate, "backup-2")
        copy_backend = SQLiteBackend.open(self.path("copy.db"))
        self._backends.append(copy_backend)
        copy_gate = Gate(
            policy=copy_backend.get_policy(), storage=copy_backend
        )
        self.assertEqual(
            copy_gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        self.assertEqual(
            copy_gate.operation_status("backup-2")["status"],
            "not_found",
        )


class RecoveryJourneyTests(GateSQLiteCase):
    """B2-E4: fault -> degraded -> query -> reset -> retry, exactly once.

    A keyed transfer fails mid-redemption on a real SQLite backend,
    rolls back, and degrades the gate. The caller resolves the truth
    via ``operation_status`` while degraded, recovers with
    ``operator_reset``, and resumes with the same key: the transfer
    executes exactly once and the stored receipt answers retries.
    """

    def keyed_initial(self, testcase, gate, key, **kwargs):
        params = {"amount": 100, "target": "bob"}
        params.update(kwargs)
        response = gate.gate({
            "action": "transfer_money", "args": args(**params),
            "idempotency_key": key,
        })
        testcase.assertEqual(
            response["status"], "confirmation_required"
        )
        return response["confirmation"]

    def test_storage_fault_recovery_executes_once(self):
        gate, _ = self.make_gate()
        key = "rec-1"
        token1 = self.keyed_initial(self, gate, key)

        # Deterministic statement fault late in redemption: the
        # journal INSERT aborts, so the whole transaction — consume,
        # AUTHORIZED record, counters — must roll back.
        self.abort_on("g.db", "journal", "INSERT")
        failed = gate.gate({
            "action": "transfer_money", "args": args(),
            "confirmation": token1, "idempotency_key": key,
        })
        # Error, not success and not a definite denial. (True
        # outcome_uncertain needs commit/rollback failure, which no
        # real backend can produce deterministically; that path stays
        # stub-tested. This journey covers the realizable fault.)
        self.assertEqual(failed["status"], "error")
        self.assertEqual(failed["reason"], "storage_unavailable")
        status = gate.status()
        self.assertTrue(status["degraded"])
        self.assertEqual(
            status["incident"]["case"], "storage_unavailable"
        )
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate.journal_entries()), 0)
        self.assertEqual(gate.status()["daily_spent"], 0)

        # Truthful status while degraded; the query mutates nothing.
        audit_before = len(gate.audit_records())
        journal_before = len(gate.journal_entries())
        pending = gate.operation_status(key)
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(len(gate.audit_records()), audit_before)
        self.assertEqual(len(gate.journal_entries()), journal_before)

        # Recover: remove the fault, then reset. Reset requires clean
        # reconciliation (true: everything rolled back) and clears
        # all confirmation tokens, so a fresh token is required next.
        self.drop_trigger("g.db")
        reset = gate.operator_reset()
        self.assertEqual(reset["status"], "reset")
        self.assertFalse(gate.status()["degraded"])

        # Resume the same logical operation: pending record found, new
        # token issued, single execution with a committed receipt.
        token2 = self.keyed_initial(self, gate, key)
        self.assertNotEqual(token2, token1)
        redeemed = gate.gate({
            "action": "transfer_money", "args": args(),
            "confirmation": token2, "idempotency_key": key,
        })
        self.assertEqual(redeemed["status"], "allowed")
        self.assertEqual(redeemed["receipt"]["journal_seq"], 1)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        self.assertEqual(len(gate.journal_entries()), 1)
        committed = gate.operation_status(key)
        self.assertEqual(committed["status"], "committed")
        self.assertEqual(committed["receipt"], redeemed["receipt"])

        # Retry answers from the stored receipt: no second mutation.
        retry = gate.gate({
            "action": "transfer_money", "args": args(),
            "idempotency_key": key,
        })
        self.assertEqual(retry["status"], "allowed")
        self.assertTrue(retry["duplicate"])
        self.assertEqual(retry["receipt"], redeemed["receipt"])
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        self.assertEqual(len(gate.journal_entries()), 1)

        # Evidence audit: the failed attempt left no partial records
        # behind (no authorized/outcome from attempt one); the trailing
        # decision is the duplicate-return marker for the retry.
        self.assertEqual(
            kinds(gate),
            ["genesis", "decision", "degraded_cleared", "decision",
             "authorized", "outcome", "decision"],
        )


if __name__ == "__main__":
    unittest.main()
