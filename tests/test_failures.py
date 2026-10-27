"""Fault-injection tests for failure semantics and degraded-mode recovery (Gate C).

Private access below is limited to documented test-only fault hooks and
evidence capture; production paths never use these hooks.
"""
import dataclasses
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.audit import AuditError
from proofgate.canonical import canonicalize
from proofgate.enforcement import Gate
from proofgate.policy import Policy


class FakeClock:
    def __init__(self):
        self.now_value = 20000.0

    def __call__(self):
        return self.now_value

    def advance(self, seconds):
        self.now_value += seconds


def make_gate(clock=None):
    clock = clock if clock is not None else FakeClock()
    gate = Gate(
        policy=Policy.create(
            version="v1", per_transfer_cap=500, daily_cap=1000,
            allowed_targets=("bob", "carol"),
        ),
        balances={"alice": 10000},
        clock=clock,
    )
    return gate, clock


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


def full_transfer(testcase, gate, **kwargs):
    token = do_initial(testcase, gate, **kwargs)
    return gate.gate({
        "action": "transfer_money",
        "args": args(
            amount=kwargs.get("amount", 100),
            target=kwargs.get("target", "bob"),
        ),
        "confirmation": token,
    })


def kinds(gate):
    return [r["kind"] for r in gate.audit_records()]


class CaseAFailureTests(unittest.TestCase):
    def test_authorized_append_fails(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "audit_unavailable")
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate.journal_entries()), 0)
        self.assertNotIn("authorized", kinds(gate))
        status = gate.status()
        self.assertTrue(status["degraded"])
        self.assertEqual(
            status["incident"]["case"], "audit_unavailable"
        )
        # Checked but never consumed: no mutation path was entered.
        self.assertFalse(gate._confirmations._entries[token].used)
        # Recovery: disarm, reset, fresh flow; the old token is dead
        # because reset clears the store.
        gate._audit.fault_hook = None
        reset = gate.operator_reset()
        self.assertEqual(reset["status"], "reset")
        self.assertGreaterEqual(reset["cleared_tokens"], 1)
        gone = do_redeem(gate, token)
        self.assertEqual(gone["reason"], "invalid_confirmation")
        fresh = full_transfer(self, gate)
        self.assertEqual(fresh["status"], "allowed")

    def test_reset_refused_while_fault_armed(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        do_redeem(gate, token)
        reset = gate.operator_reset()
        self.assertEqual(reset["status"], "error")
        self.assertEqual(reset["reason"], "audit_unavailable")
        self.assertTrue(gate.status()["degraded"])
        gate._audit.fault_hook = None
        self.assertEqual(
            gate.operator_reset()["status"], "reset"
        )

    def test_initial_decision_fault(self):
        gate, _ = make_gate()

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        response = gate.gate(
            {"action": "transfer_money", "args": args()}
        )
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "audit_unavailable")
        self.assertEqual(len(gate.audit_records()), 1)  # genesis only
        gate._audit.fault_hook = None
        reset = gate.operator_reset()
        self.assertEqual(reset["status"], "reset")
        self.assertEqual(full_transfer(self, gate)["status"], "allowed")


class CaseBDivergenceTests(unittest.TestCase):
    def test_ledger_fails_after_journal(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)

        def boom():
            raise RuntimeError("simulated ledger fault")

        gate._ledger.fault_hook = boom
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "execution_failed")
        self.assertNotEqual(response["status"], "denied")
        # Token consumed: the store shows it used, and any replay is
        # rejected (blocked by degraded mode at the gate layer).
        self.assertTrue(gate._confirmations._entries[token].used)
        replay = do_redeem(gate, token)
        self.assertEqual(replay["status"], "error")
        # AUTHORIZED record and journal entry preserved.
        authorized = [
            r for r in gate.audit_records() if r["kind"] == "authorized"
        ]
        self.assertEqual(len(authorized), 1)
        (entry,) = gate.journal_entries()
        self.assertEqual(
            (entry.seq, entry.source, entry.target, entry.amount),
            (1, "alice", "bob", 100),
        )
        # Best-effort OUTCOME error record present.
        outcomes = [
            r for r in gate.audit_records() if r["kind"] == "outcome"
        ]
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["decision"], "error")
        self.assertEqual(outcomes[0]["extra"]["journal_seq"], 1)
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})
        status = gate.status()
        self.assertTrue(status["degraded"])
        self.assertEqual(
            status["incident"]["case"], "journal_ledger_divergence"
        )
        self.assertEqual(status["incident"]["journal_seq"], 1)
        # Byte-for-byte preservation across subsequent blocked ops.
        before = (
            canonicalize(authorized[0])
            + canonicalize(dataclasses.asdict(entry))
        )
        blocked = gate.gate(
            {"action": "transfer_money", "args": args()}
        )
        self.assertEqual(blocked["status"], "error")
        self.assertEqual(blocked["reason"], "degraded")
        refused = gate.operator_reset()
        self.assertEqual(refused["status"], "error")
        self.assertEqual(refused["reason"], "reset_refused")
        authorized2 = [
            r for r in gate.audit_records() if r["kind"] == "authorized"
        ]
        (entry2,) = gate.journal_entries()
        self.assertEqual(
            canonicalize(authorized2[0])
            + canonicalize(dataclasses.asdict(entry2)),
            before,
        )
        # A healthy audit writer does not imply a healthy system, but
        # read-only service continues and is recorded.
        read = gate.gate(
            {"action": "get_balance", "args": {"account": "alice"}}
        )
        self.assertEqual(read["status"], "allowed")
        self.assertEqual(read["balance"], 10000)
        # Reconciliation identifies the dangling entry exactly.
        health = gate.check_health()
        recon = health["reconcile"]
        self.assertFalse(recon["clean"])
        self.assertEqual(recon["journal_ahead"], 1)
        self.assertEqual(
            recon["mismatches"]["bob"],
            {"expected": 100, "actual": 0},
        )
        self.assertEqual(
            recon["incident"], "journal_ledger_divergence"
        )
        # Reconstruction: old token dead, fresh instance serves.
        gate._ledger.fault_hook = None
        with tempfile.TemporaryDirectory() as tmp:
            export = gate.export_audit(os.path.join(tmp, "a.jsonl"))
            fresh = Gate(
                policy=Policy.create(
                    version="v1", per_transfer_cap=500,
                    daily_cap=1000, allowed_targets=("bob",),
                ),
                balances=gate.ledger_snapshot(),
                prior_export_hash=export["sha256"],
            )
            stale = fresh.gate({
                "action": "transfer_money", "args": args(),
                "confirmation": token,
            })
            self.assertEqual(stale["reason"], "invalid_confirmation")
            token2 = do_initial(self, fresh)
            self.assertEqual(
                do_redeem(fresh, token2)["status"], "allowed"
            )

    def test_outcome_best_effort_may_fail(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)

        def boom():
            raise RuntimeError("simulated ledger fault")

        def fail_outcome(kind):
            # Selective: AUTHORIZED must succeed so the flow reaches the
            # best-effort OUTCOME attempt; a blanket fault would fail
            # earlier with audit_unavailable (Case A, tested elsewhere).
            if kind == "outcome":
                raise AuditError("audit_unavailable")

        gate._ledger.fault_hook = boom
        gate._audit.fault_hook = fail_outcome
        response = do_redeem(gate, token)
        self.assertEqual(response["reason"], "execution_failed")
        incident = gate.status()["incident"]
        self.assertEqual(
            incident["case"], "journal_ledger_divergence"
        )
        self.assertIn("outcome_note", incident)
        self.assertNotIn("outcome", kinds(gate))


class CaseCUnrecordedOutcomeTests(unittest.TestCase):
    def test_outcome_append_fails_after_mutation(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)

        def fail_outcome(kind):
            if kind == "outcome":
                raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail_outcome
        response = do_redeem(gate, token)
        self.assertEqual(response["status"], "executed_recording_failed")
        self.assertNotEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "outcome_unrecorded")
        self.assertEqual(
            (response["journal_seq"], response["source"],
             response["target"], response["amount"]),
            (1, "alice", "bob", 100),
        )
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        self.assertIn("authorized", kinds(gate))
        self.assertNotIn("outcome", kinds(gate))
        status = gate.status()
        self.assertTrue(status["degraded"])
        self.assertEqual(
            status["incident"]["case"], "outcome_unrecorded"
        )
        # Reset refused: the cross-check flags the missing OUTCOME.
        refused = gate.operator_reset()
        self.assertEqual(refused["reason"], "reset_refused")
        self.assertEqual(refused["detail"]["gaps"], [1])
        blocked = gate.gate(
            {"action": "transfer_money", "args": args()}
        )
        self.assertEqual(blocked["reason"], "degraded")
        # Reconstruction from the reconciled snapshot serves again.
        gate._audit.fault_hook = None
        with tempfile.TemporaryDirectory() as tmp:
            export = gate.export_audit(os.path.join(tmp, "a.jsonl"))
            fresh = Gate(
                policy=Policy.create(
                    version="v1", per_transfer_cap=500,
                    daily_cap=1000, allowed_targets=("bob",),
                ),
                balances=gate.ledger_snapshot(),
                prior_export_hash=export["sha256"],
            )
            stale = fresh.gate({
                "action": "transfer_money", "args": args(),
                "confirmation": token,
            })
            self.assertEqual(stale["reason"], "invalid_confirmation")
            token2 = do_initial(self, fresh)
            self.assertEqual(
                do_redeem(fresh, token2)["status"], "allowed"
            )


class CaseDCorruptionTests(unittest.TestCase):
    def test_last_record_tamper_fails_closed(self):
        gate, _ = make_gate()
        self.assertEqual(full_transfer(self, gate)["status"], "allowed")
        # Simulated tampering via private access (prevention out of
        # scope; immediate detection of last-link damage is tested).
        gate._audit._records[-1]["reason"] = "forged"
        tampered = [canonicalize(r) for r in gate.audit_records()]
        response = gate.gate(
            {"action": "transfer_money", "args": args()}
        )
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "audit_unavailable")
        self.assertTrue(gate.status()["degraded"])
        after = [canonicalize(r) for r in gate.audit_records()]
        self.assertEqual(after, tampered)
        ok, detail = gate._audit.verify()
        self.assertFalse(ok)
        self.assertEqual(detail["problem"], "bad_hash")

    def test_middle_tamper_detected_at_health_check(self):
        gate, _ = make_gate()
        self.assertEqual(full_transfer(self, gate)["status"], "allowed")
        gate._audit._records[1]["reason"] = "forged"
        # Detection granularity: middle tampering is latent to the
        # per-append last-link check and caught by verification.
        report = gate.check_health()
        self.assertFalse(report["audit"]["ok"])
        self.assertTrue(report["degraded"])
        self.assertTrue(gate.status()["degraded"])
        refused = gate.operator_reset()
        self.assertEqual(refused["reason"], "reset_refused")


class DegradedReadTests(unittest.TestCase):
    def test_read_served_with_healthy_writer(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)

        def boom():
            raise RuntimeError("simulated ledger fault")

        gate._ledger.fault_hook = boom
        do_redeem(gate, token)
        gate._ledger.fault_hook = None
        before = len(gate.audit_records())
        read = gate.gate(
            {"action": "get_balance", "args": {"account": "alice"}}
        )
        self.assertEqual(read["status"], "allowed")
        self.assertEqual(read["balance"], 10000)
        self.assertEqual(len(gate.audit_records()), before + 1)

    def test_read_blocked_with_broken_writer(self):
        gate, _ = make_gate()
        do_initial(self, gate)

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        read = gate.gate(
            {"action": "get_balance", "args": {"account": "alice"}}
        )
        self.assertEqual(read["status"], "error")
        self.assertEqual(read["reason"], "audit_unavailable")


class OperatorRuleTests(unittest.TestCase):
    def test_reset_when_healthy_refused(self):
        gate, _ = make_gate()
        reset = gate.operator_reset()
        self.assertEqual(reset["status"], "error")
        self.assertEqual(reset["reason"], "not_degraded")

    def test_update_while_degraded_blocked(self):
        gate, _ = make_gate()
        do_initial(self, gate)

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        gate.gate({"action": "transfer_money", "args": args()})
        result = gate.update_policy(Policy.create(
            version="v2", per_transfer_cap=500, daily_cap=1000,
            allowed_targets=("bob",),
        ))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "degraded")
        self.assertEqual(gate.status()["policy_version"], "v1")

    def test_update_audit_failure_retains_policy(self):
        gate, _ = make_gate()

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        result = gate.update_policy(Policy.create(
            version="v2", per_transfer_cap=500, daily_cap=1000,
            allowed_targets=("carol",),
        ))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "audit_unavailable")
        self.assertEqual(gate.status()["policy_version"], "v1")
        self.assertTrue(gate.status()["degraded"])
        gate._audit.fault_hook = None
        self.assertEqual(
            gate.operator_reset()["status"], "reset"
        )
        # Old policy provably still enforced after recovery.
        token = do_initial(self, gate, target="bob")
        allowed = gate.gate({
            "action": "transfer_money",
            "args": args(target="bob"), "confirmation": token,
        })
        self.assertEqual(allowed["status"], "allowed")
        authorized = [
            r for r in gate.audit_records() if r["kind"] == "authorized"
        ]
        self.assertEqual(authorized[-1]["policy_version"], "v1")


class ExportIsolationTests(unittest.TestCase):
    def test_export_failure_leaves_gate_healthy(self):
        gate, _ = make_gate()
        with self.assertRaises(OSError):
            gate.export_audit(
                os.path.join("no-such-dir-xyz", "a.jsonl")
            )
        self.assertFalse(gate.status()["degraded"])
        self.assertEqual(full_transfer(self, gate)["status"], "allowed")


class DefensiveBranchTests(unittest.TestCase):
    """Fail-closed behavior of defensive audit-failure branches (Gate D)."""

    def test_deny_with_broken_writer(self):
        gate, _ = make_gate()

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        # A malformed request takes the _deny path; its DECISION record
        # cannot be written, so the gate fails closed into degraded mode
        # instead of returning an unrecorded denial.
        response = gate.gate(
            {"action": "transfer_money",
             "args": {"source": "alice", "target": "bob"}}
        )
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["reason"], "audit_unavailable")
        self.assertTrue(gate.status()["degraded"])
        self.assertEqual(
            gate.status()["incident"]["case"], "audit_unavailable"
        )
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate.audit_records()), 1)  # genesis only
        # Nothing executed, so recovery is a clean reset after disarm.
        gate._audit.fault_hook = None
        self.assertEqual(gate.operator_reset()["status"], "reset")
        self.assertEqual(full_transfer(self, gate)["status"], "allowed")

    def test_rejected_update_with_broken_writer(self):
        gate, _ = make_gate()
        bad = Policy(
            version="vX", per_transfer_cap=-5, daily_cap=100,
            allowed_targets=("bob",),
        )

        def fail(kind):
            raise AuditError("audit_unavailable")

        gate._audit.fault_hook = fail
        result = gate.update_policy(bad)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "audit_unavailable")
        self.assertEqual(gate.status()["policy_version"], "v1")
        self.assertTrue(gate.status()["degraded"])
        gate._audit.fault_hook = None
        self.assertEqual(gate.operator_reset()["status"], "reset")
        # Old policy provably still enforced after recovery.
        token = do_initial(self, gate)
        self.assertEqual(do_redeem(gate, token)["status"], "allowed")

    def test_health_check_with_unwritable_note(self):
        gate, _ = make_gate()
        # Corrupt the only (genesis/last) record: the O(1) last-link
        # check then fails every append, including the verification
        # record the health check attempts to write.
        gate._audit._records[0]["reason"] = "forged"
        report = gate.check_health()
        self.assertFalse(report["audit"]["ok"])
        self.assertEqual(
            report["audit"]["detail"]["problem"], "bad_hash"
        )
        self.assertEqual(report["verification_record"], "unwritable")
        self.assertTrue(report["newly_degraded"])
        self.assertTrue(report["degraded"])
        self.assertTrue(gate.status()["degraded"])
        self.assertEqual(
            gate.status()["incident"]["case"], "verification_mismatch"
        )
        refused = gate.operator_reset()
        self.assertEqual(refused["reason"], "reset_refused")


if __name__ == "__main__":
    unittest.main()
