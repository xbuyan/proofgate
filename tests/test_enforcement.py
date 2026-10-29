"""Tests for the enforcement state machine: allow/deny/confirm/error paths (Gate C)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.canonical import arg_hash
from proofgate.confirmations import ConfirmationStore
from proofgate.enforcement import Gate, create_gate
from proofgate.journal import Journal
from proofgate.ledger import LedgerError, SyntheticLedger
# Private capability import: direct unit tests of the mutation path that
# only the gate may use. Supported callers cannot obtain one (see bypass).
from proofgate.ledger import _Mutator
from proofgate.policy import Policy


class FakeClock:
    def __init__(self):
        self.now_value = 10000.0

    def __call__(self):
        return self.now_value

    def advance(self, seconds):
        self.now_value += seconds


def make_gate(balances=None, policy=None, clock=None):
    clock = clock if clock is not None else FakeClock()
    if policy is None:
        policy = Policy.create(
            version="v1",
            per_transfer_cap=500,
            daily_cap=1000,
            allowed_targets=("bob", "carol"),
        )
    gate = Gate(
        policy=policy,
        balances={"alice": 10000} if balances is None else balances,
        clock=clock,
    )
    return gate, clock


def transfer_req(source="alice", target="bob", amount=100,
                 confirmation=None):
    args = {"source": source, "target": target, "amount": amount}
    request = {"action": "transfer_money", "args": args}
    if confirmation is not None:
        request["confirmation"] = confirmation
    return request


def balance_req(account="alice"):
    return {"action": "get_balance", "args": {"account": account}}


def do_initial(testcase, gate, **kwargs):
    response = gate.gate(transfer_req(**kwargs))
    testcase.assertEqual(response["status"], "confirmation_required")
    testcase.assertEqual(
        set(response), {"status", "reason", "confirmation"}
    )
    token = response["confirmation"]
    testcase.assertIsInstance(token, str)
    testcase.assertGreater(len(token), 20)
    return token


class UnknownToolTests(unittest.TestCase):
    def test_unknown_tool_denied(self):
        gate, _ = make_gate()
        response = gate.gate({"action": "wire_money", "args": {}})
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "unknown_tool")
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 10000}
        )
        kinds = [r["kind"] for r in gate.audit_records()]
        self.assertEqual(kinds, ["genesis", "decision"])


class MalformedRequestTests(unittest.TestCase):
    CASES = [
        ("not-a-dict", "invalid_arguments"),
        ({}, "unknown_tool"),
        ({"action": 123, "args": {}}, "unknown_tool"),
        ({"action": "transfer_money"}, "invalid_arguments"),
        ({"action": "transfer_money", "args": {}, "extra": 1},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "bob"}},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "bob", "amount": True}},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "bob", "amount": "100"}},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "bob", "amount": 0}},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "bob", "amount": -5}},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "alice", "amount": 10}},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "", "amount": 10}},
         "invalid_arguments"),
        ({"action": "transfer_money",
          "args": {"source": "alice", "target": "bob", "amount": 10,
                   "memo": "x"}},
         "invalid_arguments"),
        ({"action": "transfer_money", "args": [], }, "invalid_arguments"),
        ({"action": "transfer_money", "actor": 7,
          "args": {"source": "alice", "target": "bob", "amount": 10}},
         "invalid_arguments"),
        ({"action": "transfer_money", "confirmation": 123,
          "args": {"source": "alice", "target": "bob", "amount": 10}},
         "invalid_arguments"),
        ({"action": "transfer_money", "confirmation": "",
          "args": {"source": "alice", "target": "bob", "amount": 10}},
         "invalid_arguments"),
        ({"action": "get_balance", "confirmation": "x",
          "args": {"account": "alice"}}, "invalid_arguments"),
        ({"action": "get_balance", "args": {}}, "invalid_arguments"),
        ({"action": "get_balance", "args": {"account": ""}},
         "invalid_arguments"),
        ({"action": "get_balance",
          "args": {"account": "alice", "extra": 1}},
         "invalid_arguments"),
    ]

    def test_malformed_battery(self):
        gate, _ = make_gate()
        for request, reason in self.CASES:
            with self.subTest(request=request):
                response = gate.gate(request)
                self.assertEqual(response["status"], "denied")
                self.assertEqual(response["reason"], reason)
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(len(gate.journal_entries()), 0)
        self.assertEqual(
            len(gate.audit_records()), 1 + len(self.CASES)
        )


class TokenFlowTests(unittest.TestCase):
    def test_forged_confirmation_denied(self):
        gate, _ = make_gate()
        do_initial(self, gate)
        response = gate.gate(transfer_req(confirmation="forged-token"))
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "invalid_confirmation")
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})

    def test_replay_denied(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)
        first = gate.gate(transfer_req(confirmation=token))
        self.assertEqual(first["status"], "allowed")
        second = gate.gate(transfer_req(confirmation=token))
        self.assertEqual(second["status"], "denied")
        self.assertEqual(second["reason"], "confirmation_reused")
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

    def test_expired_denied(self):
        gate, clock = make_gate()
        token = do_initial(self, gate)
        clock.advance(301)
        response = gate.gate(transfer_req(confirmation=token))
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "confirmation_expired")

    def test_expiry_boundary_exact_denied(self):
        gate, clock = make_gate()
        token = do_initial(self, gate)
        clock.advance(300)
        response = gate.gate(transfer_req(confirmation=token))
        self.assertEqual(response["reason"], "confirmation_expired")

    def test_argument_mismatch_denied(self):
        gate, _ = make_gate()
        token = do_initial(self, gate, amount=100)
        response = gate.gate(
            transfer_req(amount=101, confirmation=token)
        )
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "confirmation_mismatch")
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})

    def test_target_mismatch_denied(self):
        gate, _ = make_gate()
        token = do_initial(self, gate, target="bob")
        response = gate.gate(
            transfer_req(target="carol", confirmation=token)
        )
        self.assertEqual(response["reason"], "confirmation_mismatch")

    def test_mismatch_does_not_consume(self):
        gate, _ = make_gate()
        token = do_initial(self, gate, amount=100)
        bad = gate.gate(transfer_req(amount=101, confirmation=token))
        self.assertEqual(bad["status"], "denied")
        good = gate.gate(transfer_req(amount=100, confirmation=token))
        self.assertEqual(good["status"], "allowed")

    def test_policy_deny_does_not_consume(self):
        gate, _ = make_gate(balances={"alice": 150})
        first = do_initial(self, gate, amount=100)
        second = do_initial(self, gate, amount=100)
        self.assertEqual(
            gate.gate(transfer_req(amount=100, confirmation=second))[
                "status"], "allowed",
        )
        denied = gate.gate(
            transfer_req(amount=100, confirmation=first)
        )
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(denied["reason"], "insufficient_funds")
        # Private peek: the rejected token was checked, never consumed.
        self.assertFalse(gate._confirmations._entries[first].used)


class ReadTests(unittest.TestCase):
    def test_balance_ok(self):
        gate, _ = make_gate()
        response = gate.gate(balance_req("alice"))
        self.assertEqual(response["status"], "allowed")
        self.assertEqual(response["reason"], "ok")
        self.assertEqual(response["balance"], 10000)
        self.assertEqual(
            set(response), {"status", "reason", "account", "balance"}
        )
        self.assertEqual(len(gate.journal_entries()), 0)
        kinds = [r["kind"] for r in gate.audit_records()]
        self.assertEqual(kinds, ["genesis", "decision"])

    def test_unknown_account_reads_zero(self):
        gate, _ = make_gate()
        response = gate.gate(balance_req("ghost"))
        self.assertEqual(response["status"], "allowed")
        self.assertEqual(response["balance"], 0)


class TransferFlowTests(unittest.TestCase):
    def test_valid_transfer_full_flow(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)
        response = gate.gate(transfer_req(confirmation=token))
        self.assertEqual(response["status"], "allowed")
        self.assertEqual(
            set(response), {"status", "reason", "receipt"}
        )
        receipt = response["receipt"]
        self.assertEqual(
            receipt,
            {
                "action": "transfer_money",
                "source": "alice",
                "target": "bob",
                "amount": 100,
                "journal_seq": 1,
                "source_balance": 9900,
                "target_balance": 100,
                "policy_version": "v1",
            },
        )
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        self.assertEqual(len(gate.journal_entries()), 1)
        self.assertEqual(gate.status()["daily_spent"], 100)
        kinds = [r["kind"] for r in gate.audit_records()]
        self.assertEqual(
            kinds, ["genesis", "decision", "authorized", "outcome"]
        )
        health = gate.check_health()
        self.assertTrue(health["audit"]["ok"])
        self.assertTrue(health["reconcile"]["clean"])

    def test_over_limit_denied_without_token(self):
        gate, _ = make_gate()
        response = gate.gate(transfer_req(amount=501))
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["reason"], "policy_limit_exceeded")
        self.assertNotIn("confirmation", response)

    def test_insufficient_funds_denied(self):
        gate, _ = make_gate(balances={"alice": 50})
        response = gate.gate(transfer_req(amount=100))
        self.assertEqual(response["reason"], "insufficient_funds")

    def test_unknown_source_denied(self):
        gate, _ = make_gate()
        response = gate.gate(transfer_req(source="ghost"))
        self.assertEqual(response["reason"], "insufficient_funds")

    def test_exact_cap_boundary_allowed(self):
        gate, _ = make_gate()
        token = do_initial(self, gate, amount=500)
        response = gate.gate(
            transfer_req(amount=500, confirmation=token)
        )
        self.assertEqual(response["status"], "allowed")

    def test_unseeded_allowed_target_created(self):
        gate, _ = make_gate()
        token = do_initial(self, gate, target="carol")
        response = gate.gate(
            transfer_req(target="carol", confirmation=token)
        )
        self.assertEqual(response["status"], "allowed")
        self.assertEqual(gate.ledger_snapshot()["carol"], 100)

    def test_two_independent_tokens(self):
        gate, _ = make_gate()
        first = do_initial(self, gate, amount=100)
        second = do_initial(self, gate, amount=200)
        self.assertNotEqual(first, second)
        self.assertEqual(
            gate.gate(transfer_req(amount=100, confirmation=first))[
                "status"], "allowed",
        )
        self.assertEqual(
            gate.gate(transfer_req(amount=200, confirmation=second))[
                "status"], "allowed",
        )
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9700, "bob": 300}
        )

    def test_daily_cap_accumulates(self):
        gate, _ = make_gate()
        for _ in range(2):
            token = do_initial(self, gate, amount=500)
            response = gate.gate(
                transfer_req(amount=500, confirmation=token)
            )
            self.assertEqual(response["status"], "allowed")
        denied = gate.gate(transfer_req(amount=100))
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(denied["reason"], "daily_limit_exceeded")


class PolicyUpdateTests(unittest.TestCase):
    def test_update_success(self):
        gate, _ = make_gate()
        token = do_initial(self, gate, amount=100)
        spent = do_initial(self, gate, amount=50)
        gate.gate(transfer_req(amount=50, confirmation=spent))
        self.assertEqual(gate.status()["daily_spent"], 50)
        result = gate.update_policy(
            Policy.create(
                version="v2", per_transfer_cap=500,
                daily_cap=1000, allowed_targets=("carol",),
            )
        )
        self.assertEqual(result["status"], "policy_updated")
        self.assertEqual(result["old_version"], "v1")
        self.assertEqual(result["new_version"], "v2")
        self.assertEqual(result["purged"], 2)
        self.assertEqual(gate.status()["daily_spent"], 0)
        self.assertEqual(gate.status()["policy_version"], "v2")
        # Purged token is gone; re-request under the new policy works.
        gone = gate.gate(transfer_req(amount=100, confirmation=token))
        self.assertEqual(gone["reason"], "invalid_confirmation")
        fresh = do_initial(self, gate, target="carol")
        allowed = gate.gate(
            transfer_req(target="carol", confirmation=fresh)
        )
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(
            allowed["receipt"]["policy_version"], "v2"
        )
        updates = [
            r for r in gate.audit_records()
            if r["kind"] == "policy_updated"
        ]
        self.assertEqual(len(updates), 1)
        self.assertEqual(
            updates[0]["extra"],
            {"old_version": "v1", "new_version": "v2", "purged": 2},
        )

    def test_update_invalid_rejected(self):
        gate, _ = make_gate()
        bad = Policy(
            version="vX", per_transfer_cap=-5, daily_cap=100,
            allowed_targets=("bob",),
        )
        result = gate.update_policy(bad)
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["reason"], "invalid_policy")
        self.assertEqual(gate.status()["policy_version"], "v1")
        rejected = [
            r for r in gate.audit_records()
            if r["kind"] == "policy_update_rejected"
        ]
        self.assertEqual(len(rejected), 1)
        token = do_initial(self, gate)
        self.assertEqual(
            gate.gate(transfer_req(confirmation=token))["status"],
            "allowed",
        )

    def test_update_version_reuse_rejected(self):
        gate, _ = make_gate()
        gate.update_policy(
            Policy.create(
                version="v2", per_transfer_cap=500,
                daily_cap=1000, allowed_targets=("bob",),
            )
        )
        rollback = gate.update_policy(
            Policy.create(
                version="v1", per_transfer_cap=500,
                daily_cap=1000, allowed_targets=("bob",),
            )
        )
        self.assertEqual(rollback["reason"], "version_reused")
        same = gate.update_policy(
            Policy.create(
                version="v2", per_transfer_cap=500,
                daily_cap=1000, allowed_targets=("bob",),
            )
        )
        self.assertEqual(same["reason"], "version_unchanged")
        self.assertEqual(gate.status()["policy_version"], "v2")

    def test_update_non_policy_raises(self):
        gate, _ = make_gate()
        with self.assertRaises(TypeError):
            gate.update_policy({"version": "v2"})


class LedgerJournalUnitTests(unittest.TestCase):
    def test_snapshot_isolated(self):
        ledger = SyntheticLedger({"alice": 100})
        snapshot = ledger.snapshot()
        snapshot["alice"] = 0
        self.assertEqual(ledger.balance("alice"), 100)

    def test_unknown_balance_zero(self):
        ledger = SyntheticLedger({})
        self.assertEqual(ledger.balance("ghost"), 0)

    def test_mutator_applies(self):
        ledger = SyntheticLedger({"alice": 100})
        mutator = _Mutator(ledger)
        self.assertEqual(
            mutator.apply_transfer("alice", "bob", 40), (60, 40)
        )
        self.assertEqual(
            ledger.snapshot(), {"alice": 60, "bob": 40}
        )

    def test_mutator_insufficient_raises_unchanged(self):
        ledger = SyntheticLedger({"alice": 10})
        with self.assertRaises(LedgerError):
            _Mutator(ledger).apply_transfer("alice", "bob", 50)
        self.assertEqual(ledger.snapshot(), {"alice": 10})

    def test_bad_seed_rejected(self):
        with self.assertRaises(LedgerError):
            SyntheticLedger({"alice": -1})
        with self.assertRaises(LedgerError):
            SyntheticLedger({"alice": True})

    def test_seed_enforces_sqlite_integer_range(self):
        ledger = SyntheticLedger({"alice": 2**63 - 1})
        self.assertEqual(ledger.balance("alice"), 2**63 - 1)
        with self.assertRaises(LedgerError):
            SyntheticLedger({"alice": 2**63})

    def test_journal_sequence_and_snapshot(self):
        journal = Journal()
        first = journal.append_transfer("alice", "bob", 10)
        second = journal.append_transfer("alice", "bob", 20)
        self.assertEqual((first.seq, second.seq), (1, 2))
        entries = journal.entries()
        self.assertIsInstance(entries, tuple)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].amount, 10)


class StatusTests(unittest.TestCase):
    def test_status_shape(self):
        gate, _ = make_gate()
        token = do_initial(self, gate)
        gate.gate(transfer_req(confirmation=token))
        status = gate.status()
        self.assertEqual(
            set(status),
            {"degraded", "incident", "policy_version", "daily_spent",
             "audit_records", "journal_entries",
             "pending_confirmations"},
        )
        self.assertEqual(
            (status["degraded"], status["incident"],
             status["policy_version"], status["daily_spent"],
             status["audit_records"], status["journal_entries"]),
            (False, None, "v1", 100, 4, 1),
        )
        # The consumed token entry is retained until purge/clear.
        self.assertEqual(status["pending_confirmations"], 1)


class FactoryTests(unittest.TestCase):
    def test_create_gate_defaults(self):
        gate = create_gate()
        self.assertIsInstance(gate, Gate)
        self.assertEqual(gate.status()["policy_version"], "v1")
        token = do_initial(self, gate)
        response = gate.gate(transfer_req(confirmation=token))
        self.assertEqual(response["status"], "allowed")


if __name__ == "__main__":
    unittest.main()
