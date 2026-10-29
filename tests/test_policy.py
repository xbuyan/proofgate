"""Tests for policy evaluation and policy validation (Gate B)."""
import dataclasses
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate import policy
from proofgate.policy import Policy, PolicyError, evaluate


def make_policy(**overrides):
    fields = {
        "version": "v1",
        "per_transfer_cap": 500,
        "daily_cap": 1000,
        "allowed_targets": ("bob", "carol"),
    }
    fields.update(overrides)
    return Policy.create(**fields)


def state(balances=None, daily_spent=0):
    return {"balances": balances or {}, "daily_spent": daily_spent}


class PolicyModelTests(unittest.TestCase):
    def test_frozen(self):
        pol = make_policy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            pol.daily_cap = 1

    def test_targets_normalized_sorted_tuple(self):
        pol = make_policy(allowed_targets=("carol", "bob", "bob"))
        self.assertEqual(pol.allowed_targets, ("bob", "carol"))

    def test_create_rejects_bad_fields(self):
        with self.assertRaises(PolicyError):
            make_policy(version="")
        with self.assertRaises(PolicyError):
            make_policy(per_transfer_cap=-1)
        with self.assertRaises(PolicyError):
            make_policy(daily_cap=True)
        with self.assertRaises(PolicyError):
            make_policy(allowed_targets=("bob", ""))
        with self.assertRaises(PolicyError):
            make_policy(allowed_targets=("bob", 7))
        with self.assertRaises(PolicyError):
            make_policy(allowed_targets="bob")
        with self.assertRaises(PolicyError):
            make_policy(allowed_targets=b"bob")

    def test_create_enforces_sqlite_integer_range(self):
        ceiling = 2**63 - 1
        pol = make_policy(
            per_transfer_cap=ceiling, daily_cap=ceiling
        )
        self.assertEqual(pol.per_transfer_cap, ceiling)
        self.assertEqual(pol.daily_cap, ceiling)
        with self.assertRaises(PolicyError):
            make_policy(per_transfer_cap=2**63)
        with self.assertRaises(PolicyError):
            make_policy(daily_cap=2**63)


class PolicyEvaluateTests(unittest.TestCase):
    def setUp(self):
        self.policy = make_policy()

    def transfer(self, **overrides):
        args = {"source": "alice", "target": "bob", "amount": 100}
        args.update(overrides)
        return args

    def test_get_balance_permitted(self):
        permitted, reason = evaluate(
            self.policy, "get_balance", {"account": "alice"},
            state({"alice": 1000}),
        )
        self.assertEqual((permitted, reason), (True, policy.REASON_OK))

    def test_unknown_tool_denied(self):
        permitted, reason = evaluate(
            self.policy, "wire_money", {}, state()
        )
        self.assertEqual(
            (permitted, reason), (False, policy.REASON_UNKNOWN_TOOL)
        )

    def test_valid_transfer_permitted(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(),
            state({"alice": 1000}),
        )
        self.assertEqual((permitted, reason), (True, policy.REASON_OK))

    def test_target_not_allowed(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(target="mallory"),
            state({"alice": 1000}),
        )
        self.assertEqual(
            (permitted, reason),
            (False, policy.REASON_TARGET_NOT_ALLOWED),
        )

    def test_per_transfer_cap_exceeded(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(amount=501),
            state({"alice": 10000}),
        )
        self.assertEqual(
            (permitted, reason), (False, policy.REASON_LIMIT_EXCEEDED)
        )

    def test_per_transfer_cap_boundary_exact_allowed(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(amount=500),
            state({"alice": 10000}),
        )
        self.assertEqual((permitted, reason), (True, policy.REASON_OK))

    def test_daily_cap_exceeded(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(amount=200),
            state({"alice": 10000}, daily_spent=900),
        )
        self.assertEqual(
            (permitted, reason), (False, policy.REASON_DAILY_LIMIT)
        )

    def test_daily_cap_boundary_exact_allowed(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(amount=100),
            state({"alice": 10000}, daily_spent=900),
        )
        self.assertEqual((permitted, reason), (True, policy.REASON_OK))

    def test_insufficient_funds(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(amount=100),
            state({"alice": 50}),
        )
        self.assertEqual(
            (permitted, reason), (False, policy.REASON_INSUFFICIENT_FUNDS)
        )

    def test_unknown_source_reads_as_zero(self):
        permitted, reason = evaluate(
            self.policy, "transfer_money", self.transfer(source="ghost"),
            state({"alice": 10000}),
        )
        self.assertEqual(
            (permitted, reason), (False, policy.REASON_INSUFFICIENT_FUNDS)
        )

    def test_invalid_amounts(self):
        for amount in (0, -5):
            permitted, reason = evaluate(
                self.policy, "transfer_money",
                self.transfer(amount=amount), state({"alice": 10000}),
            )
            self.assertEqual(
                (permitted, reason), (False, policy.REASON_INVALID_AMOUNT)
            )


if __name__ == "__main__":
    unittest.main()
