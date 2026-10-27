"""Tests for confirmation lifecycle: binding, expiry, single-use, replay (Gate B)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.confirmations import (
    DEFAULT_TTL_SECONDS,
    ConfirmationError,
    ConfirmationStore,
)


class FakeClock:
    def __init__(self):
        self.now_value = 1000.0

    def __call__(self):
        return self.now_value

    def advance(self, seconds):
        self.now_value += seconds


class FakeMonotonicClock:
    """Faithful stand-in for time.monotonic: forward-only by force."""

    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        if seconds < 0:
            raise ValueError("monotonic clock cannot advance backward")
        self.value += seconds


class ConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.store = ConfirmationStore(clock=self.clock)

    def issue(self, action="transfer_money", digest="h", version="v1"):
        return self.store.issue(action, digest, version)

    def redeem(self, token, action="transfer_money", digest="h",
               version="v1"):
        return self.store.redeem(token, action, digest, version)

    def reason_of(self, callable_obj, *args):
        with self.assertRaises(ConfirmationError) as caught:
            callable_obj(*args)
        return caught.exception.reason

    def test_issue_redeem_ok_returns_binding(self):
        token = self.issue()
        binding = self.redeem(token)
        self.assertEqual(binding.action, "transfer_money")
        self.assertEqual(binding.arg_hash, "h")
        self.assertEqual(binding.policy_version, "v1")

    def test_forged_token_denied(self):
        self.assertEqual(
            self.reason_of(self.redeem, "forged-token-value"),
            "invalid_confirmation",
        )

    def test_replay_denied(self):
        token = self.issue()
        self.redeem(token)
        self.assertEqual(
            self.reason_of(self.redeem, token), "confirmation_reused"
        )

    def test_expired_denied(self):
        token = self.issue()
        self.clock.advance(DEFAULT_TTL_SECONDS + 1)
        self.assertEqual(
            self.reason_of(self.redeem, token), "confirmation_expired"
        )

    def test_expiry_boundary_exact_is_expired(self):
        token = self.issue()
        self.clock.advance(DEFAULT_TTL_SECONDS)
        self.assertEqual(
            self.reason_of(self.redeem, token), "confirmation_expired"
        )

    def test_just_before_expiry_ok(self):
        token = self.issue()
        self.clock.advance(DEFAULT_TTL_SECONDS - 0.001)
        self.redeem(token)  # must not raise

    def test_argument_mismatch_denied(self):
        token = self.issue(digest="h1")
        self.assertEqual(
            self.reason_of(self.redeem, token, "transfer_money", "h2"),
            "confirmation_mismatch",
        )

    def test_action_mismatch_denied(self):
        token = self.issue(action="transfer_money")
        self.assertEqual(
            self.reason_of(self.redeem, token, "get_balance", "h"),
            "confirmation_mismatch",
        )

    def test_policy_version_mismatch_denied(self):
        token = self.issue(version="v1")
        self.assertEqual(
            self.reason_of(
                self.redeem, token, "transfer_money", "h", "v2"
            ),
            "policy_superseded",
        )

    def test_used_beats_expired(self):
        token = self.issue()
        self.redeem(token)
        self.clock.advance(DEFAULT_TTL_SECONDS + 100)
        self.assertEqual(
            self.reason_of(self.redeem, token), "confirmation_reused"
        )

    def test_tokens_unique_and_prefixed(self):
        tokens = {self.issue() for _ in range(200)}
        self.assertEqual(len(tokens), 200)
        for token in tokens:
            self.assertGreater(len(token), 20)
            self.assertEqual(
                ConfirmationStore.token_id(token), token[:8]
            )
            self.assertEqual(len(ConfirmationStore.token_id(token)), 8)

    def test_purge_version(self):
        first = self.issue(version="v1")
        self.issue(version="v1")
        other = self.issue(version="v2")
        self.assertEqual(self.store.purge_version("v1"), 2)
        self.assertEqual(
            self.reason_of(self.redeem, first), "invalid_confirmation"
        )
        self.redeem(other, "transfer_money", "h", "v2")  # v2 token survives

    def test_clear(self):
        self.issue()
        self.issue()
        self.assertEqual(self.store.clear(), 2)
        self.assertEqual(self.store.pending_count(), 0)

    def test_bad_ttl_rejected(self):
        with self.assertRaises(ValueError):
            ConfirmationStore(ttl_seconds=0)

    def test_nonfinite_ttl_rejected(self):
        with self.assertRaises(ValueError):
            ConfirmationStore(ttl_seconds=float("inf"))
        with self.assertRaises(ValueError):
            ConfirmationStore(ttl_seconds=float("nan"))

    def test_large_finite_ttl_accepted(self):
        store = ConfirmationStore(ttl_seconds=1e308)
        token = store.issue("transfer_money", "h", "v1")
        binding = store.check(token, "transfer_money", "h", "v1")
        self.assertEqual(binding.policy_version, "v1")

    def test_check_does_not_consume(self):
        token = self.issue()
        binding = self.store.check(token, "transfer_money", "h", "v1")
        self.assertEqual(binding.policy_version, "v1")
        self.store.check(token, "transfer_money", "h", "v1")
        self.redeem(token)  # still redeemable after checks

    def test_consume_twice_rejected(self):
        token = self.issue()
        self.store.check(token, "transfer_money", "h", "v1")
        self.store.consume(token)
        self.assertEqual(
            self.reason_of(self.store.consume, token),
            "confirmation_reused",
        )

    def test_expiry_with_monotonic_clock(self):
        clock = FakeMonotonicClock(value=0.0)
        store = ConfirmationStore(ttl_seconds=300, clock=clock)
        token = store.issue("transfer_money", "h", "v1")
        clock.advance(299)
        binding = store.check(token, "transfer_money", "h", "v1")
        self.assertEqual(binding.policy_version, "v1")
        clock.advance(2)
        with self.assertRaises(ConfirmationError) as caught:
            store.check(token, "transfer_money", "h", "v1")
        self.assertEqual(caught.exception.reason, "confirmation_expired")
        with self.assertRaises(ValueError):
            clock.advance(-200)


if __name__ == "__main__":
    unittest.main()
