"""Tests for the storage backend contract and memory adapter (A2.1)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.enforcement import Gate, create_gate
from proofgate.ledger import LedgerError
from proofgate.policy import Policy
from proofgate.storage import MemoryBackend, StorageBackend


def make_policy():
    return Policy.create(
        version="v1", per_transfer_cap=500, daily_cap=1000,
        allowed_targets=("bob", "carol"),
    )


def make_backend(**overrides):
    params = {"policy": make_policy(), "balances": {"alice": 10000}}
    params.update(overrides)
    return MemoryBackend(**params)


class BackendContractTests(unittest.TestCase):
    def test_memory_constructs_working_stores(self):
        backend = make_backend()
        self.assertIsInstance(backend, StorageBackend)
        self.assertEqual(backend.ledger.balance("alice"), 10000)
        self.assertEqual(len(backend.journal), 0)
        (genesis,) = backend.audit.records
        self.assertEqual(genesis["kind"], "genesis")
        token = backend.confirmations.issue("transfer_money", "h", "v1")
        binding = backend.confirmations.check(
            token, "transfer_money", "h", "v1"
        )
        self.assertEqual(binding.policy_version, "v1")

    def test_transaction_reentrant_noop(self):
        backend = make_backend()
        with backend.transaction():
            with backend.transaction():
                pass
        token = backend.confirmations.issue("transfer_money", "h", "v1")
        self.assertTrue(token)

    def test_bad_balances_raise_from_backend(self):
        with self.assertRaises(LedgerError):
            make_backend(balances={"alice": -1})

    def test_storage_backend_is_abstract(self):
        with self.assertRaises(TypeError):
            StorageBackend()


class GateWiringTests(unittest.TestCase):
    def test_gate_uses_memory_by_default(self):
        gate = Gate(policy=make_policy(), balances={"alice": 10000})
        # Private access: assert the wiring itself; behavior is covered
        # by the full existing suite running through this default.
        self.assertIsInstance(gate._storage, MemoryBackend)

    def test_create_gate_uses_memory_by_default(self):
        gate = create_gate()
        self.assertIsInstance(gate._storage, MemoryBackend)

    def test_explicit_backend_end_to_end(self):
        gate = Gate(policy=make_policy(), storage=make_backend())
        args = {"source": "alice", "target": "bob", "amount": 100}
        initial = gate.gate({"action": "transfer_money", "args": args})
        self.assertEqual(initial["status"], "confirmation_required")
        executed = gate.gate({
            "action": "transfer_money", "args": dict(args),
            "confirmation": initial["confirmation"],
        })
        self.assertEqual(executed["status"], "allowed")
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

    def test_backends_isolated(self):
        first = Gate(policy=make_policy(), storage=make_backend())
        second = Gate(policy=make_policy(), storage=make_backend())
        args = {"source": "alice", "target": "bob", "amount": 100}
        token = first.gate(
            {"action": "transfer_money", "args": args}
        )["confirmation"]
        first.gate({
            "action": "transfer_money", "args": dict(args),
            "confirmation": token,
        })
        self.assertEqual(
            second.ledger_snapshot(), {"alice": 10000}
        )

    def test_storage_arguments_checked(self):
        with self.assertRaises(TypeError):
            Gate(policy=make_policy(), balances={"alice": 1},
                 storage="not-a-backend")
        with self.assertRaises(TypeError):
            Gate(policy=make_policy())
        with self.assertRaises(TypeError):
            Gate(policy=make_policy(), balances={"alice": 1},
                 storage=make_backend())


if __name__ == "__main__":
    unittest.main()
