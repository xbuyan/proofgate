"""Concurrency tests: serialized limits and single-use redemption (Gate C).

Synchronization uses barriers and joins only; no timing-dependent
assertions. Every test asserts exact terminal counts.
"""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.enforcement import create_gate
from proofgate.policy import Policy


def transfer_args(amount=100, target="bob"):
    return {"source": "alice", "target": target, "amount": amount}


class ConcurrencyTests(unittest.TestCase):
    def run_threads(self, count, worker):
        barrier = threading.Barrier(count)
        errors = []

        def wrap(index):
            try:
                barrier.wait()
                worker(index)
            except Exception as exc:  # surfaced, never swallowed
                errors.append(exc)

        threads = [
            threading.Thread(target=wrap, args=(index,))
            for index in range(count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertFalse(
            [t for t in threads if t.is_alive()],
            "worker threads did not finish",
        )
        self.assertEqual(errors, [])
        return threads

    def test_racing_redemption_single_winner(self):
        gate = create_gate(balances={"alice": 100000})
        initial = gate.gate({
            "action": "transfer_money", "args": transfer_args(),
        })
        token = initial["confirmation"]
        outcomes = []
        lock = threading.Lock()

        def worker(_):
            response = gate.gate({
                "action": "transfer_money",
                "args": transfer_args(), "confirmation": token,
            })
            with lock:
                outcomes.append(
                    (response["status"], response["reason"])
                )

        self.run_threads(10, worker)
        allowed = [o for o in outcomes if o[0] == "allowed"]
        reused = [o for o in outcomes if o[1] == "confirmation_reused"]
        self.assertEqual(len(allowed), 1)
        self.assertEqual(len(reused), 9)
        self.assertEqual(
            gate.ledger_snapshot(),
            {"alice": 99900, "bob": 100},
        )
        self.assertEqual(len(gate.journal_entries()), 1)

    def test_racing_transfers_capped(self):
        gate = create_gate(balances={"alice": 100000})
        outcomes = []
        lock = threading.Lock()

        def worker(_):
            initial = gate.gate({
                "action": "transfer_money", "args": transfer_args(),
            })
            if initial["status"] != "confirmation_required":
                with lock:
                    outcomes.append(
                        (initial["status"], initial["reason"])
                    )
                return
            response = gate.gate({
                "action": "transfer_money",
                "args": transfer_args(),
                "confirmation": initial["confirmation"],
            })
            with lock:
                outcomes.append(
                    (response["status"], response["reason"])
                )

        self.run_threads(20, worker)
        allowed = [o for o in outcomes if o[0] == "allowed"]
        denied = [o for o in outcomes if o[0] == "denied"]
        self.assertEqual(len(allowed), 10)
        self.assertEqual(len(denied), 10)
        for status, reason in denied:
            self.assertEqual(reason, "daily_limit_exceeded")
        self.assertEqual(
            gate.ledger_snapshot(),
            {"alice": 99000, "bob": 1000},
        )
        health = gate.check_health()
        self.assertTrue(health["reconcile"]["clean"])
        self.assertTrue(health["audit"]["ok"])

    def test_concurrent_reads_and_writes(self):
        gate = create_gate(balances={"alice": 10000})
        read_results = []
        write_results = []
        errors = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def reader():
            try:
                barrier.wait()
                for _ in range(20):
                    response = gate.gate({
                        "action": "get_balance",
                        "args": {"account": "alice"},
                    })
                    with lock:
                        read_results.append(response["status"])
            except Exception as exc:
                with lock:
                    errors.append(exc)

        def writer():
            try:
                barrier.wait()
                for _ in range(5):
                    initial = gate.gate({
                        "action": "transfer_money",
                        "args": transfer_args(amount=10),
                    })
                    response = gate.gate({
                        "action": "transfer_money",
                        "args": transfer_args(amount=10),
                        "confirmation": initial["confirmation"],
                    })
                    with lock:
                        write_results.append(response["status"])
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = (
            [threading.Thread(target=reader) for _ in range(4)]
            + [threading.Thread(target=writer) for _ in range(4)]
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertFalse(
            [t for t in threads if t.is_alive()],
            "worker threads did not finish",
        )
        self.assertEqual(errors, [])
        self.assertEqual(len(read_results), 80)
        self.assertTrue(all(s == "allowed" for s in read_results))
        self.assertEqual(len(write_results), 20)
        self.assertTrue(all(s == "allowed" for s in write_results))
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9800, "bob": 200}
        )
        self.assertTrue(gate.check_health()["reconcile"]["clean"])

    def test_policy_update_atomicity(self):
        gate = create_gate(balances={"alice": 100000})
        outcomes = []
        lock = threading.Lock()
        workers = 6
        barrier = threading.Barrier(workers + 1)

        def worker(_):
            barrier.wait()
            for _ in range(15):
                initial = gate.gate({
                    "action": "transfer_money",
                    "args": transfer_args(amount=10),
                })
                if initial["status"] != "confirmation_required":
                    with lock:
                        outcomes.append(dict(initial))
                    continue
                response = gate.gate({
                    "action": "transfer_money",
                    "args": transfer_args(amount=10),
                    "confirmation": initial["confirmation"],
                })
                with lock:
                    outcomes.append(dict(response))

        threads = [
            threading.Thread(target=worker, args=(index,))
            for index in range(workers)
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        updated = gate.update_policy(Policy.create(
            version="v2", per_transfer_cap=500, daily_cap=1000,
            allowed_targets=("carol",),
        ))
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(updated["status"], "policy_updated")
        self.assertEqual(gate.status()["policy_version"], "v2")
        for outcome in outcomes:
            self.assertIn(outcome["status"], ("allowed", "denied"))
            if outcome["status"] == "allowed":
                self.assertEqual(
                    outcome["receipt"]["policy_version"], "v1"
                )
            else:
                self.assertIn(
                    outcome["reason"],
                    ("target_not_allowed", "invalid_confirmation"),
                )
        for record in gate.audit_records():
            if record["kind"] == "authorized":
                self.assertEqual(record["policy_version"], "v1")
        health = gate.check_health()
        self.assertTrue(health["reconcile"]["clean"])
        self.assertTrue(health["audit"]["ok"])


if __name__ == "__main__":
    unittest.main()
