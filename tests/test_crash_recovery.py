"""Real subprocess-crash tests on isolated temporary databases.

Each test kills a child process with SIGKILL at a controlled
transaction boundary, reopens the database, and proves safe recovery:
pending operations resume, committed operations return their stored
receipt, and no boundary duplicates a transfer. POSIX-only (SIGKILL);
never touches a user database.
"""
import os
import signal
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.enforcement import Gate
from proofgate.policy import Policy
from proofgate.sqlite_backend import SQLiteBackend

CHILD = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "crash_child.py"
)


def make_policy():
    return Policy.create(
        version="v1", per_transfer_cap=500, daily_cap=1000,
        allowed_targets=("bob", "carol"),
    )


@unittest.skipUnless(
    hasattr(signal, "SIGKILL"), "POSIX SIGKILL required"
)
class CrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._backends = []
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.close_backends)

    def close_backends(self):
        for backend in self._backends:
            try:
                backend.close()
            except Exception:
                pass

    def path(self, name="g.db"):
        return os.path.join(self.tmp.name, name)

    def create(self, name="g.db"):
        backend = SQLiteBackend.create(
            self.path(name), policy=make_policy(),
            balances={"alice": 10000},
        )
        backend.close()

    def reopen(self, name="g.db"):
        backend = SQLiteBackend.open(self.path(name))
        self._backends.append(backend)
        return Gate(policy=backend.get_policy(), storage=backend)

    def run_child(self, key, mode, name="g.db"):
        proc = subprocess.run(
            [sys.executable, CHILD, self.path(name), key, mode],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(
            proc.returncode, -signal.SIGKILL,
            "child did not die by SIGKILL:\nstdout: %s\nstderr: %s"
            % (proc.stdout, proc.stderr),
        )
        return proc

    def test_kill_before_commit_recovers_to_pending(self):
        self.create()
        self.run_child("op-crash-1", "before-commit")
        gate = self.reopen()
        status = gate.operation_status("op-crash-1")
        self.assertEqual(status["status"], "pending")
        self.assertEqual(len(gate.journal_entries()), 0)
        self.assertEqual(gate.ledger_snapshot(), {"alice": 10000})
        self.assertEqual(gate.status()["daily_spent"], 0)
        token = gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": 100},
            "idempotency_key": "op-crash-1",
        })["confirmation"]
        allowed = gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": 100},
            "confirmation": token,
            "idempotency_key": "op-crash-1",
        })
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(len(gate.journal_entries()), 1)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

    def test_kill_after_commit_returns_recorded_outcome(self):
        self.create()
        self.run_child("op-crash-2", "after-commit")
        gate = self.reopen()
        status = gate.operation_status("op-crash-2")
        self.assertEqual(status["status"], "committed")
        again = gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": 100},
            "idempotency_key": "op-crash-2",
        })
        self.assertEqual(again["status"], "allowed")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["receipt"], status["receipt"])
        self.assertEqual(len(gate.journal_entries()), 1)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )


if __name__ == "__main__":
    unittest.main()
