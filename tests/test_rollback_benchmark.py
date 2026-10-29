"""Older-backup restore characterization (KNOWN LIMITATION benchmark).

Proves, against isolated temporary databases only, that restoring an
older but internally valid backup is accepted by startup verification
when reopened without checkpoint enforcement: balances, journal, and
operation history silently roll back, and a previously committed
idempotency key can execute its transfer again.

Checkpoint enforcement rejects such a rollback while the trusted
checkpoint stays ahead (see ``test_older_backup_rejected`` in
``tests/test_checkpoint.py``). Checkpoints provide no authenticity and
no protection when an attacker can replace both the database and the
checkpoint. This benchmark pins the unenforced behavior only.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.enforcement import Gate
from proofgate.policy import Policy
from proofgate.sqlite_backend import SQLiteBackend


def make_policy():
    return Policy.create(
        version="v1", per_transfer_cap=500, daily_cap=1000,
        allowed_targets=("bob", "carol"),
    )


def transfer_args(amount=100, target="bob"):
    return {"source": "alice", "target": target, "amount": amount}


class RollbackBenchmarkTests(unittest.TestCase):
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

    def keyed_transfer(self, testcase, gate, key, args):
        initial = gate.gate({
            "action": "transfer_money", "args": dict(args),
            "idempotency_key": key,
        })
        testcase.assertEqual(initial["status"], "confirmation_required")
        redeemed = gate.gate({
            "action": "transfer_money", "args": dict(args),
            "confirmation": initial["confirmation"],
            "idempotency_key": key,
        })
        testcase.assertEqual(redeemed["status"], "allowed")
        return redeemed

    def test_restore_older_backup_rolls_back_silently(self):
        live = self.path("g.db")
        backup_path = self.path("b1.db")
        backend = SQLiteBackend.create(
            live, policy=make_policy(), balances={"alice": 10000}
        )
        self._backends.append(backend)
        gate = Gate(policy=backend.get_policy(), storage=backend)

        # T1 commits; its evidence must survive the round-trip.
        self.keyed_transfer(
            self, gate, "rb-t1", transfer_args(100, "bob")
        )
        self.assertEqual(
            gate.operation_status("rb-t1")["status"], "committed"
        )

        # A pending token issued before the backup: its row is inside
        # B1 and redeemable now, stale after the restore reopen.
        pending = gate.gate({
            "action": "transfer_money",
            "args": transfer_args(10, "carol"),
            "idempotency_key": "rb-t3",
        })
        self.assertEqual(pending["status"], "confirmation_required")
        old_token = pending["confirmation"]

        # B1 is taken while the source stays open.
        backend.backup(backup_path)

        # T2 commits after B1; its evidence must NOT survive.
        t2_receipt = self.keyed_transfer(
            self, gate, "rb-t2", transfer_args(50, "bob")
        )["receipt"]
        self.assertEqual(t2_receipt["journal_seq"], 2)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 9850, "bob": 150}
        )
        self.assertEqual(
            gate.operation_status("rb-t2")["status"], "committed"
        )

        # Close cleanly, then restore B1 over the discarded live file.
        # No live database is overwritten: the backend is closed, and
        # any leftover sidecars are removed so they cannot contaminate
        # the restored state.
        backend.close()
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                os.remove(live + suffix)
            except FileNotFoundError:
                pass
        os.remove(live)
        shutil.copyfile(backup_path, live)

        # KNOWN LIMITATION: startup verification accepts the older
        # backup. A refusal here would mean rollback detection exists
        # and this characterization must be rewritten, not weakened.
        restored = SQLiteBackend.open(live)
        self._backends.append(restored)
        gate2 = Gate(policy=restored.get_policy(), storage=restored)

        # History rolled back: T1 present, T2 erased.
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )
        self.assertEqual(len(gate2.journal_entries()), 1)
        self.assertEqual(
            gate2.operation_status("rb-t1")["status"], "committed"
        )
        self.assertEqual(
            gate2.operation_status("rb-t2")["status"], "not_found"
        )
        self.assertEqual(
            gate2.operation_status("rb-t3")["status"], "pending"
        )

        # The pre-restore token is rejected as stale by boot-epoch
        # validation. This is token invalidation, NOT detection of
        # the rollback itself.
        stale = gate2.gate({
            "action": "transfer_money",
            "args": transfer_args(10, "carol"),
            "confirmation": old_token,
            "idempotency_key": "rb-t3",
        })
        self.assertEqual(stale["status"], "denied")
        self.assertEqual(stale["reason"], "confirmation_stale")
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9900, "bob": 100}
        )

        # KNOWN LIMITATION: the same T2 key and arguments execute the
        # transfer a second time, because the restored database has no
        # record of the first execution.
        retry_initial = gate2.gate({
            "action": "transfer_money",
            "args": transfer_args(50, "bob"),
            "idempotency_key": "rb-t2",
        })
        self.assertEqual(
            retry_initial["status"], "confirmation_required"
        )
        retry = gate2.gate({
            "action": "transfer_money",
            "args": transfer_args(50, "bob"),
            "confirmation": retry_initial["confirmation"],
            "idempotency_key": "rb-t2",
        })
        self.assertEqual(retry["status"], "allowed")
        # A genuine second execution, not a stored duplicate receipt:
        # no duplicate marker, and the journal grew by one entry. (The
        # receipt contents coincide with the erased original because
        # the retried arguments, journal position, and balances match.)
        self.assertNotIn("duplicate", retry)
        self.assertEqual(len(gate2.journal_entries()), 2)
        self.assertEqual(
            gate2.ledger_snapshot(), {"alice": 9850, "bob": 150}
        )
        self.assertEqual(
            gate2.operation_status("rb-t2")["status"], "committed"
        )


if __name__ == "__main__":
    unittest.main()
