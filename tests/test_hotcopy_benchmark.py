"""Hot-copy staleness characterization (KNOWN LIMITATION benchmark).

Proves, against isolated temporary databases only, that copying just
the main SQLite file while the database is open in WAL mode yields a
stale copy that startup verification still accepts when opened
without checkpoint enforcement — while the supported
``SQLiteBackend.backup()`` snapshot taken at the same moment carries
the full committed state.

Checkpoint enforcement can reject such a stale database when the
independently preserved checkpoint is ahead of it (see
``test_older_backup_rejected`` in ``tests/test_checkpoint.py``). This
benchmark pins the unenforced behavior only; if unenforced
stale-prefix detection ever lands, the KNOWN-LIMITATION assertions
below must be flipped deliberately.
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


class HotCopyBenchmarkTests(unittest.TestCase):
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

    def test_hot_copy_opens_stale_while_backup_is_complete(self):
        live = self.path("g.db")
        backend = SQLiteBackend.create(
            live, policy=make_policy(), balances={"alice": 10000}
        )
        self._backends.append(backend)
        # Close once so the seed state checkpoints into the main file;
        # the hot copy below is then a valid stale database rather
        # than a schema-less fragment that would fail for the wrong
        # reason.
        backend.close()
        backend = SQLiteBackend.open(live)
        self._backends.append(backend)
        gate = Gate(policy=backend.get_policy(), storage=backend)

        # One committed keyed transfer; its evidence must survive in
        # the supported backup but may be absent from a hot copy.
        receipt = self.keyed_transfer(
            self, gate, "p2-t1", transfer_args(100, "bob")
        )["receipt"]
        self.assertEqual(
            gate.operation_status("p2-t1")["status"], "committed"
        )
        live_balances = gate.ledger_snapshot()
        live_journal = len(gate.journal_entries())
        live_audit = len(gate.audit_records())

        # Premise: committed state is uncheckpointed while the source
        # stays open — exactly what a main-file copy drops.
        wal_bytes = os.path.getsize(live + "-wal")
        self.assertGreater(wal_bytes, 0)

        # Both artifacts are taken while the source stays open.
        backend.backup(self.path("b1.db"))
        shutil.copyfile(live, self.path("copy.db"))
        backend.close()

        # The supported backup is complete: balances, operation
        # receipt, journal, and audit evidence all survive, plus the
        # copy's own boot record from opening it.
        backup_backend = SQLiteBackend.open(self.path("b1.db"))
        self._backends.append(backup_backend)
        backup_gate = Gate(
            policy=backup_backend.get_policy(), storage=backup_backend
        )
        self.assertEqual(backup_gate.ledger_snapshot(), live_balances)
        backup_status = backup_gate.operation_status("p2-t1")
        self.assertEqual(backup_status["status"], "committed")
        self.assertEqual(backup_status["receipt"], receipt)
        self.assertEqual(
            len(backup_gate.journal_entries()), live_journal
        )
        self.assertEqual(
            len(backup_gate.audit_records()), live_audit + 1
        )
        self.assertEqual(
            backup_gate.audit_records()[-1]["kind"], "boot"
        )

        # KNOWN LIMITATION: the hot copy opens cleanly despite missing
        # committed state, because this open uses no checkpoint
        # enforcement. A refusal here would mean unenforced
        # stale-prefix detection exists and this characterization must
        # be rewritten, not weakened.
        copy_backend = SQLiteBackend.open(self.path("copy.db"))
        self._backends.append(copy_backend)
        copy_gate = Gate(
            policy=copy_backend.get_policy(), storage=copy_backend
        )
        self.assertEqual(
            copy_gate.ledger_snapshot(), {"alice": 10000}
        )
        self.assertEqual(
            copy_gate.operation_status("p2-t1")["status"], "not_found"
        )
        self.assertEqual(len(copy_gate.journal_entries()), 0)
        self.assertLess(
            len(copy_gate.audit_records()), live_audit + 1
        )


if __name__ == "__main__":
    unittest.main()
