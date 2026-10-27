"""Tests for reconciliation and reconstruction provenance limits (Gate C)."""
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.canonical import canonicalize
from proofgate.enforcement import Gate, create_gate
from proofgate.journal import Journal
from proofgate.policy import Policy
from proofgate.verify import cross_check_journal_audit, reconcile


def make_policy(version="v1"):
    return Policy.create(
        version=version, per_transfer_cap=500, daily_cap=1000,
        allowed_targets=("bob", "carol"),
    )


class ReconcileTests(unittest.TestCase):
    def test_clean(self):
        journal = Journal()
        journal.append_transfer("alice", "bob", 100)
        report = reconcile(
            {"alice": 1000}, journal.entries(),
            {"alice": 900, "bob": 100},
        )
        self.assertEqual(
            report,
            {"clean": True, "checked_entries": 1, "mismatches": {},
             "journal_ahead": None, "incident": None},
        )

    def test_empty_clean(self):
        report = reconcile({"alice": 5}, (), {"alice": 5})
        self.assertTrue(report["clean"])

    def test_ledger_tamper_is_generic_mismatch(self):
        journal = Journal()
        journal.append_transfer("alice", "bob", 100)
        report = reconcile(
            {"alice": 1000}, journal.entries(),
            {"alice": 900, "bob": 999},
        )
        self.assertFalse(report["clean"])
        self.assertIsNone(report["journal_ahead"])
        self.assertEqual(
            report["mismatches"],
            {"bob": {"expected": 100, "actual": 999}},
        )

    def test_dangling_entry_identified(self):
        journal = Journal()
        journal.append_transfer("alice", "bob", 100)
        dangling = journal.append_transfer("alice", "bob", 50)
        report = reconcile(
            {"alice": 1000}, journal.entries(),
            {"alice": 900, "bob": 100},
        )
        self.assertFalse(report["clean"])
        self.assertEqual(report["journal_ahead"], dangling.seq)
        self.assertEqual(
            report["mismatches"]["bob"],
            {"expected": 150, "actual": 100},
        )

    def test_incident_ref_echoed_without_effect(self):
        journal = Journal()
        plain = reconcile({"a": 1}, journal.entries(), {"a": 1})
        tagged = reconcile(
            {"a": 1}, journal.entries(), {"a": 1},
            incident_ref="case-x",
        )
        self.assertEqual(tagged["incident"], "case-x")
        self.assertEqual(
            {k: v for k, v in tagged.items() if k != "incident"},
            {k: v for k, v in plain.items() if k != "incident"},
        )


class CrossCheckTests(unittest.TestCase):
    def outcome(self, seq, decision="allowed", record_seq=9):
        return {
            "kind": "outcome", "seq": record_seq,
            "decision": decision, "extra": {"journal_seq": seq},
        }

    def test_clean(self):
        journal = Journal()
        journal.append_transfer("alice", "bob", 10)
        journal.append_transfer("alice", "bob", 20)
        report = cross_check_journal_audit(
            journal.entries(),
            [self.outcome(1, record_seq=5),
             self.outcome(2, record_seq=8)],
        )
        self.assertEqual(
            report,
            {"clean": True, "gaps": [], "orphans": [],
             "malformed_outcomes": [], "checked_entries": 2},
        )

    def test_gap_flagged(self):
        journal = Journal()
        journal.append_transfer("alice", "bob", 10)
        journal.append_transfer("alice", "bob", 20)
        report = cross_check_journal_audit(
            journal.entries(), [self.outcome(1, record_seq=5)]
        )
        self.assertEqual(
            (report["clean"], report["gaps"]), (False, [2])
        )

    def test_error_outcome_does_not_cover(self):
        journal = Journal()
        journal.append_transfer("alice", "bob", 10)
        report = cross_check_journal_audit(
            journal.entries(),
            [self.outcome(1, decision="error", record_seq=5)],
        )
        self.assertEqual(
            (report["clean"], report["gaps"]), (False, [1])
        )

    def test_orphan_and_malformed_flagged(self):
        journal = Journal()
        journal.append_transfer("alice", "bob", 10)
        bad = {"kind": "outcome", "seq": 7, "decision": "allowed",
               "extra": {}}
        report = cross_check_journal_audit(
            journal.entries(),
            [self.outcome(1, record_seq=5),
             self.outcome(99, record_seq=6), bad],
        )
        self.assertFalse(report["clean"])
        self.assertEqual(report["orphans"], [99])
        self.assertEqual(report["malformed_outcomes"], [7])


class CheckHealthTests(unittest.TestCase):
    def test_healthy_is_read_only(self):
        gate = create_gate(balances={"alice": 10000})
        initial = gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": 100},
        })
        gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": 100},
            "confirmation": initial["confirmation"],
        })
        before = len(gate.audit_records())
        report = gate.check_health()
        self.assertTrue(report["reconcile"]["clean"])
        self.assertTrue(report["cross_check"]["clean"])
        self.assertTrue(report["audit"]["ok"])
        self.assertFalse(report["degraded"])
        self.assertEqual(len(gate.audit_records()), before)

    def test_tamper_degrades_and_records(self):
        gate = create_gate(balances={"alice": 10000})
        # Simulated same-process tampering (prevention out of scope).
        gate._ledger._balances["bob"] = 424242
        report = gate.check_health()
        self.assertFalse(report["reconcile"]["clean"])
        self.assertTrue(report["degraded"])
        records = gate.audit_records()
        self.assertEqual(records[-1]["kind"], "verification")
        self.assertEqual(records[-1]["decision"], "mismatch")
        self.assertEqual(records[-1]["reason"], "balance_mismatch")


class ProvenanceTests(unittest.TestCase):
    def transfer(self, gate, amount=100):
        initial = gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": amount},
        })
        return gate.gate({
            "action": "transfer_money",
            "args": {"source": "alice", "target": "bob",
                     "amount": amount},
            "confirmation": initial["confirmation"],
        })

    def test_genuine_and_fabricated_recorded_verbatim(self):
        old = create_gate(balances={"alice": 10000})
        self.transfer(old)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.jsonl")
            export = old.export_audit(path)
            genuine = export["sha256"]
            with open(path, "rb") as handle:
                self.assertEqual(
                    hashlib.sha256(handle.read()).hexdigest(),
                    genuine,
                )
            fabricated = "00" * 32
            first = Gate(
                policy=make_policy(), balances={"alice": 10000},
                prior_export_hash=genuine,
            )
            second = Gate(
                policy=make_policy(), balances={"alice": 10000},
                prior_export_hash=fabricated,
            )
            for gate, marker in ((first, genuine),
                                 (second, fabricated)):
                (genesis,) = [
                    r for r in gate.audit_records()
                    if r["kind"] == "genesis"
                ]
                self.assertEqual(
                    genesis["extra"], {"prior_export_hash": marker}
                )
                for record in gate.audit_records():
                    self.assertNotIn(
                        "prior_verified",
                        canonicalize(record).decode(),
                    )
            # Both instances serve identically; neither verifies history.
            self.assertEqual(
                self.transfer(first)["receipt"],
                self.transfer(second)["receipt"],
            )

    def test_old_export_tamper_independent_of_new(self):
        old = create_gate(balances={"alice": 10000})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.jsonl")
            export = old.export_audit(path)
            with open(path, "rb") as handle:
                blob = bytearray(handle.read())
            blob[40] ^= 0x01
            with open(path, "wb") as handle:
                handle.write(bytes(blob))
            from proofgate.audit import verify_export
            ok, _ = verify_export(path)
            self.assertFalse(ok)
            fresh = Gate(
                policy=make_policy(), balances={"alice": 10000},
                prior_export_hash=export["sha256"],
            )
            self.assertEqual(
                self.transfer(fresh)["status"], "allowed"
            )


if __name__ == "__main__":
    unittest.main()
