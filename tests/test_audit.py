"""Tests for audit chaining, verifier, export, and tamper detection (Gate B)."""
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.audit import (
    GENESIS_PREV_HASH,
    AuditCorruptionError,
    AuditError,
    AuditLog,
    verify_export,
)
from proofgate.canonical import arg_hash, canonicalize
from proofgate.enforcement import create_gate


class FakeClock:
    def __init__(self):
        self.now_value = 5000.0

    def __call__(self):
        tick = self.now_value
        self.now_value += 1.0
        return tick


def decision(log, **overrides):
    fields = {
        "kind": "decision",
        "actor": "agent",
        "action": "transfer_money",
        "arg_hash": "h",
        "policy_version": "v1",
        "decision": "denied",
        "reason": "ok",
    }
    fields.update(overrides)
    return log.append(**fields)


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog(
            initial_policy_version="v1", clock=FakeClock()
        )

    def test_genesis_record(self):
        (genesis,) = self.log.records
        self.assertEqual(genesis["kind"], "genesis")
        self.assertEqual(genesis["seq"], 1)
        self.assertEqual(genesis["prev_hash"], GENESIS_PREV_HASH)
        self.assertEqual(genesis["decision"], "recorded")
        ok, detail = self.log.verify()
        self.assertEqual((ok, detail), (True, {"records": 1}))

    def test_append_links_chain(self):
        decision(self.log)
        decision(self.log, reason="other")
        records = self.log.records
        self.assertEqual([r["seq"] for r in records], [1, 2, 3])
        self.assertEqual(records[1]["prev_hash"], records[0]["record_hash"])
        self.assertEqual(records[2]["prev_hash"], records[1]["record_hash"])
        ok, detail = self.log.verify()
        self.assertEqual((ok, detail), (True, {"records": 3}))

    def test_records_and_returns_are_copies(self):
        returned = decision(self.log)
        returned["reason"] = "mutated"
        self.log.records[1]["reason"] = "mutated"
        ok, _ = self.log.verify()
        self.assertTrue(ok)
        self.assertEqual(self.log.records[1]["reason"], "ok")

    def test_tamper_edit_detected(self):
        decision(self.log)
        decision(self.log)
        # Simulated tampering via private access: same-process mutation is
        # outside the threat model to prevent; detection is what is tested.
        self.log._records[1]["reason"] = "forged"
        ok, detail = self.log.verify()
        self.assertEqual(
            (ok, detail), (False, {"index": 1, "problem": "bad_hash"})
        )

    def test_delete_detected(self):
        decision(self.log)
        decision(self.log)
        del self.log._records[1]
        ok, detail = self.log.verify()
        self.assertFalse(ok)
        self.assertEqual(detail["index"], 1)

    def test_swap_detected(self):
        decision(self.log, reason="first")
        decision(self.log, reason="second")
        records = self.log._records
        records[1], records[2] = records[2], records[1]
        ok, _ = self.log.verify()
        self.assertFalse(ok)

    def test_append_after_tamper_raises(self):
        decision(self.log)
        self.log._records[-1]["reason"] = "forged"
        with self.assertRaises(AuditCorruptionError):
            decision(self.log)
        self.assertEqual(len(self.log), 2)

    def test_fault_hook_blocks_append(self):
        def fail(kind):
            raise AuditError("audit_unavailable")

        log = AuditLog(initial_policy_version="v1", fault_hook=fail)
        with self.assertRaises(AuditError):
            decision(log)
        self.assertEqual(len(log), 1)  # genesis only

    def test_export_round_trip(self):
        decision(self.log)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            report = self.log.export_jsonl(path)
            with open(path, "rb") as handle:
                blob = handle.read()
            self.assertTrue(blob.endswith(b"\n"))
            self.assertEqual(
                report,
                {
                    "path": path,
                    "records": 2,
                    "sha256": hashlib.sha256(blob).hexdigest(),
                },
            )
            ok, detail = verify_export(path)
            self.assertEqual((ok, detail), (True, {"records": 2}))

    def test_export_torn_tail_detected(self):
        decision(self.log)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            self.log.export_jsonl(path)
            with open(path, "ab") as handle:
                handle.write(b'{"kind":"dec')
            ok, detail = verify_export(path)
            self.assertEqual(
                (ok, detail),
                (False, {"problem": "unparseable_line", "line": 3}),
            )

    def test_export_tampered_byte_detected(self):
        decision(self.log, reason="stable-marker")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            self.log.export_jsonl(path)
            with open(path, "rb") as handle:
                blob = bytearray(handle.read())
            blob[60] ^= 0x01
            with open(path, "wb") as handle:
                handle.write(bytes(blob))
            ok, _ = verify_export(path)
            self.assertFalse(ok)

    def test_export_empty_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "empty.jsonl")
            with open(path, "wb"):
                pass
            ok, detail = verify_export(path)
            self.assertEqual((ok, detail), (False, {"problem": "empty"}))

    def test_prior_export_hash_recorded_verbatim(self):
        marker = "ab" * 32
        log = AuditLog(
            initial_policy_version="v2", prior_export_hash=marker
        )
        (genesis,) = log.records
        self.assertEqual(
            genesis["extra"], {"prior_export_hash": marker}
        )
        self.assertNotIn("prior_verified", canonicalize(genesis).decode())

    def test_no_prior_hash_leaves_extra_empty(self):
        (genesis,) = self.log.records
        self.assertEqual(genesis["extra"], {})


class AuditCorrespondenceTests(unittest.TestCase):
    """Every gate response maps to its audit record(s) (Gate C)."""

    def test_full_flow_correspondence(self):
        gate = create_gate(
            balances={"alice": 10000}, clock=FakeClock()
        )
        transfer = {"source": "alice", "target": "bob", "amount": 100}
        read = gate.gate({
            "action": "get_balance", "actor": "auditor-7",
            "args": {"account": "alice"},
        })
        initial = gate.gate({
            "action": "transfer_money", "args": dict(transfer),
        })
        executed = gate.gate({
            "action": "transfer_money", "args": dict(transfer),
            "confirmation": initial["confirmation"],
        })
        denied = gate.gate({
            "action": "transfer_money",
            "args": dict(transfer, amount=5000),
        })
        self.assertEqual(
            (read["status"], initial["status"], executed["status"],
             denied["status"]),
            ("allowed", "confirmation_required", "allowed", "denied"),
        )
        records = gate.audit_records()
        self.assertEqual(
            [r["kind"] for r in records],
            ["genesis", "decision", "decision", "authorized",
             "outcome", "decision"],
        )
        self.assertEqual(
            [r["seq"] for r in records], [1, 2, 3, 4, 5, 6]
        )
        read_rec, init_rec, auth_rec, out_rec, deny_rec = records[1:]
        self.assertEqual(
            (read_rec["decision"], read_rec["reason"],
             read_rec["actor"]),
            ("allowed", "ok", "auditor-7"),
        )
        self.assertEqual(
            read_rec["arg_hash"], arg_hash({"account": "alice"})
        )
        digest = arg_hash(transfer)
        self.assertEqual(
            (init_rec["decision"], init_rec["arg_hash"]),
            ("confirmation_required", digest),
        )
        token_id = init_rec["token_id"]
        self.assertEqual(token_id, initial["confirmation"][:8])
        self.assertNotEqual(token_id, initial["confirmation"])
        self.assertEqual(auth_rec["token_id"], token_id)
        self.assertEqual(out_rec["token_id"], token_id)
        self.assertEqual(auth_rec["arg_hash"], digest)
        self.assertEqual(out_rec["arg_hash"], digest)
        self.assertEqual(out_rec["extra"]["journal_seq"], 1)
        self.assertEqual(
            (deny_rec["decision"], deny_rec["reason"]),
            ("denied", "policy_limit_exceeded"),
        )
        self.assertEqual(
            deny_rec["arg_hash"],
            arg_hash(dict(transfer, amount=5000)),
        )
        for record in records[1:]:
            self.assertEqual(record["policy_version"], "v1")
        health = gate.check_health()
        self.assertTrue(health["audit"]["ok"])
        self.assertTrue(health["reconcile"]["clean"])
        self.assertTrue(health["cross_check"]["clean"])
        # A healthy check appends nothing.
        self.assertEqual(len(gate.audit_records()), 6)


if __name__ == "__main__":
    unittest.main()
