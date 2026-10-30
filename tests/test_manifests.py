"""Local manifest tests: enumeration consistency over audit history.

Slice A. A manifest enumerates the eligible ``allowed`` OUTCOME records
in an audit range. Verification establishes C-H only (faithful local
enumeration); ``co`` is always ``unresolved``. Outcomes without an
operation record are reported ``unresolved`` -- never assigned an
identity -- because current data cannot distinguish a legitimate
keyless transfer from a deleted operation record.
"""
import copy
import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.canonical import canonicalize
from proofgate.enforcement import Gate
from proofgate.manifests import (
    ManifestError,
    _record_shape_valid,
    build_manifest,
    verify_local_consistency,
)
from proofgate.policy import Policy
from proofgate.sqlite_backend import SQLiteBackend


def make_policy(**overrides):
    params = {
        "version": "v1",
        "per_transfer_cap": 500,
        "daily_cap": 1000,
        "allowed_targets": ("bob", "carol"),
    }
    params.update(overrides)
    return Policy.create(**params)


def args(amount=100, target="bob"):
    return {"source": "alice", "target": target, "amount": amount}


def recompute(manifest):
    """Recompute a presented manifest's digests (attacker model)."""
    entries = manifest["entries"]
    root = hashlib.sha256(canonicalize(entries)).hexdigest()
    header = {
        "format_version": manifest["format_version"],
        "range_start": manifest["range_start"],
        "range_end": manifest["range_end"],
        "op_count": manifest["op_count"],
        "keyed_count": manifest["keyed_count"],
        "unresolved_count": manifest["unresolved_count"],
        "entries_root": root,
    }
    manifest["entries_root"] = root
    manifest["manifest_digest"] = hashlib.sha256(
        canonicalize(header)
    ).hexdigest()
    return manifest


def refix_counts(manifest):
    entries = manifest["entries"]
    manifest["op_count"] = len(entries)
    manifest["keyed_count"] = sum(
        1 for e in entries if e.get("classification") == "keyed"
    )
    manifest["unresolved_count"] = sum(
        1 for e in entries if e.get("classification") == "unresolved"
    )
    return manifest


class ManifestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._backends = []
        self.addCleanup(self.tmp.cleanup)

    def tearDown(self):
        for backend in self._backends:
            try:
                backend.close()
            except Exception:
                pass

    def path(self, name="g.db"):
        return os.path.join(self.tmp.name, name)

    def make_gate(self, name="g.db", policy=None, balances=None):
        policy = policy if policy is not None else make_policy()
        balances = (
            balances if balances is not None else {"alice": 10000}
        )
        backend = SQLiteBackend.create(
            self.path(name), policy=policy, balances=balances
        )
        self._backends.append(backend)
        return Gate(policy=policy, storage=backend), backend

    def make_memory_gate(self, policy=None, balances=None):
        return Gate(
            policy=policy if policy is not None else make_policy(),
            balances=balances if balances is not None else {
                "alice": 10000
            },
        )

    def reopen(self, backend, name="g.db"):
        backend.close()
        reopened = SQLiteBackend.open(self.path(name))
        self._backends.append(reopened)
        return (
            Gate(policy=reopened.get_policy(), storage=reopened),
            reopened,
        )

    def keyed_transfer(self, testcase, gate, key, **kwargs):
        params = {"amount": 100, "target": "bob"}
        params.update(kwargs)
        initial = gate.gate({
            "action": "transfer_money", "args": args(**params),
            "idempotency_key": key,
        })
        testcase.assertEqual(initial["status"], "confirmation_required")
        redeemed = gate.gate({
            "action": "transfer_money", "args": args(**params),
            "confirmation": initial["confirmation"],
            "idempotency_key": key,
        })
        testcase.assertEqual(redeemed["status"], "allowed")
        return redeemed["receipt"]

    def keyless_transfer(self, testcase, gate, **kwargs):
        params = {"amount": 100, "target": "bob"}
        params.update(kwargs)
        initial = gate.gate({
            "action": "transfer_money", "args": args(**params),
        })
        testcase.assertEqual(initial["status"], "confirmation_required")
        redeemed = gate.gate({
            "action": "transfer_money", "args": args(**params),
            "confirmation": initial["confirmation"],
        })
        testcase.assertEqual(redeemed["status"], "allowed")
        return redeemed["receipt"]

    def evidence(self, gate, backend):
        return (
            list(gate.audit_records()),
            list(gate.journal_entries()),
            backend.list_operations()
            if backend is not None
            else gate._storage.list_operations(),
        )

    def full_range(self, records):
        return 1, records[-1]["seq"]

    def opening(self, gate, backend):
        storage = backend if backend is not None else gate._storage
        return storage.get_opening_balances(), gate.ledger_snapshot()

    def build_and_verify(self, gate, backend=None, **kwargs):
        records, journal, ops = self.evidence(gate, backend)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=kwargs.pop("range_start", start),
            range_end=kwargs.pop("range_end", end),
        )
        opening, snapshot = self.opening(gate, backend)
        return verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=kwargs.pop("opening_balances", opening),
            ledger_snapshot=kwargs.pop("ledger_snapshot", snapshot),
            **kwargs
        ), manifest

    def assert_pass(self, result, unresolved):
        """Every C-H PASS also pins C-O unresolved and the listing."""
        self.assertEqual(result["ch"], "pass")
        self.assertEqual(result["ch_problems"], [])
        self.assertEqual(result["co"], "unresolved")
        self.assertEqual(
            result["co_reason"], "no_independent_occurrence_evidence"
        )
        self.assertEqual(result["unresolved_entries"], unresolved)
        self.assertEqual(result["exact_ids_available"], not unresolved)
        self.assertEqual(result["deployment_bound"], False)

    def codes(self, result):
        return [p["code"] for p in result["ch_problems"]]

    def backends(self):
        """Yield (label, gate, backend-or-None) for both backends."""
        gate, backend = self.make_gate()
        yield "sqlite", gate, backend
        yield "memory", self.make_memory_gate(), None


class BuildVerifyTests(ManifestCase):
    def test_keyed_history_passes(self):
        for label, gate, backend in self.backends():
            with self.subTest(backend=label):
                self.keyed_transfer(self, gate, "m-a")
                self.keyed_transfer(
                    self, gate, "m-b", amount=50, target="carol"
                )
                result, manifest = self.build_and_verify(gate, backend)
                self.assert_pass(result, [])
                self.assertEqual(
                    [e["op_key"] for e in manifest["entries"]],
                    ["m-a", "m-b"],
                )
                self.assertEqual(manifest["keyed_count"], 2)
                self.assertEqual(manifest["unresolved_count"], 0)
                self.assertEqual(len(manifest["manifest_digest"]), 64)
                self.assertTrue(result["reconcile_checked"])

    def test_keyless_outcome_unresolved(self):
        for label, gate, backend in self.backends():
            with self.subTest(backend=label):
                self.keyless_transfer(self, gate)
                result, manifest = self.build_and_verify(gate, backend)
                (entry,) = manifest["entries"]
                self.assertEqual(
                    entry["classification"], "unresolved"
                )
                self.assertNotIn("op_key", entry)
                self.assert_pass(result, [entry["audit_seq"]])

    def test_mixed_history_counts(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyless_transfer(self, gate, amount=50, target="carol")
        result, manifest = self.build_and_verify(gate, backend)
        self.assertEqual(manifest["op_count"], 2)
        self.assertEqual(manifest["keyed_count"], 1)
        self.assertEqual(manifest["unresolved_count"], 1)
        self.assert_pass(
            result,
            [e["audit_seq"] for e in manifest["entries"]
             if e["classification"] == "unresolved"],
        )

    def test_deterministic_rebuild(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyless_transfer(self, gate, amount=50, target="carol")
        records, journal, ops = self.evidence(gate, backend)
        start, end = self.full_range(records)
        first = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end,
        )
        records2, journal2, ops2 = self.evidence(gate, backend)
        second = build_manifest(
            records2, journal2, ops2,
            range_start=start, range_end=end,
        )
        self.assertEqual(first, second)
        self.assertEqual(canonicalize(first), canonicalize(second))

    def test_empty_range_passes(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, backend)
        manifest = build_manifest(
            records, journal, ops, range_start=1, range_end=1
        )
        self.assertEqual(manifest["entries"], [])
        self.assertEqual(manifest["op_count"], 0)
        opening, snapshot = self.opening(gate, backend)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(result, [])

    def test_sqlite_reopen_range_stable(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, backend)
        start, end = self.full_range(records)
        before = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        gate2, backend2 = self.reopen(backend)
        records2, journal2, ops2 = self.evidence(gate2, backend2)
        after = build_manifest(
            records2, journal2, ops2, range_start=start, range_end=end
        )
        self.assertEqual(before, after)
        opening, snapshot = self.opening(gate2, backend2)
        result = verify_local_consistency(
            after, records2, journal2, ops2,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(result, [])

    def test_reconcile_unchecked_flag(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        result = verify_local_consistency(
            manifest, records, journal, ops
        )
        self.assert_pass(result, [])
        self.assertFalse(result["reconcile_checked"])


class NegativeTests(ManifestCase):
    def clean(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyed_transfer(self, gate, "m-b", amount=50)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        opening, snapshot = self.opening(gate, None)
        return manifest, records, journal, ops, opening, snapshot

    def verify(self, manifest, records, journal, ops, opening, snapshot):
        return verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )

    def test_tampered_entry_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        manifest["entries"][0]["amount"] = 9999
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("digest_mismatch", self.codes(result))

    def test_tampered_entry_recomputed_digests_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        manifest["entries"][0]["amount"] = 9999
        recompute(manifest)
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("manifest_tamper", self.codes(result))

    def test_omitted_entry_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        manifest["entries"].pop(0)
        recompute(refix_counts(manifest))
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("manifest_omission", self.codes(result))

    def test_extra_entry_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        extra = copy.deepcopy(manifest["entries"][0])
        extra["audit_seq"] = 9999
        manifest["entries"].append(extra)
        recompute(refix_counts(manifest))
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("manifest_extra", self.codes(result))

    def test_duplicate_presented_seq_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        manifest["entries"].append(
            copy.deepcopy(manifest["entries"][0])
        )
        recompute(refix_counts(manifest))
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("manifest_extra", self.codes(result))

    def test_reordered_entries_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        manifest["entries"].reverse()
        recompute(manifest)
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("manifest_reorder", self.codes(result))

    def test_count_mismatch_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        manifest["op_count"] = 99
        recompute(manifest)
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("manifest_count_mismatch", self.codes(result))

    def test_range_uncovered_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        manifest["range_end"] = manifest["range_end"] + 5
        recompute(manifest)
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("range_uncovered", self.codes(result))

    def test_broken_chain_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        records[2]["record_hash"] = "0" * 64
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("chain_invalid", self.codes(result))

    def test_genesis_invalid_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        records[0]["kind"] = "outcome"
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("genesis_invalid", self.codes(result))

    def test_discontiguous_audit_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        del records[2]
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("audit_discontiguous", self.codes(result))

    def test_history_not_full_fails(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        result = self.verify(
            manifest, records[2:], journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("history_not_full", self.codes(result))

    def test_pending_coexisting_with_outcome(self):
        # A pending keyed request plus a keyless execution with
        # identical arguments is legitimate: the OUTCOME has no
        # operation record, so it reports unresolved, not conflict.
        gate = self.make_memory_gate()
        initial = gate.gate({
            "action": "transfer_money", "args": args(),
            "idempotency_key": "m-pending",
        })
        self.assertEqual(initial["status"], "confirmation_required")
        self.keyless_transfer(self, gate)
        result, manifest = self.build_and_verify(gate, None)
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "unresolved")
        self.assert_pass(result, [entry["audit_seq"]])

    def test_outcome_missing(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        dropped = [
            record for record in records
            if not (
                record.get("kind") == "outcome"
                and record.get("decision") == "allowed"
            )
        ]
        renumbered = []
        for seq, record in enumerate(dropped, start=1):
            kept = dict(record, seq=seq)
            renumbered.append(kept)
        result = self.verify(
            manifest, renumbered, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("outcome_missing", self.codes(result))

    def test_fingerprint_mismatch(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        ops[0]["receipt"]["amount"] = 101
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("fingerprint_mismatch", self.codes(result))

    def test_receipt_journal_seq_without_entry(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        ops[0]["receipt"]["journal_seq"] = 9999
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("journal_mismatch", self.codes(result))

    def test_duplicate_operation_binding(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        clone = copy.deepcopy(ops[0])
        clone["key"] = "m-clone"
        ops.append(clone)
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn(
            "duplicate_operation_binding", self.codes(result)
        )
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "duplicate_operation_binding"
        )

    def test_journal_gap(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        journal.pop(0)
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("journal_gap", self.codes(result))

    def test_bad_outcome_shape(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        for record in records:
            if (
                record.get("kind") == "outcome"
                and record.get("decision") == "allowed"
            ):
                record["extra"] = "not-a-dict"
                break
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("bad_outcome_shape", self.codes(result))

    def test_bad_operation_shape(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        ops[0]["action"] = ""
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("bad_operation_shape", self.codes(result))

    def test_pending_receipt(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        ops.append({
            "key": "pending-bad", "action": "transfer_money",
            "arg_hash": "0" * 64, "actor": "tester",
            "status": "pending", "receipt": {},
            "created_epoch": 0, "updated_epoch": 0,
        })
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("pending_receipt", self.codes(result))

    def test_journal_action_mismatch(self):
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        journal[0] = replace(journal[0], action="get_balance")
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("journal_mismatch", self.codes(result))

    def test_malformed_inputs_raise(self):
        (manifest, records, journal, ops, _, _) = self.clean()
        start, end = self.full_range(records)
        bad_manifests = [
            None, "x", [],
            dict(manifest, format_version=0),
            dict(manifest, format_version="1"),
            dict(manifest, format_version=True),
            dict(manifest, range_start=0),
            dict(manifest, range_end=0),
            dict(manifest, entries="x"),
            dict(manifest, entries=[{"no_seq": 1}]),
            dict(manifest, op_count=True),
            dict(manifest, manifest_digest=123),
        ]
        for index, bad in enumerate(bad_manifests):
            with self.subTest(case=index):
                with self.assertRaises(ManifestError):
                    verify_local_consistency(
                        bad, records, journal, ops
                    )
        with self.assertRaises(ManifestError):
            verify_local_consistency(manifest, "x", journal, ops)
        with self.assertRaises(ManifestError):
            verify_local_consistency(manifest, records, "x", ops)
        with self.assertRaises(ManifestError):
            verify_local_consistency(manifest, records, journal, "x")
        opening = {"alice": 10000}
        snapshot = {"alice": 10000}
        with self.assertRaises(ManifestError):
            verify_local_consistency(
                manifest, records, journal, ops,
                opening_balances="x", ledger_snapshot=snapshot,
            )
        with self.assertRaises(ManifestError):
            verify_local_consistency(
                manifest, records, journal, ops,
                opening_balances=opening, ledger_snapshot=[1],
            )
        with self.assertRaises(ManifestError):
            build_manifest(
                records, journal, ops,
                range_start=0, range_end=end,
            )
        with self.assertRaises(ManifestError):
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end + 50,
            )


class AntiConflationTests(ManifestCase):
    BANNED = frozenset({
        "verified", "verify", "complete", "completeness",
        "completed", "anchored", "anchor", "fresh", "freshness",
        "final", "finality", "trusted", "trust", "authentic",
        "authenticity", "proven", "proof",
    })

    def keys(self, value, found=None):
        found = found if found is not None else set()
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str):
                    found.add(key.lower())
                self.keys(item, found)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self.keys(item, found)
        return found

    def test_no_combined_status_field(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyless_transfer(self, gate, amount=50)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        opening, snapshot = self.opening(gate, None)
        passed = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        broken = copy.deepcopy(manifest)
        broken["entries"].pop()
        failed = verify_local_consistency(
            broken, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        for name, value in (
            ("manifest", manifest),
            ("pass-result", passed),
            ("fail-result", failed),
        ):
            with self.subTest(value=name):
                self.assertEqual(
                    self.keys(value) & self.BANNED, set()
                )

    def test_co_always_unresolved(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        opening, snapshot = self.opening(gate, None)
        passed = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        broken = copy.deepcopy(manifest)
        broken["entries"].pop()
        failed = verify_local_consistency(
            broken, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        for result in (passed, failed):
            self.assertEqual(result["co"], "unresolved")
            self.assertEqual(
                result["co_reason"], "no_independent_occurrence_evidence"
            )

    def test_unresolved_have_no_identity(self):
        gate = self.make_memory_gate()
        self.keyless_transfer(self, gate)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "unresolved")
        self.assertNotIn("op_key", entry)
        self.assertNotIn("receipt_digest", entry)

    def test_record_shape_mirror_agrees_with_gate(self):
        shapes = [
            {"key": "k", "action": "transfer_money",
             "arg_hash": "h", "actor": "a", "status": "committed",
             "receipt": {"journal_seq": 1}},
            {"key": "k", "action": "transfer_money",
             "arg_hash": "h", "actor": "a", "status": "committed",
             "receipt": None},
            {"key": "k", "action": "transfer_money",
             "arg_hash": "h", "actor": "a", "status": "committed",
             "receipt": []},
            {"key": "k", "action": "transfer_money",
             "arg_hash": "h", "actor": "a", "status": "pending",
             "receipt": None},
            {"key": "k", "action": "transfer_money",
             "arg_hash": "h", "actor": "a", "status": "pending",
             "receipt": {}},
            {"key": "k", "action": "transfer_money",
             "arg_hash": "h", "actor": "a", "status": "weird",
             "receipt": None},
            {"key": "k", "action": "",
             "arg_hash": "h", "actor": "a", "status": "pending",
             "receipt": None},
            {"key": "k", "action": "transfer_money",
             "arg_hash": 7, "actor": "a", "status": "pending",
             "receipt": None},
        ]
        for index, shape in enumerate(shapes):
            with self.subTest(shape=index):
                self.assertEqual(
                    _record_shape_valid(shape),
                    Gate._operation_record_valid(shape),
                )


class LegacyTests(ManifestCase):
    def test_missing_registry_means_unresolved(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, _ = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, [],
            range_start=start, range_end=end,
        )
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "unresolved")
        self.assertNotIn("op_key", entry)
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, [],
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(result, [entry["audit_seq"]])

    def test_deleted_record_end_to_end_sqlite(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "m-a")
        backend.close()
        raw = sqlite3.connect(self.path())
        try:
            raw.execute(
                "DELETE FROM operations WHERE op_key = ?", ("m-a",)
            )
            raw.execute(
                "UPDATE confirmations SET op_key = NULL "
                "WHERE op_key = ?",
                ("m-a",),
            )
            raw.commit()
        finally:
            raw.close()
        gate2, backend2 = self.reopen(backend)
        records, journal, ops = self.evidence(gate2, backend2)
        self.assertEqual(ops, [])
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "unresolved")
        self.assertNotIn("op_key", entry)
        opening, snapshot = self.opening(gate2, backend2)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(result, [entry["audit_seq"]])


class ListOperationsTests(ManifestCase):
    def test_memory_list_operations_ordered_copies(self):
        gate = self.make_memory_gate()
        for key in ("b-key", "a-key"):
            initial = gate.gate({
                "action": "transfer_money", "args": args(),
                "idempotency_key": key,
            })
            self.assertEqual(
                initial["status"], "confirmation_required"
            )
        listed = gate._storage.list_operations()
        self.assertEqual(
            [record["key"] for record in listed],
            ["a-key", "b-key"],
        )
        listed[0]["status"] = "committed"
        listed[0]["receipt"] = {"journal_seq": 1}
        stored = gate._storage.get_operation("a-key")
        self.assertEqual(stored["status"], "pending")
        self.assertIsNone(stored["receipt"])

    def test_sqlite_list_operations_ordered_copies(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "b-key")
        listed = backend.list_operations()
        self.assertEqual([r["key"] for r in listed], ["b-key"])
        listed[0]["receipt"]["amount"] = 9999
        stored = backend.get_operation("b-key")
        self.assertEqual(stored["receipt"]["amount"], 100)
        gate2, backend2 = self.reopen(backend)
        relisted = backend2.list_operations()
        self.assertEqual([r["key"] for r in relisted], ["b-key"])
        self.assertEqual(gate2.operation_status("b-key")["status"],
                         "committed")

    def test_list_operations_empty(self):
        self.assertEqual(
            self.make_memory_gate()._storage.list_operations(), []
        )
        _, backend = self.make_gate()
        self.assertEqual(backend.list_operations(), [])


class AmendmentTests(ManifestCase):
    def test_reconcile_dirty_fails(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        opening, snapshot = self.opening(gate, None)
        snapshot["alice"] -= 1
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("reconcile_dirty", self.codes(result))
        self.assertTrue(result["reconcile_checked"])

    def test_reconcile_skipped_never_passes(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        result = verify_local_consistency(
            manifest, records, journal, ops
        )
        self.assert_pass(result, [])
        self.assertFalse(result["reconcile_checked"])
        self.assertNotIn("reconcile_dirty", self.codes(result))
        self.assertEqual(
            [key for key in result if "clean" in key], []
        )

    def test_cross_check_orphan_fails(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        journal.pop()
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("cross_check_dirty", self.codes(result))

    def test_unencodable_presented_manifest(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        manifest["entries"][0]["amount"] = object()
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("unencodable_manifest", self.codes(result))

    def test_build_unencodable_evidence_raises(self):
        gate = self.make_memory_gate()
        self.keyless_transfer(self, gate)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        tampered = [
            dict(record, policy_version={"not-a-string"})
            if record.get("kind") == "outcome"
            else record
            for record in records
        ]
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                tampered, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "unencodable_entries"
        )

    def test_empty_evidence_inputs(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        with self.assertRaises(ManifestError) as raised:
            build_manifest([], [], [], range_start=1, range_end=1)
        self.assertEqual(raised.exception.problem, "range_uncovered")
        manifest = build_manifest(
            records, journal, ops, range_start=1, range_end=1
        )
        result = verify_local_consistency(manifest, [], [], [])
        self.assertEqual(result["ch"], "fail")
        self.assertIn("history_not_full", self.codes(result))


class RemediationTests(ManifestCase):
    def test_duplicate_keys_rejected_during_build(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        clone = copy.deepcopy(ops[0])
        clone["arg_hash"] = "f" * 64
        ops.append(clone)
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "duplicate_operation_key"
        )

    def test_duplicate_keys_fail_verification(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        clone = copy.deepcopy(ops[0])
        clone["arg_hash"] = "f" * 64
        ops.append(clone)
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("duplicate_operation_key", self.codes(result))

    def test_same_fingerprint_distinct_keys_valid(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "k-one")
        self.keyed_transfer(self, gate, "k-two")
        result, manifest = self.build_and_verify(gate, None)
        self.assertEqual(
            [e["op_key"] for e in manifest["entries"]],
            ["k-one", "k-two"],
        )
        self.assert_pass(result, [])

    def test_huge_range_rejected_promptly(self):
        # Completing at all proves bounded work: enumerating 2**62
        # sequences is physically impossible.
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=1, range_end=2**62,
            )
        self.assertEqual(raised.exception.problem, "range_uncovered")
