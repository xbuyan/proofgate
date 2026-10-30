"""Local manifest tests: enumeration consistency over audit history.

Slice A established v1 manifests: eligible ``allowed`` OUTCOME records
enumerated over a range, C-H only, ``co`` always ``unresolved``.
Slice B adds v2 (default): marker-bearing records use explicit keying
evidence (``keyed``/``keyless`` via the shared helpers), legacy
records keep the guarded fingerprint join, and v1 is frozen
explicit opt-in over marker-free histories only.
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

from proofgate.canonical import arg_hash, canonicalize
from proofgate.enforcement import Gate
from proofgate.manifests import (
    MANIFEST_VERSION,
    MANIFEST_VERSION_V2,
    ManifestError,
    _record_shape_valid,
    build_manifest,
    verify_local_consistency,
)
from proofgate.policy import Policy
from proofgate.sqlite_backend import SQLiteBackend
from proofgate.sqlite_backend import _Mutator as SQLiteMutator
from proofgate.tools import transfer_money as apply_transfer


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
    if manifest["format_version"] == MANIFEST_VERSION_V2:
        header["keyless_count"] = manifest["keyless_count"]
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
    if manifest["format_version"] == MANIFEST_VERSION_V2:
        manifest["keyless_count"] = sum(
            1 for e in entries if e.get("classification") == "keyless"
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

    def assert_pass(self, result, unresolved, exact_ids=None):
        """Every C-H PASS also pins C-O unresolved and the listing.

        v2 rules are required. ``exact_ids`` defaults to ``not
        unresolved`` (all-keyed ranges); keyless-bearing ranges pass
        ``False`` explicitly since keyless entries carry no op_key.
        """
        self.assertEqual(result["rules"], "v2")
        self.assertEqual(result["ch"], "pass")
        self.assertEqual(result["ch_problems"], [])
        self.assertEqual(result["co"], "unresolved")
        self.assertEqual(
            result["co_reason"], "no_independent_occurrence_evidence"
        )
        self.assertEqual(result["unresolved_entries"], unresolved)
        if exact_ids is None:
            exact_ids = not unresolved
        self.assertEqual(result["exact_ids_available"], exact_ids)
        self.assertEqual(
            result["identity_dispositions_complete"], not unresolved
        )
        self.assertEqual(result["deployment_bound"], False)

    def assert_pass_v1(self, result, unresolved):
        """Frozen v1 pass: legacy rules label, v1-only fields."""
        self.assertEqual(result["rules"], "v1-legacy")
        self.assertEqual(result["ch"], "pass")
        self.assertEqual(result["ch_problems"], [])
        self.assertEqual(result["co"], "unresolved")
        self.assertEqual(
            result["co_reason"], "no_independent_occurrence_evidence"
        )
        self.assertEqual(result["unresolved_entries"], unresolved)
        self.assertEqual(result["exact_ids_available"], not unresolved)
        self.assertNotIn("identity_dispositions_complete", result)
        self.assertEqual(result["deployment_bound"], False)

    def codes(self, result):
        return [p["code"] for p in result["ch_problems"]]

    def backends(self):
        """Yield (label, gate, backend-or-None) for both backends."""
        gate, backend = self.make_gate()
        yield "sqlite", gate, backend
        yield "memory", self.make_memory_gate(), None

    def craft_legacy_memory(self, gate, key="m-leg", amount=25,
                            target="carol", register=True):
        """Append one marker-free legacy execution (Memory backend).

        Mirrors the SQLite legacy fixture via backend APIs only: the
        OUTCOME extra holds journal/ledger fields alone and the
        receipt (when registered) holds neither op_key nor audit_seq.
        Returns the receipt, or None when unregistered.
        """
        storage = gate._storage
        digest = arg_hash(args(amount, target))
        with storage.transaction():
            new_source, new_target = apply_transfer(
                storage.mutator(), "alice", target, amount
            )
            entry = storage.journal.append_transfer(
                "alice", target, amount
            )
            storage.audit.append(
                kind="decision", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1",
                decision="confirmation_required", reason="ok",
                token_id="deadbeef", extra={},
            )
            storage.audit.append(
                kind="authorized", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1", decision="authorized",
                reason="ok", token_id="deadbeef", extra={},
            )
            storage.audit.append(
                kind="outcome", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1", decision="allowed",
                reason="ok", token_id="deadbeef",
                extra={
                    "journal_seq": entry.seq,
                    "source_balance": new_source,
                    "target_balance": new_target,
                },
            )
            receipt = {
                "action": "transfer_money", "source": "alice",
                "target": target, "amount": amount,
                "journal_seq": entry.seq,
                "source_balance": new_source,
                "target_balance": new_target,
                "policy_version": "v1",
            }
            if register:
                storage.register_operation(
                    key, "transfer_money", digest, "agent"
                )
                storage.complete_operation(key, receipt)
        return receipt if register else None


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
                    manifest["format_version"], MANIFEST_VERSION_V2
                )
                self.assertEqual(
                    [e["op_key"] for e in manifest["entries"]],
                    ["m-a", "m-b"],
                )
                self.assertEqual(
                    [e["keying_source"] for e in manifest["entries"]],
                    ["marker", "marker"],
                )
                self.assertEqual(manifest["keyed_count"], 2)
                self.assertEqual(manifest["keyless_count"], 0)
                self.assertEqual(manifest["unresolved_count"], 0)
                self.assertEqual(len(manifest["manifest_digest"]), 64)
                self.assertTrue(result["reconcile_checked"])

    def test_keyless_outcome_explicit(self):
        for label, gate, backend in self.backends():
            with self.subTest(backend=label):
                self.keyless_transfer(self, gate)
                result, manifest = self.build_and_verify(gate, backend)
                (entry,) = manifest["entries"]
                self.assertEqual(
                    entry["classification"], "keyless"
                )
                self.assertEqual(entry["keying_source"], "marker")
                self.assertNotIn("op_key", entry)
                self.assertNotIn("receipt_digest", entry)
                self.assertEqual(manifest["keyless_count"], 1)
                self.assertEqual(manifest["unresolved_count"], 0)
                self.assert_pass(result, [], exact_ids=False)

    def test_mixed_history_counts(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyless_transfer(self, gate, amount=50, target="carol")
        result, manifest = self.build_and_verify(gate, backend)
        self.assertEqual(manifest["op_count"], 2)
        self.assertEqual(manifest["keyed_count"], 1)
        self.assertEqual(manifest["keyless_count"], 1)
        self.assertEqual(manifest["unresolved_count"], 0)
        self.assert_pass(result, [], exact_ids=False)

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
        # identical arguments is legitimate: the keyless marker
        # proves the OUTCOME claims no operation, so the pending
        # record is coexistence, not conflict.
        gate = self.make_memory_gate()
        initial = gate.gate({
            "action": "transfer_money", "args": args(),
            "idempotency_key": "m-pending",
        })
        self.assertEqual(initial["status"], "confirmation_required")
        self.keyless_transfer(self, gate)
        result, manifest = self.build_and_verify(gate, None)
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "keyless")
        self.assertEqual(entry["keying_source"], "marker")
        self.assert_pass(result, [], exact_ids=False)

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

    def test_cloned_receipt_key_mismatch(self):
        # A cloned operation row reuses another operation's keyed
        # receipt: v2 detects the identity mismatch on the reverse
        # check even though the receipt content is otherwise valid.
        (manifest, records, journal, ops, opening, snapshot) = self.clean()
        clone = copy.deepcopy(ops[0])
        clone["key"] = "m-clone"
        ops.append(clone)
        result = self.verify(
            manifest, records, journal, ops, opening, snapshot
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("receipt_key_mismatch", self.codes(result))
        start, end = self.full_range(records)
        rebuilt = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end,
        )
        self.assertEqual(
            [e["op_key"] for e in rebuilt["entries"]],
            ["m-a", "m-b"],
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

    def test_keyless_have_no_identity(self):
        gate = self.make_memory_gate()
        self.keyless_transfer(self, gate)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "keyless")
        self.assertEqual(entry["keying_source"], "marker")
        self.assertNotIn("op_key", entry)
        self.assertNotIn("receipt_digest", entry)

    def test_unresolved_have_no_identity(self):
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate, register=False)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops, range_start=start, range_end=end
        )
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "unresolved")
        self.assertEqual(entry["keying_source"], "legacy-join")
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
        # A marker-absent legacy OUTCOME with no operation rows is
        # genuinely indeterminable: unresolved, never keyed, C-H pass.
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate, register=False)
        records, journal, _ = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, [],
            range_start=start, range_end=end,
        )
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "unresolved")
        self.assertEqual(entry["keying_source"], "legacy-join")
        self.assertNotIn("op_key", entry)
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, [],
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(result, [entry["audit_seq"]])

    def test_keyed_outcome_missing_registry_orphaned(self):
        # The same missing-registry input against a Slice B keyed
        # marker is an orphaned OUTCOME, not an unresolved one.
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, _ = self.evidence(gate, None)
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, [],
                range_start=start, range_end=end,
            )
        self.assertEqual(raised.exception.problem, "outcome_orphaned")

    def test_deleted_record_end_to_end_sqlite(self):
        # Genuine legacy history: the OUTCOME and receipt below
        # carry no keying evidence at all (pre-Slice-B shape), so
        # deleting the operation row exercises legacy-unresolved
        # handling rather than keyed-tamper refusal.
        _, backend = self.make_gate()
        digest = arg_hash(args())
        with backend.transaction():
            SQLiteMutator(backend.ledger).apply_transfer(
                "alice", "bob", 100
            )
            entry = backend.journal.append_transfer(
                "alice", "bob", 100
            )
            backend.audit.append(
                kind="decision", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1",
                decision="confirmation_required", reason="ok",
                token_id="deadbeef", extra={},
            )
            backend.audit.append(
                kind="authorized", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1", decision="authorized",
                reason="ok", token_id="deadbeef", extra={},
            )
            backend.audit.append(
                kind="outcome", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1", decision="allowed",
                reason="ok", token_id="deadbeef",
                extra={
                    "journal_seq": entry.seq,
                    "source_balance": backend.ledger.balance("alice"),
                    "target_balance": backend.ledger.balance("bob"),
                },
            )
            backend.register_operation(
                "m-a", "transfer_money", digest, "agent"
            )
            backend.complete_operation("m-a", {
                "action": "transfer_money", "source": "alice",
                "target": "bob", "amount": 100,
                "journal_seq": entry.seq,
                "source_balance": backend.ledger.balance("alice"),
                "target_balance": backend.ledger.balance("bob"),
                "policy_version": "v1",
            })
            backend.confirmations.issue(
                "transfer_money", digest, "v1"
            )
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
        outcomes = [
            record for record in gate2.audit_records()
            if record["kind"] == "outcome"
            and record["decision"] == "allowed"
        ]
        (outcome,) = outcomes
        self.assertNotIn("keyed", outcome["extra"])
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


class ManifestV2Tests(ManifestCase):
    def test_keyed_marker_entry_shape(self):
        gate = self.make_memory_gate()
        receipt = self.keyed_transfer(self, gate, "m-a")
        result, manifest = self.build_and_verify(gate, None)
        self.assert_pass(result, [])
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "keyed")
        self.assertEqual(entry["keying_source"], "marker")
        self.assertEqual(entry["op_key"], "m-a")
        self.assertEqual(
            entry["journal_seq"], receipt["journal_seq"]
        )
        self.assertEqual(len(entry["receipt_digest"]), 64)
        self.assertEqual(entry["amount"], 100)

    def test_mixed_three_way_history(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyless_transfer(self, gate, amount=50, target="carol")
        self.craft_legacy_memory(gate)
        result, manifest = self.build_and_verify(gate, None)
        self.assert_pass(result, [], exact_ids=False)
        self.assertEqual(
            [e["classification"] for e in manifest["entries"]],
            ["keyed", "keyless", "keyed"],
        )
        self.assertEqual(
            [e["keying_source"] for e in manifest["entries"]],
            ["marker", "marker", "legacy-join"],
        )
        self.assertEqual(manifest["keyed_count"], 2)
        self.assertEqual(manifest["keyless_count"], 1)
        self.assertEqual(manifest["unresolved_count"], 0)
        self.assertEqual(manifest["entries"][2]["op_key"], "m-leg")

    def test_legacy_resolved_via_guarded_join(self):
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate)
        result, manifest = self.build_and_verify(gate, None)
        self.assert_pass(result, [])
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "keyed")
        self.assertEqual(entry["keying_source"], "legacy-join")
        self.assertEqual(entry["op_key"], "m-leg")

    def test_legacy_outcome_cannot_borrow_keyed_receipt(self):
        # Counterexample A: a forged legacy OUTCOME shares the live
        # keyed receipt's (action, arg_hash, journal_seq) but carries
        # different balances. The receipt is excluded from the legacy
        # join, so the forged OUTCOME stays unresolved -- never m-a.
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        storage = gate._storage
        digest = arg_hash(args())
        with storage.transaction():
            forged = storage.audit.append(
                kind="outcome", actor="agent",
                action="transfer_money", arg_hash=digest,
                policy_version="v1", decision="allowed",
                reason="ok", token_id="deadbeef",
                extra={
                    "journal_seq": 1,
                    "source_balance": 0,
                    "target_balance": 0,
                },
            )
        records, journal, ops = self.evidence(gate, None)
        self.assertNotIn("keyed", forged["extra"])
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end,
        )
        by_seq = {e["audit_seq"]: e for e in manifest["entries"]}
        self.assertEqual(by_seq[forged["seq"]]["classification"],
                         "unresolved")
        self.assertNotIn("op_key", by_seq[forged["seq"]])
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(result, [forged["seq"]])
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end, format_version=1,
            )
        self.assertEqual(
            raised.exception.problem, "marker_history_requires_v2"
        )

    def test_legacy_duplicate_binding_preserved(self):
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate)
        records, journal, ops = self.evidence(gate, None)
        clone = copy.deepcopy(ops[0])
        clone["key"] = "m-clone"
        ops.append(clone)
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "duplicate_operation_binding"
        )

    def test_malformed_marker_build_raises(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        for record in records:
            if record.get("kind") == "outcome":
                record["extra"]["keyed"] = "yes"
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "keying_malformed"
        )

    def test_partial_receipt_pair_fails_closed(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        del ops[0]["receipt"]["audit_seq"]
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "keyed_legacy_receipt"
        )
        records2, journal2, ops2 = self.evidence(gate, None)
        manifest = build_manifest(
            records2, journal2, ops2,
            range_start=start, range_end=end,
        )
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("receipt_keying_malformed", self.codes(result))
        self.assertIn("keyed_legacy_receipt", self.codes(result))

    def test_nondict_receipt_rejected(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        ops[0]["receipt"] = ["not", "a", "dict"]
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "bad_receipt_shape"
        )

    def test_keyed_pending_build_raises(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        ops[0]["status"] = "pending"
        ops[0]["receipt"] = None
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(raised.exception.problem, "keyed_pending")

    def test_wrong_position_receipt_refused(self):
        # Swapped audit positions: receipt content still matches its
        # own OUTCOME exactly once, so only the position binding
        # catches the forgery.
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyed_transfer(self, gate, "m-b", amount=50)
        records, journal, ops = self.evidence(gate, None)
        seq_a = ops[0]["receipt"]["audit_seq"]
        ops[0]["receipt"]["audit_seq"] = ops[1]["receipt"][
            "audit_seq"
        ]
        ops[1]["receipt"]["audit_seq"] = seq_a
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError):
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        records2, journal2, ops2 = self.evidence(gate, None)
        manifest = build_manifest(
            records2, journal2, ops2,
            range_start=start, range_end=end,
        )
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("receipt_position_mismatch", self.codes(result))
        self.assertNotIn("outcome_missing", self.codes(result))
        self.assertNotIn("ambiguous_outcome", self.codes(result))

    def test_duplicate_position_two_receipts_refused(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyed_transfer(self, gate, "m-b", amount=50)
        records, journal, ops = self.evidence(gate, None)
        ops[1]["receipt"]["audit_seq"] = ops[0]["receipt"][
            "audit_seq"
        ]
        records2, journal2, ops2 = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records2, journal2, ops2,
            range_start=start, range_end=end,
        )
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("receipt_position_mismatch", self.codes(result))

    def test_keyless_contradiction_build_raises(self):
        gate = self.make_memory_gate()
        self.keyless_transfer(self, gate)
        records, journal, ops = self.evidence(gate, None)
        outcome = next(
            r for r in records
            if r.get("kind") == "outcome"
            and r.get("decision") == "allowed"
        )
        ops.append({
            "key": "m-squat", "action": outcome["action"],
            "arg_hash": outcome["arg_hash"], "actor": "agent",
            "status": "committed",
            "receipt": {"journal_seq": outcome["extra"][
                "journal_seq"]},
            "created_epoch": 0, "updated_epoch": 0,
        })
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end,
            )
        self.assertEqual(
            raised.exception.problem, "keyless_contradiction"
        )

    def test_out_of_range_position_still_validated(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyed_transfer(self, gate, "m-b", amount=50)
        records, journal, ops = self.evidence(gate, None)
        seqs = sorted(
            r["seq"] for r in records
            if r.get("kind") == "outcome"
            and r.get("decision") == "allowed"
        )
        manifest = build_manifest(
            records, journal, ops,
            range_start=seqs[1], range_end=seqs[1],
        )
        self.assertEqual(
            [e["op_key"] for e in manifest["entries"]], ["m-b"]
        )
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(result, [])

    def test_out_of_range_tamper_still_refused(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyed_transfer(self, gate, "m-b", amount=50)
        records, journal, ops = self.evidence(gate, None)
        seqs = sorted(
            r["seq"] for r in records
            if r.get("kind") == "outcome"
            and r.get("decision") == "allowed"
        )
        manifest = build_manifest(
            records, journal, ops,
            range_start=seqs[1], range_end=seqs[1],
        )
        ops[0]["receipt"]["audit_seq"] = seqs[1]
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("receipt_position_mismatch", self.codes(result))

    def test_committed_keyed_plus_keyless_same_args(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        self.keyless_transfer(self, gate)
        result, manifest = self.build_and_verify(gate, None)
        self.assert_pass(result, [], exact_ids=False)
        self.assertEqual(
            [e["classification"] for e in manifest["entries"]],
            ["keyed", "keyless"],
        )

    def test_identity_fields_truth_table(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        keyed, _ = self.build_and_verify(gate, None)
        self.assertTrue(keyed["exact_ids_available"])
        self.assertTrue(keyed["identity_dispositions_complete"])
        gate2 = self.make_memory_gate()
        self.keyless_transfer(self, gate2)
        keyless, _ = self.build_and_verify(gate2, None)
        self.assertFalse(keyless["exact_ids_available"])
        self.assertTrue(keyless["identity_dispositions_complete"])
        gate3 = self.make_memory_gate()
        self.craft_legacy_memory(gate3, register=False)
        legacy, _ = self.build_and_verify(gate3, None)
        self.assertFalse(legacy["exact_ids_available"])
        self.assertFalse(legacy["identity_dispositions_complete"])
        records, journal, ops = self.evidence(gate, None)
        empty = build_manifest(
            records, journal, ops, range_start=1, range_end=1
        )
        opening, snapshot = self.opening(gate, None)
        vacuous = verify_local_consistency(
            empty, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assert_pass(vacuous, [])
        self.assertTrue(vacuous["identity_dispositions_complete"])

    def test_pending_receipt_with_keying_fields(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        ops.append({
            "key": "pending-bad", "action": "transfer_money",
            "arg_hash": "0" * 64, "actor": "tester",
            "status": "pending",
            "receipt": {"op_key": "pending-bad", "audit_seq": 1},
            "created_epoch": 0, "updated_epoch": 0,
        })
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end,
        )
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("pending_receipt", self.codes(result))

    def test_partial_pair_excluded_from_legacy_join(self):
        # A legacy OUTCOME sharing a triple with a partial-pair
        # receipt stays unresolved (guard excludes either field),
        # while verification still fails the malformed evidence.
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate, register=False)
        records, journal, ops = self.evidence(gate, None)
        outcome = next(
            r for r in records
            if r.get("kind") == "outcome"
            and r.get("decision") == "allowed"
        )
        ops.append({
            "key": "m-partial", "action": outcome["action"],
            "arg_hash": outcome["arg_hash"], "actor": "agent",
            "status": "committed",
            "receipt": {
                "op_key": "m-partial",
                "journal_seq": outcome["extra"]["journal_seq"],
            },
            "created_epoch": 0, "updated_epoch": 0,
        })
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end,
        )
        (entry,) = manifest["entries"]
        self.assertEqual(entry["classification"], "unresolved")
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn("receipt_keying_malformed", self.codes(result))


class V1PolicyTests(ManifestCase):
    def test_build_defaults_to_v2(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end,
        )
        self.assertEqual(
            manifest["format_version"], MANIFEST_VERSION_V2
        )

    def test_v1_build_and_verify_legacy_history(self):
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end, format_version=1,
        )
        self.assertEqual(
            manifest["format_version"], MANIFEST_VERSION
        )
        self.assertNotIn("keyless_count", manifest)
        (entry,) = manifest["entries"]
        self.assertNotIn("keying_source", entry)
        self.assertEqual(entry["classification"], "keyed")
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
            allow_legacy_v1=True,
        )
        self.assert_pass_v1(result, [])

    def test_v1_build_refuses_marked_histories(self):
        gate = self.make_memory_gate()
        self.keyed_transfer(self, gate, "m-a")
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end, format_version=1,
            )
        self.assertEqual(
            raised.exception.problem, "marker_history_requires_v2"
        )
        keyless = self.make_memory_gate()
        self.keyless_transfer(self, keyless)
        records, journal, ops = self.evidence(keyless, None)
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end, format_version=1,
            )
        self.assertEqual(
            raised.exception.problem, "marker_history_requires_v2"
        )
        legacy = self.make_memory_gate()
        self.craft_legacy_memory(legacy, register=False)
        records, journal, ops = self.evidence(legacy, None)
        ops.append({
            "key": "pending-bad", "action": "transfer_money",
            "arg_hash": "0" * 64, "actor": "tester",
            "status": "pending",
            "receipt": {"op_key": "pending-bad"},
            "created_epoch": 0, "updated_epoch": 0,
        })
        start, end = self.full_range(records)
        with self.assertRaises(ManifestError) as raised:
            build_manifest(
                records, journal, ops,
                range_start=start, range_end=end, format_version=1,
            )
        self.assertEqual(
            raised.exception.problem, "marker_history_requires_v2"
        )

    def test_v1_verify_requires_opt_in(self):
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end, format_version=1,
        )
        opening, snapshot = self.opening(gate, None)
        with self.assertRaises(ManifestError) as raised:
            verify_local_consistency(
                manifest, records, journal, ops,
                opening_balances=opening, ledger_snapshot=snapshot,
            )
        self.assertEqual(
            raised.exception.problem, "legacy_verification_not_enabled"
        )

    def test_v1_verify_refuses_marked_history(self):
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end, format_version=1,
        )
        marked = [dict(r) for r in records]
        for record in marked:
            if record.get("kind") == "outcome":
                record["extra"] = dict(
                    record["extra"], keyed=False
                )
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, marked, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
            allow_legacy_v1=True,
        )
        self.assertEqual(result["ch"], "fail")
        self.assertIn(
            "marker_history_requires_v2", self.codes(result)
        )
        self.assertEqual(result["rules"], "v1-legacy")

    def test_v1_result_shape_frozen(self):
        gate = self.make_memory_gate()
        self.craft_legacy_memory(gate)
        records, journal, ops = self.evidence(gate, None)
        start, end = self.full_range(records)
        manifest = build_manifest(
            records, journal, ops,
            range_start=start, range_end=end, format_version=1,
        )
        self.assertEqual(
            set(manifest),
            {
                "format_version", "range_start", "range_end",
                "op_count", "keyed_count", "unresolved_count",
                "entries", "entries_root", "manifest_digest",
            },
        )
        opening, snapshot = self.opening(gate, None)
        result = verify_local_consistency(
            manifest, records, journal, ops,
            opening_balances=opening, ledger_snapshot=snapshot,
            allow_legacy_v1=True,
        )
        self.assertEqual(
            set(result),
            {
                "rules", "ch", "ch_problems", "co", "co_reason",
                "entries", "unresolved_entries",
                "exact_ids_available", "manifest_digest",
                "deployment_bound", "reconcile_checked",
            },
        )
