"""Unit tests for shared keying-evidence helpers in proofgate.verify.

Slice B, Phase 1. Pure-function tests over synthetic dicts: no backend,
no transactions, no timing. Each helper is specified by its contract:
absent keying evidence means legacy, present evidence must be valid,
and malformed evidence fails closed instead of silently passing.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.canonical import arg_hash
from proofgate.journal import JournalEntry
from proofgate.verify import (
    check_keyed_outcome,
    check_keyless_outcome,
    check_receipt_keying,
    operation_receipt_consistent,
    outcome_keying_state,
)


ACTION = "transfer_money"
ARGS = {"source": "alice", "target": "bob", "amount": 100}
DIGEST = arg_hash(ARGS)

_ABSENT = object()


def base_outcome(seq=5, keyed=_ABSENT, op_key=_ABSENT, **overrides):
    extra = {
        "journal_seq": 1,
        "source_balance": 9900,
        "target_balance": 100,
    }
    if keyed is not _ABSENT:
        extra["keyed"] = keyed
        # Default identity only for keyed markers: a bare keyless
        # fixture must carry no op_key, per the contract.
        if keyed is True and op_key is _ABSENT:
            op_key = "k-1"
        if op_key is not _ABSENT:
            extra["op_key"] = op_key
    record = {
        "kind": "outcome",
        "seq": seq,
        "action": ACTION,
        "arg_hash": DIGEST,
        "policy_version": "v1",
        "decision": "allowed",
        "extra": extra,
    }
    record.update(overrides)
    return record


def base_receipt(op_key=_ABSENT, audit_seq=_ABSENT, **overrides):
    receipt = {
        "action": ACTION,
        "source": "alice",
        "target": "bob",
        "amount": 100,
        "journal_seq": 1,
        "source_balance": 9900,
        "target_balance": 100,
        "policy_version": "v1",
    }
    if op_key is not _ABSENT:
        receipt["op_key"] = op_key
    if audit_seq is not _ABSENT:
        receipt["audit_seq"] = audit_seq
    receipt.update(overrides)
    return receipt


def base_record(key="k-1", status="committed", receipt=_ABSENT):
    if receipt is _ABSENT:
        receipt = base_receipt(op_key=key, audit_seq=5)
    return {
        "key": key,
        "action": ACTION,
        "arg_hash": DIGEST,
        "actor": "agent",
        "status": status,
        "receipt": receipt,
        "created_epoch": 0,
        "updated_epoch": 0,
    }


class KeyingStateTests(unittest.TestCase):
    def test_absent_marker_is_legacy(self):
        self.assertEqual(
            outcome_keying_state(base_outcome()), ("legacy", None)
        )

    def test_keyed_marker(self):
        self.assertEqual(
            outcome_keying_state(base_outcome(keyed=True)),
            ("keyed", "k-1"),
        )

    def test_keyless_marker(self):
        self.assertEqual(
            outcome_keying_state(base_outcome(keyed=False)),
            ("keyless", None),
        )

    def test_keyed_requires_bool(self):
        for bad in (1, 0, "true", None):
            with self.subTest(bad=bad):
                self.assertEqual(
                    outcome_keying_state(base_outcome(keyed=bad)),
                    ("malformed", "keying_malformed"),
                )

    def test_keyed_requires_valid_op_key(self):
        for bad in ("", None, 7, "has space", "x" * 129):
            with self.subTest(bad=bad):
                self.assertEqual(
                    outcome_keying_state(
                        base_outcome(keyed=True, op_key=bad)
                    ),
                    ("malformed", "keying_malformed"),
                )
        missing = base_outcome(keyed=True)
        del missing["extra"]["op_key"]
        self.assertEqual(
            outcome_keying_state(missing),
            ("malformed", "keying_malformed"),
        )

    def test_keyless_forbids_op_key(self):
        for present in ("k-1", None, ""):
            with self.subTest(present=present):
                self.assertEqual(
                    outcome_keying_state(
                        base_outcome(keyed=False, op_key=present)
                    ),
                    ("malformed", "keying_malformed"),
                )

    def test_non_dict_extra_is_malformed(self):
        self.assertEqual(
            outcome_keying_state(base_outcome(extra=None)),
            ("malformed", "bad_outcome_shape"),
        )

    def test_non_dict_outcome_is_malformed(self):
        self.assertEqual(
            outcome_keying_state(None),
            ("malformed", "bad_outcome_shape"),
        )


class KeylessOutcomeTests(unittest.TestCase):
    def test_contradiction_found(self):
        outcome = base_outcome(keyed=False)
        ops = [base_record()]
        self.assertEqual(
            check_keyless_outcome(outcome, ops), "keyless_contradiction"
        )

    def test_distinct_execution_passes(self):
        outcome = base_outcome(keyed=False)
        record = base_record()
        record["receipt"]["journal_seq"] = 2
        self.assertIsNone(check_keyless_outcome(outcome, [record]))

    def test_pending_coexistence_passes(self):
        outcome = base_outcome(keyed=False)
        record = base_record(status="pending", receipt=None)
        self.assertIsNone(check_keyless_outcome(outcome, [record]))

    def test_no_operations_passes(self):
        outcome = base_outcome(keyed=False)
        self.assertIsNone(check_keyless_outcome(outcome, []))

    def test_malformed_journal_seq_fails_closed(self):
        for bad in (0, -1, True, "1", None):
            with self.subTest(bad=bad):
                outcome = base_outcome(keyed=False)
                outcome["extra"]["journal_seq"] = bad
                self.assertEqual(
                    check_keyless_outcome(outcome, []),
                    "bad_outcome_shape",
                )

    def test_malformed_binding_fails_closed(self):
        outcome = base_outcome(keyed=False, action="")
        self.assertEqual(
            check_keyless_outcome(outcome, []), "bad_outcome_shape"
        )
        outcome = base_outcome(keyed=False, arg_hash=None)
        self.assertEqual(
            check_keyless_outcome(outcome, []), "bad_outcome_shape"
        )

    def test_malformed_receipt_row_defers_to_shape_check(self):
        outcome = base_outcome(keyed=False)
        record = base_record()
        record["receipt"]["journal_seq"] = True
        self.assertIsNone(check_keyless_outcome(outcome, [record]))
        self.assertEqual(
            operation_receipt_consistent(
                record["action"], record["arg_hash"],
                record["receipt"], [], [],
            ),
            "bad_receipt_shape",
        )


class ReceiptKeyingTests(unittest.TestCase):
    def test_legacy_pair_skipped(self):
        record = base_record(receipt=base_receipt())
        self.assertIsNone(check_receipt_keying(record, []))

    def test_valid_new_pair(self):
        record = base_record()
        audit = [base_outcome(keyed=True)]
        self.assertIsNone(check_receipt_keying(record, audit))

    def test_exactly_one_field_present_fails(self):
        record = base_record(receipt=base_receipt(op_key="k-1"))
        self.assertEqual(
            check_receipt_keying(record, []),
            "receipt_keying_malformed",
        )
        record = base_record(receipt=base_receipt(audit_seq=5))
        self.assertEqual(
            check_receipt_keying(record, []),
            "receipt_keying_malformed",
        )

    def test_present_none_counts_as_present(self):
        record = base_record(
            receipt=base_receipt(op_key=None, audit_seq=5)
        )
        self.assertEqual(
            check_receipt_keying(record, []), "receipt_key_mismatch"
        )
        record = base_record(
            receipt=base_receipt(op_key="k-1", audit_seq=None)
        )
        self.assertEqual(
            check_receipt_keying(record, []),
            "receipt_position_invalid",
        )

    def test_key_mismatch(self):
        record = base_record(
            receipt=base_receipt(op_key="k-2", audit_seq=5)
        )
        self.assertEqual(
            check_receipt_keying(record, []), "receipt_key_mismatch"
        )
        record = base_record(
            receipt=base_receipt(op_key="bad key", audit_seq=5)
        )
        self.assertEqual(
            check_receipt_keying(record, []), "receipt_key_mismatch"
        )

    def test_invalid_position(self):
        for bad in (0, -2, True, "5"):
            with self.subTest(bad=bad):
                record = base_record(
                    receipt=base_receipt(op_key="k-1", audit_seq=bad)
                )
                self.assertEqual(
                    check_receipt_keying(record, []),
                    "receipt_position_invalid",
                )

    def test_missing_outcome_at_position(self):
        record = base_record()
        self.assertEqual(
            check_receipt_keying(record, []),
            "receipt_position_mismatch",
        )

    def test_non_allowed_target_rejected(self):
        record = base_record()
        audit = [base_outcome(keyed=True, decision="error")]
        self.assertEqual(
            check_receipt_keying(record, audit),
            "receipt_position_mismatch",
        )
        audit = [base_outcome(keyed=True, kind="decision")]
        self.assertEqual(
            check_receipt_keying(record, audit),
            "receipt_position_mismatch",
        )

    def test_legacy_target_rejected(self):
        record = base_record()
        audit = [base_outcome()]
        self.assertEqual(
            check_receipt_keying(record, audit),
            "receipt_position_mismatch",
        )

    def test_wrong_marker_key_rejected(self):
        record = base_record()
        audit = [base_outcome(keyed=True, op_key="k-2")]
        self.assertEqual(
            check_receipt_keying(record, audit),
            "receipt_position_mismatch",
        )

    def test_content_mismatch_rejected(self):
        cases = [
            {"journal_seq": 2},
            {"source_balance": 1},
            {"target_balance": 2},
        ]
        for extra_override in cases:
            with self.subTest(extra_override=extra_override):
                record = base_record()
                outcome = base_outcome(keyed=True)
                outcome["extra"].update(extra_override)
                self.assertEqual(
                    check_receipt_keying(record, [outcome]),
                    "receipt_position_mismatch",
                )
        record = base_record()
        outcome = base_outcome(keyed=True, policy_version="v9")
        self.assertEqual(
            check_receipt_keying(record, [outcome]),
            "receipt_position_mismatch",
        )

    def test_malformed_target_extra_fails_closed(self):
        record = base_record()
        outcome = base_outcome(keyed=True)
        outcome["extra"]["journal_seq"] = "1"
        self.assertEqual(
            check_receipt_keying(record, [outcome]),
            "bad_outcome_shape",
        )

    def test_non_dict_inputs_fail_closed(self):
        self.assertEqual(
            check_receipt_keying(None, []), "bad_operation_shape"
        )
        record = base_record(receipt=None)
        self.assertEqual(
            check_receipt_keying(record, []), "bad_receipt_shape"
        )

    def test_bool_seq_record_never_matches_position(self):
        record = base_record(
            receipt=base_receipt(op_key="k-1", audit_seq=1)
        )
        outcome = base_outcome(keyed=True, seq=True)
        self.assertEqual(
            check_receipt_keying(record, [outcome]),
            "receipt_position_mismatch",
        )


class KeyedOutcomeTests(unittest.TestCase):
    def test_valid_keyed_outcome(self):
        outcome = base_outcome(keyed=True)
        ops = [base_record()]
        self.assertIsNone(
            check_keyed_outcome(outcome, "k-1", ops, [outcome])
        )

    def test_missing_record_orphaned(self):
        outcome = base_outcome(keyed=True)
        self.assertEqual(
            check_keyed_outcome(outcome, "k-1", [], [outcome]),
            "outcome_orphaned",
        )

    def test_pending_record_rejected(self):
        outcome = base_outcome(keyed=True)
        ops = [base_record(status="pending", receipt=None)]
        self.assertEqual(
            check_keyed_outcome(outcome, "k-1", ops, [outcome]),
            "keyed_pending",
        )

    def test_non_dict_receipt_rejected(self):
        outcome = base_outcome(keyed=True)
        ops = [base_record(receipt=None)]
        self.assertEqual(
            check_keyed_outcome(outcome, "k-1", ops, [outcome]),
            "bad_receipt_shape",
        )

    def test_legacy_receipt_with_marker_rejected(self):
        outcome = base_outcome(keyed=True)
        ops = [base_record(receipt=base_receipt())]
        self.assertEqual(
            check_keyed_outcome(outcome, "k-1", ops, [outcome]),
            "keyed_legacy_receipt",
        )

    def test_receipt_pinned_to_other_position_rejected(self):
        outcome = base_outcome(keyed=True)
        other = base_outcome(seq=9, keyed=True)
        record = base_record(
            receipt=base_receipt(op_key="k-1", audit_seq=9)
        )
        self.assertEqual(
            check_keyed_outcome(
                outcome, "k-1", [record], [outcome, other]
            ),
            "receipt_position_mismatch",
        )

    def test_duplicate_keys_rejected(self):
        outcome = base_outcome(keyed=True)
        ops = [base_record(), base_record()]
        self.assertEqual(
            check_keyed_outcome(outcome, "k-1", ops, [outcome]),
            "duplicate_operation_key",
        )

    def test_malformed_outcome_rejected(self):
        self.assertEqual(
            check_keyed_outcome(None, "k-1", [], []),
            "bad_outcome_shape",
        )
        outcome = base_outcome(keyed=True, seq="5")
        self.assertEqual(
            check_keyed_outcome(
                outcome, "k-1", [base_record()], [outcome]
            ),
            "bad_outcome_shape",
        )

    def test_mismatched_caller_identity_rejected(self):
        outcome = base_outcome(keyed=True)
        record = base_record(
            key="k-2",
            receipt=base_receipt(op_key="k-2", audit_seq=5),
        )
        self.assertEqual(
            check_keyed_outcome(outcome, "k-2", [record], [outcome]),
            "receipt_position_mismatch",
        )

    def test_garbage_status_rejected(self):
        outcome = base_outcome(keyed=True)
        record = base_record(receipt=base_receipt())
        record["status"] = "weird"
        self.assertEqual(
            check_keyed_outcome(
                outcome, "k-1", [record], [outcome]
            ),
            "keyed_pending",
        )


class ScanRobustnessTests(unittest.TestCase):
    def test_non_dict_operation_rows_skipped(self):
        outcome = base_outcome(keyed=False)
        self.assertIsNone(
            check_keyless_outcome(outcome, [None, "k-1", 7])
        )

    def test_non_dict_rows_never_match_identity(self):
        outcome = base_outcome(keyed=True)
        self.assertEqual(
            check_keyed_outcome(
                outcome, "k-1", [None, "k-1"], [outcome]
            ),
            "outcome_orphaned",
        )

    def test_non_dict_audit_rows_skipped(self):
        record = base_record()
        self.assertEqual(
            check_receipt_keying(record, [None, "x"]),
            "receipt_position_mismatch",
        )


class KeyingCompositionTests(unittest.TestCase):
    def test_full_triple_passes_both_checks(self):
        outcome = base_outcome(keyed=True)
        record = base_record()
        journal = [
            JournalEntry(1, ACTION, "alice", "bob", 100)
        ]
        self.assertIsNone(
            operation_receipt_consistent(
                record["action"], record["arg_hash"],
                record["receipt"], journal, [outcome],
            )
        )
        self.assertIsNone(
            check_keyed_outcome(
                outcome, "k-1", [record], [outcome]
            )
        )
        self.assertIsNone(check_receipt_keying(record, [outcome]))

    def test_tampered_balances_fail_both_checks(self):
        outcome = base_outcome(keyed=True)
        outcome["extra"]["source_balance"] = 1
        record = base_record()
        journal = [
            JournalEntry(1, ACTION, "alice", "bob", 100)
        ]
        self.assertEqual(
            operation_receipt_consistent(
                record["action"], record["arg_hash"],
                record["receipt"], journal, [outcome],
            ),
            "outcome_missing",
        )
        self.assertEqual(
            check_receipt_keying(record, [outcome]),
            "receipt_position_mismatch",
        )
