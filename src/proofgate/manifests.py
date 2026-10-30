"""Local operation manifests: enumeration consistency over audit history.

Slice A. A manifest enumerates the eligible ``allowed`` OUTCOME records in
an audit range and classifies each as keyed (bound to a committed operation
record) or unresolved (no operation record; keying indeterminable from
current data). Verification establishes C-H only: the manifest faithfully
represents the eligible records of a verified local history. It never
establishes C-O, independent retention, freshness, or finality, and the
result vocabulary is shaped so those claims cannot be implied: ``co`` is
always ``unresolved`` and no combined status field exists.

Both entry points are pure functions over caller snapshots. They never
mutate backend state. Content findings are returned as problem codes;
only malformed input shapes raise :class:`ManifestError`.

Responsibility split: :func:`build_manifest` transcribes eligible
records (range coverage, outcome shapes, journal linkage, duplicate
linkage). It does not verify the chain, reconcile, cross-check, or
check receipt-value bindings (fingerprint, balances, policy-version
agreement); :func:`verify_local_consistency` establishes all of those.

Reconciliation runs only when opening balances and a ledger snapshot
are supplied; ``reconcile_checked`` reports whether it ran. A skipped
reconciliation is never represented as passed: no problem code passes
for it, and the flag reads False.

Pending operation rows never conflict with OUTCOME records: a pending
request legitimately coexists with a keyless same-args execution, so
coexistence reports unresolved. A committed-to-pending status flip is
therefore indistinguishable from that legitimate case in Slice A
evidence and likewise degrades to unresolved; detecting it needs
OUTCOME keying evidence (a later slice).
"""

import copy
import hashlib

from .audit import _verify_chain
from .canonical import CanonicalizationError, canonicalize
from .verify import (
    cross_check_journal_audit,
    operation_receipt_consistent,
    reconcile,
)

__all__ = [
    "MANIFEST_VERSION",
    "ManifestError",
    "build_manifest",
    "verify_local_consistency",
]

MANIFEST_VERSION = 1

CO_UNRESOLVED = "unresolved"
CO_REASON_NO_EVIDENCE = "no_independent_occurrence_evidence"


class ManifestError(Exception):
    """Malformed manifest or evidence input (programmer error)."""

    def __init__(self, problem, detail=None):
        super().__init__(problem)
        self.problem = problem
        self.detail = detail or {}


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _problem(code, **detail):
    found = {"code": code}
    found.update(detail)
    return found


def _digest(obj):
    """Return hex SHA-256 of canonical bytes, or None if unencodable."""
    try:
        return hashlib.sha256(canonicalize(obj)).hexdigest()
    except (CanonicalizationError, RecursionError):
        return None


def _require_records(audit_records):
    if not isinstance(audit_records, (list, tuple)):
        raise ManifestError("bad_audit_records", {"expected": "sequence"})
    records = list(audit_records)
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ManifestError(
                "bad_audit_records", {"index": index}
            )
    return records


def _require_journal(journal_entries):
    if not isinstance(journal_entries, (list, tuple)):
        raise ManifestError("bad_journal_entries", {"expected": "sequence"})
    entries = list(journal_entries)
    for entry in entries:
        for field in ("seq", "action", "source", "target", "amount"):
            if not hasattr(entry, field):
                raise ManifestError(
                    "bad_journal_entries", {"missing_field": field}
                )
    return entries


def _require_operations(operations):
    if not isinstance(operations, (list, tuple)):
        raise ManifestError("bad_operations", {"expected": "sequence"})
    records = list(operations)
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ManifestError("bad_operations", {"index": index})
    return records


def _require_range(range_start, range_end):
    if (
        not _is_int(range_start)
        or not _is_int(range_end)
        or range_start < 1
        or range_end < range_start
    ):
        raise ManifestError(
            "bad_range",
            {"range_start": range_start, "range_end": range_end},
        )


def _require_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ManifestError("bad_manifest", {"expected": "dict"})
    if manifest.get("format_version") != MANIFEST_VERSION or isinstance(
        manifest.get("format_version"), bool
    ):
        raise ManifestError(
            "unsupported_manifest_version",
            {"found": manifest.get("format_version")},
        )
    try:
        _require_range(manifest.get("range_start"), manifest.get("range_end"))
    except ManifestError as exc:
        raise ManifestError("bad_manifest_range", exc.detail) from exc
    entries = manifest.get("entries")
    if not isinstance(entries, (list, tuple)):
        raise ManifestError("bad_manifest_entries", {"expected": "list"})
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not _is_int(
            entry.get("audit_seq")
        ):
            raise ManifestError(
                "bad_manifest_entries", {"index": index}
            )
    for key in ("op_count", "keyed_count", "unresolved_count"):
        value = manifest.get(key)
        if not _is_int(value) or value < 0:
            raise ManifestError("bad_manifest_counts", {"key": key})
    for key in ("entries_root", "manifest_digest"):
        if not isinstance(manifest.get(key), str):
            raise ManifestError("bad_manifest_digests", {"key": key})


def _record_shape_valid(record):
    """Mirror of ``Gate._operation_record_valid`` (pinned by cross-test).

    Deliberately fail-closed where the gate version would raise: a
    missing ``status`` is invalid here rather than a ``KeyError``.
    Committed records additionally require a nonempty string key,
    since a manifest cannot report an identity it was not given.
    """
    status = record.get("status")
    if status == "committed":
        receipt_ok = isinstance(record.get("receipt"), dict)
        key_ok = isinstance(record.get("key"), str) and bool(
            record.get("key")
        )
    elif status == "pending":
        receipt_ok = record.get("receipt") is None
        key_ok = isinstance(record.get("key"), str) and bool(
            record.get("key")
        )
    else:
        return False
    return (
        isinstance(record.get("action"), str)
        and bool(record.get("action"))
        and isinstance(record.get("arg_hash"), str)
        and bool(record.get("arg_hash"))
        and receipt_ok
        and key_ok
    )


def _eligible_outcomes(records, range_start, range_end):
    """Allowed OUTCOME records in range, ordered by audit seq."""
    return sorted(
        (
            record
            for record in records
            if record.get("kind") == "outcome"
            and record.get("decision") == "allowed"
            and _is_int(record.get("seq"))
            and range_start <= record["seq"] <= range_end
        ),
        key=lambda record: record["seq"],
    )


def _classify(outcome, journal_by_seq, operations):
    """Classify one eligible OUTCOME.

    Returns ``(entry_or_None, problem_or_None)``. A keyed entry needs a
    committed record matching action, argument hash, and journal
    sequence. Anything else is unresolved or inconsistent; keying is
    never inferred. The token-id prefix is deliberately ignored: it is
    non-unique and its rows are purged or cleared while operation
    records survive, so it cannot serve as join evidence.
    """
    seq = outcome["seq"]
    extra = outcome.get("extra")
    if (
        not isinstance(extra, dict)
        or not _is_int(extra.get("journal_seq"))
        or extra["journal_seq"] < 1
    ):
        return None, _problem("bad_outcome_shape", audit_seq=seq)
    action = outcome.get("action")
    arg_hash = outcome.get("arg_hash")
    journal_seq = extra["journal_seq"]
    journal = journal_by_seq.get(journal_seq)
    if journal is None:
        return None, _problem(
            "journal_gap", audit_seq=seq, journal_seq=journal_seq
        )
    if journal.action != action:
        return None, _problem(
            "journal_mismatch", audit_seq=seq, journal_seq=journal_seq
        )
    matches = [
        record
        for record in operations
        if record.get("status") == "committed"
        and isinstance(record.get("key"), str)
        and bool(record.get("key"))
        and record.get("action") == action
        and record.get("arg_hash") == arg_hash
        and isinstance(record.get("receipt"), dict)
        and record["receipt"].get("journal_seq") == journal_seq
    ]
    if len(matches) > 1:
        return None, _problem(
            "duplicate_operation_binding",
            audit_seq=seq,
            journal_seq=journal_seq,
            keys=sorted(record["key"] for record in matches),
        )
    if len(matches) == 1:
        record = matches[0]
        receipt = record["receipt"]
        digest = _digest(receipt)
        if digest is None:
            return None, _problem(
                "bad_receipt_shape",
                key=record["key"],
                audit_seq=seq,
            )
        return {
            "audit_seq": seq,
            "op_key": record["key"],
            "action": action,
            "arg_hash": arg_hash,
            "journal_seq": journal_seq,
            "receipt_digest": digest,
            "policy_version": receipt.get("policy_version"),
            "source": receipt.get("source"),
            "target": receipt.get("target"),
            "amount": receipt.get("amount"),
            "source_balance": receipt.get("source_balance"),
            "target_balance": receipt.get("target_balance"),
            "classification": "keyed",
        }, None
    # No pending check here: a pending record with the same fingerprint
    # legitimately coexists with this OUTCOME (a keyless execution plus
    # a pending keyed request with identical arguments). Treating that
    # as a conflict would fail legitimate histories.
    return {
        "audit_seq": seq,
        "action": action,
        "arg_hash": arg_hash,
        "journal_seq": journal_seq,
        "policy_version": outcome.get("policy_version"),
        "source": journal.source,
        "target": journal.target,
        "amount": journal.amount,
        "classification": "unresolved",
        "reason": "keying_indeterminable",
    }, None


def _build_entries(records, journal, operations, range_start, range_end):
    """Return ``(entries, problems)`` for the eligible OUTCOME set."""
    journal_by_seq = {entry.seq: entry for entry in journal}
    entries = []
    problems = []
    for outcome in _eligible_outcomes(records, range_start, range_end):
        entry, problem = _classify(outcome, journal_by_seq, operations)
        if problem is not None:
            problems.append(problem)
        else:
            entries.append(entry)
    return entries, problems


def _duplicate_keys(operations):
    """op_keys appearing more than once (string keys only)."""
    seen = set()
    dupes = set()
    for record in operations:
        key = record.get("key")
        if not isinstance(key, str):
            continue
        if key in seen:
            dupes.add(key)
        seen.add(key)
    return sorted(dupes)


def _assemble(range_start, range_end, entries):
    """Assemble a manifest dict; raises if entries are unencodable."""
    keyed = sum(1 for e in entries if e["classification"] == "keyed")
    root = _digest(entries)
    if root is None:
        raise ManifestError("unencodable_entries", {})
    header = {
        "format_version": MANIFEST_VERSION,
        "range_start": range_start,
        "range_end": range_end,
        "op_count": len(entries),
        "keyed_count": keyed,
        "unresolved_count": len(entries) - keyed,
    }
    digest = _digest(dict(header, entries_root=root))
    if digest is None:  # unreachable: header holds only ints and strs
        raise ManifestError("unencodable_entries", {})
    return dict(
        header, entries=list(entries), entries_root=root,
        manifest_digest=digest,
    )


def build_manifest(
    audit_records, journal_entries, operations, *,
    range_start, range_end,
):
    """Build a manifest over ``[range_start, range_end]``.

    Raises :class:`ManifestError` when the range cannot be enumerated
    faithfully: uncovered range, duplicate operation keys, duplicate
    operation linkage, journal gaps, malformed outcome shapes, or
    unencodable entry values. The audit chain, reconciliation,
    cross-checks, and receipt-value bindings are not established here;
    verification establishes them. Unresolved classifications are
    entries, not errors.
    """
    records = _require_records(audit_records)
    journal = _require_journal(journal_entries)
    ops = _require_operations(operations)
    _require_range(range_start, range_end)
    covered = {
        record["seq"]
        for record in records
        if _is_int(record.get("seq"))
    }
    if range_end - range_start + 1 > len(records):
        # Pigeonhole: more seqs claimed than records supplied, so at
        # least one is missing. Decided without enumerating the range.
        raise ManifestError(
            "range_uncovered",
            {"range_start": range_start, "range_end": range_end},
        )
    missing = [
        seq for seq in range(range_start, range_end + 1)
        if seq not in covered
    ]
    if missing:
        raise ManifestError("range_uncovered", {"missing": missing})
    dupes = _duplicate_keys(ops)
    if dupes:
        raise ManifestError("duplicate_operation_key", {"key": dupes[0]})
    entries, problems = _build_entries(
        records, journal, ops, range_start, range_end
    )
    if problems:
        first = problems[0]
        raise ManifestError(
            first["code"],
            {k: v for k, v in first.items() if k != "code"},
        )
    return _assemble(range_start, range_end, entries)


def _require_balances(opening_balances, ledger_snapshot):
    for name, value in (
        ("opening_balances", opening_balances),
        ("ledger_snapshot", ledger_snapshot),
    ):
        if not isinstance(value, dict) or not all(
            isinstance(account, str)
            and isinstance(balance, (int, float))
            and not isinstance(balance, bool)
            for account, balance in value.items()
        ):
            raise ManifestError("bad_balances", {"input": name})


def _check_history(records, problems):
    """Append chain findings; return True when the chain verifies."""
    if not records or records[0].get("seq") != 1:
        problems.append(_problem("history_not_full"))
        return False
    if [r.get("seq") for r in records] != list(range(1, len(records) + 1)):
        problems.append(_problem("audit_discontiguous"))
        return False
    if records[0].get("kind") != "genesis":
        problems.append(_problem("genesis_invalid"))
        return False
    ok, detail = _verify_chain(records)
    if not ok:
        problems.append(_problem("chain_invalid", detail=detail))
        return False
    return True


def _check_operations(ops, journal, records, problems):
    """Validate operation rows and committed receipt bindings."""
    for key in _duplicate_keys(ops):
        problems.append(_problem("duplicate_operation_key", key=key))
    for record in ops:
        if record.get("status") == "pending" and (
            record.get("receipt") is not None
        ):
            problems.append(
                _problem("pending_receipt", key=record.get("key"))
            )
            continue
        if not _record_shape_valid(record):
            problems.append(
                _problem("bad_operation_shape", key=record.get("key"))
            )
            continue
        if record["status"] == "pending":
            continue
        problem = operation_receipt_consistent(
            record["action"], record["arg_hash"], record["receipt"],
            journal, records,
        )
        if problem is not None:
            problems.append(
                _problem(problem, key=record.get("key"))
            )


def _check_entries(expected, presented, problems):
    """Compare expected entries against the presented manifest."""
    expected_by_seq = {entry["audit_seq"]: entry for entry in expected}
    presented_seqs = [entry["audit_seq"] for entry in presented]
    for seq in sorted(expected_by_seq):
        if seq not in presented_seqs:
            problems.append(_problem("manifest_omission", audit_seq=seq))
    for seq in presented_seqs:
        if seq not in expected_by_seq:
            problems.append(_problem("manifest_extra", audit_seq=seq))
    seen = set()
    for seq in presented_seqs:
        if seq in seen:
            problems.append(
                _problem(
                    "manifest_extra", audit_seq=seq, duplicate=True
                )
            )
        seen.add(seq)
    common_presented = [s for s in presented_seqs if s in expected_by_seq]
    common_expected = [s for s in sorted(expected_by_seq) if s in presented_seqs]
    if common_presented != common_expected:
        problems.append(_problem("manifest_reorder"))
    for seq in common_presented:
        presented_entry = presented[presented_seqs.index(seq)]
        expected_entry = expected_by_seq[seq]
        if presented_entry != expected_entry:
            fields = sorted(
                key
                for key in set(presented_entry) | set(expected_entry)
                if presented_entry.get(key) != expected_entry.get(key)
            )
            problems.append(
                _problem(
                    "manifest_tamper", audit_seq=seq, fields=fields
                )
            )


def _check_digests(manifest, problems):
    """Check presented digest self-consistency (not correctness)."""
    root = _digest(list(manifest["entries"]))
    if root is None:
        problems.append(_problem("unencodable_manifest"))
        return
    if root != manifest["entries_root"]:
        problems.append(_problem("digest_mismatch", which="entries_root"))
    header = {
        "format_version": manifest["format_version"],
        "range_start": manifest["range_start"],
        "range_end": manifest["range_end"],
        "op_count": manifest["op_count"],
        "keyed_count": manifest["keyed_count"],
        "unresolved_count": manifest["unresolved_count"],
        "entries_root": manifest["entries_root"],
    }
    digest = _digest(header)
    if digest is None or digest != manifest["manifest_digest"]:
        problems.append(
            _problem("digest_mismatch", which="manifest_digest")
        )


def verify_local_consistency(
    manifest, audit_records, journal_entries, operations, *,
    opening_balances=None, ledger_snapshot=None,
):
    """Verify a presented manifest against local evidence.

    Returns a result dict with independent ``ch`` and ``co`` claims.
    ``ch: pass`` means local enumeration consistency only. ``co`` is
    always ``unresolved``: this slice has no independent occurrence
    evidence. Raises :class:`ManifestError` solely for malformed
    input shapes; every content finding is a problem code.
    """
    _require_manifest(manifest)
    records = _require_records(audit_records)
    journal = _require_journal(journal_entries)
    ops = _require_operations(operations)
    problems = []
    range_start = manifest["range_start"]
    range_end = manifest["range_end"]
    history_ok = _check_history(records, problems)
    if history_ok and range_end > len(records):
        problems.append(
            _problem(
                "range_uncovered",
                range_end=range_end,
                history_end=len(records),
            )
        )
    # The cross-check assumes mapping extras; project non-dict
    # extras to {} so malformed rows report as findings (its own
    # malformed list plus bad_outcome_shape from classification)
    # instead of raising. verify.py itself is out of Slice A scope.
    projected = [
        record
        if not (
            record.get("kind") == "outcome"
            and not isinstance(record.get("extra"), dict)
        )
        else dict(record, extra={})
        for record in records
    ]
    cross = cross_check_journal_audit(journal, projected)
    if not cross.get("clean"):
        problems.append(_problem("cross_check_dirty"))
    if opening_balances is None or ledger_snapshot is None:
        reconcile_checked = False
    else:
        _require_balances(opening_balances, ledger_snapshot)
        reconcile_checked = True
        report = reconcile(opening_balances, journal, ledger_snapshot)
        if not report.get("clean"):
            problems.append(_problem("reconcile_dirty"))
    _check_operations(ops, journal, records, problems)
    expected, entry_problems = _build_entries(
        records, journal, ops, range_start, range_end
    )
    problems.extend(entry_problems)
    presented = list(manifest["entries"])
    if (
        manifest["op_count"] != len(presented)
        or manifest["keyed_count"]
        != sum(1 for e in presented if e.get("classification") == "keyed")
        or manifest["unresolved_count"]
        != sum(
            1 for e in presented
            if e.get("classification") == "unresolved"
        )
    ):
        problems.append(_problem("manifest_count_mismatch"))
    _check_digests(manifest, problems)
    _check_entries(expected, presented, problems)
    unresolved = [
        entry["audit_seq"] for entry in expected
        if entry["classification"] == "unresolved"
    ]
    return {
        "ch": "fail" if problems else "pass",
        "ch_problems": problems,
        "co": CO_UNRESOLVED,
        "co_reason": CO_REASON_NO_EVIDENCE,
        "entries": copy.deepcopy(presented),
        "unresolved_entries": unresolved,
        "exact_ids_available": not problems and not unresolved,
        "manifest_digest": manifest["manifest_digest"],
        "deployment_bound": False,
        "reconcile_checked": reconcile_checked,
    }
