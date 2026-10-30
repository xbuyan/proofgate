"""In-process journal-vs-ledger reconciliation.

:func:`reconcile` replays journal entries from opening balances and
compares the result with the ledger snapshot. It is a pure function: the
``incident_ref`` it echoes is supplied by the caller for linkage and
plays no role in the analysis.

Journal-ahead inference: when the full replay mismatches but the replay
excluding the final entry matches, the final entry is identified as
dangling (recorded without ledger effect). Anything else that mismatches
is reported as a generic balance mismatch with expected-vs-actual
per account. This is in-process consistency checking against a separate
journal object — not independent durable verification.

:func:`cross_check_journal_audit` verifies that every journal entry has
a matching successful OUTCOME audit record; entries without one are
reported as gaps (the residue of an unrecorded outcome).

Startup verification (:func:`verify_database`) runs the same read-only
checks plus schema, metadata, policy, counter, ledger, confirmation,
operation, journal, and audit validation before a persisted backend
may serve. It never writes.
"""

import json
import math

from .audit import GENESIS_PREV_HASH, _verify_chain
from .canonical import arg_hash
from .journal import JournalEntry
from .policy import validate_policy_fields
from .tools import is_valid_idempotency_key

__all__ = [
    "VerificationError",
    "check_keyed_outcome",
    "check_keyless_outcome",
    "check_receipt_keying",
    "cross_check_journal_audit",
    "operation_receipt_consistent",
    "outcome_keying_state",
    "reconcile",
    "verify_database",
]


def _replay(opening_balances, entries):
    balances = dict(opening_balances)
    for entry in entries:
        balances[entry.source] = balances.get(entry.source, 0) \
            - entry.amount
        balances[entry.target] = balances.get(entry.target, 0) \
            + entry.amount
    return balances


def _mismatches(replayed, ledger_snapshot):
    diffs = {}
    for account in set(replayed) | set(ledger_snapshot):
        expected = replayed.get(account, 0)
        actual = ledger_snapshot.get(account, 0)
        if expected != actual:
            diffs[account] = {"expected": expected, "actual": actual}
    return diffs


def reconcile(opening_balances, journal_entries, ledger_snapshot,
              incident_ref=None):
    """Replay the journal and compare against the ledger snapshot."""
    entries = list(journal_entries)
    mismatches = _mismatches(
        _replay(opening_balances, entries), ledger_snapshot
    )
    if not mismatches:
        return {
            "clean": True,
            "checked_entries": len(entries),
            "mismatches": {},
            "journal_ahead": None,
            "incident": incident_ref,
        }
    ahead = None
    if entries:
        partial = _replay(opening_balances, entries[:-1])
        if not _mismatches(partial, ledger_snapshot):
            ahead = entries[-1].seq
    return {
        "clean": False,
        "checked_entries": len(entries),
        "mismatches": mismatches,
        "journal_ahead": ahead,
        "incident": incident_ref,
    }


def cross_check_journal_audit(journal_entries, audit_records):
    """Check every journal entry has a successful OUTCOME record."""
    covered = set()
    malformed = []
    for record in audit_records:
        if record.get("kind") != "outcome":
            continue
        if record.get("decision") != "allowed":
            continue
        seq = (record.get("extra") or {}).get("journal_seq")
        if isinstance(seq, int) and not isinstance(seq, bool):
            covered.add(seq)
        else:
            malformed.append(record.get("seq"))
    journal_seqs = [entry.seq for entry in journal_entries]
    gaps = [seq for seq in journal_seqs if seq not in covered]
    orphans = sorted(seq for seq in covered if seq not in journal_seqs)
    problems = list(malformed)
    return {
        "clean": not gaps and not orphans and not problems,
        "gaps": gaps,
        "orphans": orphans,
        "malformed_outcomes": problems,
        "checked_entries": len(journal_seqs),
    }


class VerificationError(Exception):
    """Startup verification refused the database.

    ``category`` names the failed check group; ``detail`` carries
    structural facts only (names, counts, sequence numbers — never
    token values or other secrets). This is deliberately not a
    ``SQLiteBackendError`` subclass: ``verify`` must not import the
    backend module (circular), so callers distinguish refusals by
    catching this type directly.
    """

    def __init__(self, category, detail=None):
        super().__init__(
            "verification failed [%s]: %s" % (category, detail)
        )
        self.category = category
        self.detail = detail if detail is not None else {}


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _audit_record_from_row(row):
    """Rebuild an audit record dict from a storage row (positional).

    Column order must match the SELECT in :func:`verify_database`.
    Must agree field-for-field with
    ``sqlite_backend._record_from_row``; any drift breaks
    valid-database opens, so the S2 suite pins it.
    """
    return {
        "kind": row[0],
        "seq": row[1],
        "ts": row[2],
        "actor": row[3],
        "action": row[4],
        "arg_hash": row[5],
        "policy_version": row[6],
        "decision": row[7],
        "reason": row[8],
        "token_id": row[9],
        "extra": json.loads(row[10]),
        "prev_hash": row[11],
        "record_hash": row[12],
    }


def operation_receipt_consistent(op_action, op_arg_hash, receipt,
                                 journal_entries, audit_records):
    """Check a committed receipt against durable evidence.

    Returns ``None`` when the receipt matches a real journal entry
    and exactly one ``allowed`` OUTCOME record bound to the
    operation's own action and argument hash; otherwise returns a
    short problem code (``bad_receipt_shape``,
    ``fingerprint_mismatch``, ``journal_mismatch``,
    ``outcome_missing``, or ``ambiguous_outcome``). Pure function
    shared by startup verification and the runtime duplicate/query
    paths, so all three enforce the same invariant. Deliberately
    content-level: shape checks alone cannot catch a valid-JSON
    receipt with falsified values. The journal carries no argument
    hash, so the binding is closed by recomputing the fingerprint
    from the receipt's own arguments (deterministic canonical hash;
    identical input reproduces the stored digest exactly). No
    protection is claimed against an attacker who rewrites the
    whole database and recomputes every unkeyed hash.
    """
    if (
        not isinstance(receipt, dict)
        or receipt.get("action") != op_action
        or not isinstance(receipt.get("source"), str)
        or not receipt.get("source")
        or not isinstance(receipt.get("target"), str)
        or not receipt.get("target")
        or not _is_int(receipt.get("amount"))
        or receipt.get("amount") <= 0
        or not _is_int(receipt.get("journal_seq"))
        or receipt.get("journal_seq") < 1
        or not _is_int(receipt.get("source_balance"))
        or receipt.get("source_balance") < 0
        or not _is_int(receipt.get("target_balance"))
        or receipt.get("target_balance") < 0
        or not isinstance(receipt.get("policy_version"), str)
        or not receipt.get("policy_version")
    ):
        return "bad_receipt_shape"
    if (
        arg_hash({
            "source": receipt["source"],
            "target": receipt["target"],
            "amount": receipt["amount"],
        })
        != op_arg_hash
    ):
        return "fingerprint_mismatch"
    seq = receipt["journal_seq"]
    for entry in journal_entries:
        if entry.seq != seq:
            continue
        if (
            entry.action != op_action
            or entry.source != receipt["source"]
            or entry.target != receipt["target"]
            or entry.amount != receipt["amount"]
        ):
            return "journal_mismatch"
        break
    else:
        return "journal_mismatch"
    matches = 0
    for record in audit_records:
        if record.get("kind") != "outcome":
            continue
        if record.get("decision") != "allowed":
            continue
        if record.get("action") != op_action:
            continue
        if record.get("arg_hash") != op_arg_hash:
            continue
        if record.get("policy_version") != receipt["policy_version"]:
            continue
        extra = record.get("extra")
        if not isinstance(extra, dict):
            continue
        if (
            extra.get("journal_seq") == seq
            and extra.get("source_balance")
            == receipt["source_balance"]
            and extra.get("target_balance")
            == receipt["target_balance"]
        ):
            matches += 1
    if matches == 0:
        return "outcome_missing"
    if matches > 1:
        return "ambiguous_outcome"
    return None


def _is_valid_journal_seq(value):
    """Canonical journal-sequence shape: positive int, never bool."""
    return _is_int(value) and value >= 1


def outcome_keying_state(outcome):
    """Classify an OUTCOME record's keying evidence. Pure.

    Returns ``(kind, detail)``: ``("legacy", None)`` when no keying
    marker is present, ``("keyed", op_key)`` for a well-formed keyed
    marker, ``("keyless", None)`` for a well-formed keyless marker, or
    ``("malformed", problem)`` for present-but-invalid evidence. An
    absent marker and a malformed marker are never conflated.
    """
    if not isinstance(outcome, dict):
        return ("malformed", "bad_outcome_shape")
    extra = outcome.get("extra")
    if not isinstance(extra, dict):
        return ("malformed", "bad_outcome_shape")
    if "keyed" not in extra:
        return ("legacy", None)
    keyed = extra["keyed"]
    if not isinstance(keyed, bool):
        return ("malformed", "keying_malformed")
    if keyed:
        op_key = extra.get("op_key")
        if (
            not isinstance(op_key, str)
            or not op_key
            or not is_valid_idempotency_key(op_key)
        ):
            return ("malformed", "keying_malformed")
        return ("keyed", op_key)
    if "op_key" in extra:
        return ("malformed", "keying_malformed")
    return ("keyless", None)


def check_keyless_outcome(outcome, operations):
    """Fail closed when a keyless OUTCOME is contradicted. Pure.

    *outcome* must be keyless-marked (see :func:`outcome_keying_state`);
    its ``(action, arg_hash, journal_seq)`` must be well-shaped or a
    malformed code is returned instead of a silent pass. Returns
    ``"keyless_contradiction"`` when a committed operation claims the
    same execution, else ``None``. Malformed operation rows are skipped
    here: they are the subject of dedicated shape findings elsewhere,
    which fail independently.
    """
    if not isinstance(outcome, dict):
        return "bad_outcome_shape"
    action = outcome.get("action")
    arg_hash = outcome.get("arg_hash")
    if (
        not isinstance(action, str) or not action
        or not isinstance(arg_hash, str) or not arg_hash
    ):
        return "bad_outcome_shape"
    extra = outcome.get("extra")
    if not isinstance(extra, dict):
        return "bad_outcome_shape"
    journal_seq = extra.get("journal_seq")
    if not _is_valid_journal_seq(journal_seq):
        return "bad_outcome_shape"
    for record in operations:
        if not isinstance(record, dict):
            continue
        if record.get("status") != "committed":
            continue
        if record.get("action") != action:
            continue
        if record.get("arg_hash") != arg_hash:
            continue
        receipt = record.get("receipt")
        if not isinstance(receipt, dict):
            continue
        if not _is_valid_journal_seq(receipt.get("journal_seq")):
            continue
        if receipt.get("journal_seq") != journal_seq:
            continue
        return "keyless_contradiction"
    return None


def check_receipt_keying(record, audit_records):
    """Validate a committed record's identity-position pair. Pure.

    Both ``op_key`` and ``audit_seq`` absent means legacy: returns
    ``None`` (the caller skips position checks). Otherwise both must be
    present and valid, and the ``allowed`` OUTCOME at
    ``receipt["audit_seq"]`` must carry the matching keyed marker and
    execution content. Any violation returns a problem code. Callers
    must supply audit records with unique integer sequences (chain
    verification establishes this at startup and in manifests); the
    position scan takes the first sequence match. Content
    and journal linkage stay with :func:`operation_receipt_consistent`;
    callers enforcing full evidence must call both.
    """
    if not isinstance(record, dict):
        return "bad_operation_shape"
    key = record.get("key")
    receipt = record.get("receipt")
    if not isinstance(receipt, dict):
        return "bad_receipt_shape"
    key_present = "op_key" in receipt
    seq_present = "audit_seq" in receipt
    if not key_present and not seq_present:
        return None
    if not (key_present and seq_present):
        return "receipt_keying_malformed"
    op_key = receipt["op_key"]
    audit_seq = receipt["audit_seq"]
    if (
        not isinstance(op_key, str)
        or not is_valid_idempotency_key(op_key)
        or op_key != key
    ):
        return "receipt_key_mismatch"
    if not _is_int(audit_seq) or audit_seq < 1:
        return "receipt_position_invalid"
    target = None
    for candidate in audit_records:
        if not isinstance(candidate, dict):
            continue
        if not _is_int(candidate.get("seq")):
            continue
        if candidate.get("seq") == audit_seq:
            target = candidate
            break
    if target is None:
        return "receipt_position_mismatch"
    if target.get("kind") != "outcome":
        return "receipt_position_mismatch"
    if target.get("decision") != "allowed":
        return "receipt_position_mismatch"
    state, detail = outcome_keying_state(target)
    if state != "keyed" or detail != key:
        return "receipt_position_mismatch"
    if (
        target.get("action") != record.get("action")
        or target.get("arg_hash") != record.get("arg_hash")
        or target.get("policy_version") != receipt.get("policy_version")
    ):
        return "receipt_position_mismatch"
    extra = target.get("extra")
    if not isinstance(extra, dict):
        return "bad_outcome_shape"
    if not _is_valid_journal_seq(extra.get("journal_seq")):
        return "bad_outcome_shape"
    if not _is_valid_journal_seq(receipt.get("journal_seq")):
        return "bad_receipt_shape"
    if (
        extra.get("journal_seq") != receipt.get("journal_seq")
        or extra.get("source_balance")
        != receipt.get("source_balance")
        or extra.get("target_balance")
        != receipt.get("target_balance")
    ):
        return "receipt_position_mismatch"
    return None


def check_keyed_outcome(outcome, op_key, operations, audit_records):
    """Validate a keyed-marked OUTCOME against operations. Pure.

    *op_key* is the marker identity established via
    :func:`outcome_keying_state`. Returns ``None`` only when committed
    *op_key* exists with a new-format receipt pinned to this exact
    OUTCOME; otherwise returns a problem code.
    """
    if not isinstance(outcome, dict):
        return "bad_outcome_shape"
    seq = outcome.get("seq")
    if not _is_int(seq):
        return "bad_outcome_shape"
    matches = [
        record for record in operations
        if isinstance(record, dict) and record.get("key") == op_key
    ]
    if not matches:
        return "outcome_orphaned"
    if len(matches) > 1:
        return "duplicate_operation_key"
    record = matches[0]
    if record.get("status") != "committed":
        return "keyed_pending"
    receipt = record.get("receipt")
    if not isinstance(receipt, dict):
        return "bad_receipt_shape"
    if "op_key" not in receipt or "audit_seq" not in receipt:
        return "keyed_legacy_receipt"
    problem = check_receipt_keying(record, audit_records)
    if problem is not None:
        return problem
    if receipt.get("audit_seq") != seq:
        return "receipt_position_mismatch"
    return None


def verify_database(conn, expected_version, required_tables):
    """Verify a ProofGate database for startup. Read-only.

    Checks, in order: SQLite integrity (``PRAGMA quick_check``),
    schema version, required tables, metadata, policy, counters,
    ledger, confirmations, operations, journal continuity, the full
    audit chain, ledger/journal/audit reconciliation, committed
    receipt evidence binding, and OUTCOME/receipt keying evidence.
    Only ``SELECT`` and ``PRAGMA``
    statements run; no application state is written.

    Raises :class:`VerificationError` naming the failed category.
    Returns a summary dict on success. Positional row access only, so
    any row factory works.
    """
    summary = {}
    stage = "startup"
    try:
        stage = "sqlite_integrity"
        rows = conn.execute("PRAGMA quick_check").fetchall()
        if [tuple(row) for row in rows] != [("ok",)]:
            raise VerificationError(
                stage,
                {"problems": [tuple(row) for row in rows][:5]},
            )

        stage = "schema_version"
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        version = row[0] if row is not None else None
        if version != expected_version:
            raise VerificationError(stage, {"found": version})
        summary["schema_version"] = version

        stage = "schema_tables"
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        missing = sorted(set(required_tables) - tables)
        if missing:
            raise VerificationError(
                stage, "missing tables: %s" % ", ".join(missing)
            )
        summary["tables"] = len(tables)

        stage = "metadata"
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'opening_balances'"
        ).fetchone()
        if row is None:
            raise VerificationError(
                stage, {"missing": "opening_balances"}
            )
        try:
            opening = json.loads(row[0])
        except ValueError as exc:
            raise VerificationError(
                stage,
                {"key": "opening_balances", "problem": "unparseable"},
            ) from exc
        if not isinstance(opening, dict) or any(
            not isinstance(account, str)
            or not account
            or not _is_int(balance)
            or balance < 0
            for account, balance in opening.items()
        ):
            raise VerificationError(
                stage,
                {"key": "opening_balances", "problem": "bad_shape"},
            )
        summary["opening_accounts"] = len(opening)

        stage = "counters"
        counters = {}
        for name in ("daily_spent", "journal_seq", "boot_epoch"):
            row = conn.execute(
                "SELECT value FROM counters WHERE name = ?", (name,)
            ).fetchone()
            if row is None:
                raise VerificationError(stage, {"missing": name})
            if not _is_int(row[0]) or row[0] < 0:
                raise VerificationError(
                    stage, {"counter": name, "problem": "bad_value"}
                )
            counters[name] = row[0]
        if counters["journal_seq"] < 1:
            raise VerificationError(
                stage,
                {"counter": "journal_seq", "problem": "below_one"},
            )
        summary["daily_spent"] = counters["daily_spent"]
        summary["boot_epoch"] = counters["boot_epoch"]

        stage = "policy"
        rows = conn.execute(
            "SELECT version, per_transfer_cap, daily_cap, "
            "allowed_targets, retired FROM policy_versions"
        ).fetchall()
        active = [row for row in rows if row[4] == 0]
        if len(active) != 1:
            raise VerificationError(
                stage,
                {
                    "problem": "not_exactly_one_active",
                    "active_count": len(active),
                },
            )
        for row in rows:
            if row[4] not in (0, 1):
                raise VerificationError(
                    stage,
                    {"version": row[0], "problem": "bad_retired"},
                )
            try:
                targets = json.loads(row[3])
            except ValueError as exc:
                raise VerificationError(
                    stage,
                    {"version": row[0], "problem": "bad_targets"},
                ) from exc
            if not isinstance(targets, list):
                raise VerificationError(
                    stage,
                    {"version": row[0], "problem": "bad_targets"},
                )
            try:
                validate_policy_fields(
                    version=row[0],
                    per_transfer_cap=row[1],
                    daily_cap=row[2],
                    allowed_targets=targets,
                )
            except ValueError as exc:
                raise VerificationError(
                    stage,
                    {"version": row[0], "problem": "invalid"},
                ) from exc
        summary["policy_version"] = active[0][0]
        summary["retired_versions"] = len(rows) - 1

        stage = "ledger"
        balances = {}
        for row in conn.execute("SELECT account, balance FROM ledger"):
            account, balance = row[0], row[1]
            if (
                not isinstance(account, str)
                or not account
                or not _is_int(balance)
                or balance < 0
            ):
                raise VerificationError(
                    stage,
                    {
                        "problem": "bad_row",
                        "account": str(account)[:32],
                    },
                )
            balances[account] = balance
        summary["ledger_accounts"] = len(balances)

        stage = "confirmations"
        confirm_rows = conn.execute(
            "SELECT token, action, arg_hash, policy_version, "
            "issued_at, expires_at, used, epoch FROM confirmations"
        ).fetchall()
        for index, row in enumerate(confirm_rows):
            token, action, arg_hash, version = (
                row[0], row[1], row[2], row[3]
            )
            issued, expires, used, epoch = (
                row[4], row[5], row[6], row[7]
            )
            if (
                not isinstance(token, str) or not token
                or not isinstance(action, str) or not action
                or not isinstance(arg_hash, str) or not arg_hash
                or not isinstance(version, str) or not version
            ):
                raise VerificationError(
                    stage, {"index": index, "problem": "bad_binding"}
                )
            if used not in (0, 1):
                raise VerificationError(
                    stage, {"index": index, "problem": "bad_used"}
                )
            if not _is_int(epoch) or epoch < 0:
                raise VerificationError(
                    stage, {"index": index, "problem": "bad_epoch"}
                )
            if (
                not _is_number(issued)
                or not _is_number(expires)
                or not math.isfinite(issued)
                or not math.isfinite(expires)
                or expires < issued
            ):
                raise VerificationError(
                    stage, {"index": index, "problem": "bad_expiry"}
                )
        summary["confirmations"] = len(confirm_rows)

        stage = "operations"
        op_keys = set()
        committed = []
        op_records = []
        for row in conn.execute(
            "SELECT op_key, action, arg_hash, actor, status, "
            "receipt_json, created_epoch, updated_epoch "
            "FROM operations"
        ):
            key, action, arg_hash, actor = (
                row[0], row[1], row[2], row[3]
            )
            status, blob, created, updated = (
                row[4], row[5], row[6], row[7]
            )
            if not is_valid_idempotency_key(key):
                raise VerificationError(
                    stage, {"problem": "bad_key"}
                )
            if (
                not isinstance(action, str) or not action
                or not isinstance(arg_hash, str) or not arg_hash
                or not isinstance(actor, str)
            ):
                raise VerificationError(
                    stage, {"problem": "bad_binding"}
                )
            if status not in ("pending", "committed"):
                raise VerificationError(
                    stage, {"problem": "bad_status"}
                )
            if status == "pending":
                if blob is not None:
                    raise VerificationError(
                        stage, {"problem": "pending_receipt"}
                    )
                op_record = {
                    "key": key,
                    "status": status,
                    "action": action,
                    "arg_hash": arg_hash,
                    "receipt": None,
                }
            else:
                try:
                    receipt = json.loads(blob)
                except (TypeError, ValueError):
                    raise VerificationError(
                        stage, {"problem": "bad_receipt"}
                    )
                if not isinstance(receipt, dict):
                    raise VerificationError(
                        stage, {"problem": "bad_receipt"}
                    )
                op_record = {
                    "key": key,
                    "status": status,
                    "action": action,
                    "arg_hash": arg_hash,
                    "receipt": receipt,
                }
                committed.append(op_record)
            if (
                not _is_int(created) or created < 0
                or not _is_int(updated) or updated < 0
            ):
                raise VerificationError(
                    stage, {"problem": "bad_epoch"}
                )
            op_keys.add(key)
            op_records.append(op_record)
        for row in conn.execute(
            "SELECT op_key FROM confirmations "
            "WHERE op_key IS NOT NULL"
        ):
            if row[0] not in op_keys:
                raise VerificationError(
                    stage, {"problem": "dangling_op_link"}
                )
        summary["operations"] = len(op_keys)

        stage = "journal"
        entries = []
        for row in conn.execute(
            "SELECT seq, action, source, target, amount FROM journal "
            "ORDER BY seq"
        ):
            seq, action, source, target, amount = (
                row[0], row[1], row[2], row[3], row[4]
            )
            if (
                not _is_int(seq)
                or not isinstance(source, str) or not source
                or not isinstance(target, str) or not target
                or not _is_int(amount) or amount <= 0
            ):
                raise VerificationError(
                    stage, {"seq": seq, "problem": "bad_row"}
                )
            entries.append(
                JournalEntry(seq, action, source, target, amount)
            )
        seqs = [entry.seq for entry in entries]
        if seqs != list(range(1, len(seqs) + 1)):
            raise VerificationError(
                stage,
                {"problem": "sequence_gap", "count": len(seqs)},
            )
        if (seqs[-1] if seqs else 0) != counters["journal_seq"] - 1:
            raise VerificationError(
                stage, {"problem": "counter_drift"}
            )
        summary["journal_entries"] = len(entries)

        stage = "audit"
        rows = conn.execute(
            "SELECT kind, seq, ts, actor, action, arg_hash, "
            "policy_version, decision, reason, token_id, extra_json, "
            "prev_hash, record_hash FROM audit ORDER BY seq"
        ).fetchall()
        if not rows:
            raise VerificationError(stage, {"problem": "empty_chain"})
        seqs = [row[1] for row in rows]
        if seqs != list(range(1, len(rows) + 1)):
            raise VerificationError(
                stage, {"problem": "sequence_gap", "count": len(rows)}
            )
        if rows[0][0] != "genesis" or rows[0][11] != GENESIS_PREV_HASH:
            raise VerificationError(stage, {"problem": "bad_genesis"})
        try:
            records = [_audit_record_from_row(row) for row in rows]
        except (ValueError, TypeError) as exc:
            raise VerificationError(
                stage, {"problem": "unparseable_extra"}
            ) from exc
        ok, detail = _verify_chain(records)
        if not ok:
            raise VerificationError(stage, detail)
        summary["audit_records"] = len(records)

        stage = "reconcile"
        report = reconcile(opening, entries, balances)
        if not report["clean"]:
            raise VerificationError(
                stage,
                {
                    "mismatched_accounts": sorted(
                        report["mismatches"]
                    )[:8],
                    "journal_ahead": report["journal_ahead"],
                },
            )

        stage = "cross_check"
        cross = cross_check_journal_audit(entries, records)
        if not cross["clean"]:
            raise VerificationError(
                stage,
                {
                    "gaps": cross["gaps"][:8],
                    "orphans": sorted(cross["orphans"])[:8],
                    "malformed_outcomes": cross[
                        "malformed_outcomes"
                    ][:8],
                },
            )

        stage = "operation_evidence"
        for index, op in enumerate(committed):
            problem = operation_receipt_consistent(
                op["action"], op["arg_hash"], op["receipt"],
                entries, records
            )
            if problem is not None:
                raise VerificationError(
                    stage,
                    {"index": index, "problem": problem},
                )
        for op in committed:
            problem = check_receipt_keying(op, records)
            if problem is not None:
                raise VerificationError(
                    stage,
                    {"key": op["key"], "problem": problem},
                )
        for outcome in records:
            if outcome.get("kind") != "outcome":
                continue
            if outcome.get("decision") != "allowed":
                continue
            state, detail = outcome_keying_state(outcome)
            if state == "malformed":
                raise VerificationError(
                    stage,
                    {"seq": outcome.get("seq"), "problem": detail},
                )
            if state == "legacy":
                continue
            if state == "keyed":
                problem = check_keyed_outcome(
                    outcome, detail, op_records, records
                )
            else:
                problem = check_keyless_outcome(outcome, op_records)
            if problem is not None:
                raise VerificationError(
                    stage,
                    {"seq": outcome.get("seq"), "problem": problem},
                )
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError(
            stage, {"problem": "unreadable", "error": type(exc).__name__}
        ) from exc
    return summary
