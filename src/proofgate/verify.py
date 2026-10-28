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
    "cross_check_journal_audit",
    "operation_receipt_consistent",
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


def verify_database(conn, expected_version, required_tables):
    """Verify a ProofGate database for startup. Read-only.

    Checks, in order: SQLite integrity (``PRAGMA quick_check``),
    schema version, required tables, metadata, policy, counters,
    ledger, confirmations, operations, journal continuity, the full
    audit chain, ledger/journal/audit reconciliation, and committed
    receipt evidence binding. Only ``SELECT`` and ``PRAGMA``
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
                committed.append((action, arg_hash, receipt))
            if (
                not _is_int(created) or created < 0
                or not _is_int(updated) or updated < 0
            ):
                raise VerificationError(
                    stage, {"problem": "bad_epoch"}
                )
            op_keys.add(key)
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
        for index, (op_action, op_arg_hash, receipt) in enumerate(
            committed
        ):
            problem = operation_receipt_consistent(
                op_action, op_arg_hash, receipt, entries, records
            )
            if problem is not None:
                raise VerificationError(
                    stage,
                    {"index": index, "problem": problem},
                )
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError(
            stage, {"problem": "unreadable", "error": type(exc).__name__}
        ) from exc
    return summary
