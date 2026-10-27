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
"""

__all__ = ["cross_check_journal_audit", "reconcile"]


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
