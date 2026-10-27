"""Gate-only append-only mutation journal.

Every applied state change is recorded here inside the gate's critical
section, before the ledger mutation, so any residue is detectable
over-recording (``journal_ahead``) rather than silent mutation. The
journal is append-only: entries are never edited or removed.
"""

from dataclasses import dataclass

__all__ = ["Journal", "JournalEntry"]


@dataclass(frozen=True)
class JournalEntry:
    """One recorded mutation."""

    seq: int
    action: str
    source: str
    target: str
    amount: int


class Journal:
    """Append-only in-memory journal of applied mutations."""

    def __init__(self):
        self._entries = []
        self._next_seq = 1

    def append_transfer(self, source, target, amount):
        """Append a transfer entry and return it."""
        entry = JournalEntry(
            seq=self._next_seq,
            action="transfer_money",
            source=source,
            target=target,
            amount=amount,
        )
        self._entries.append(entry)
        self._next_seq += 1
        return entry

    def entries(self):
        """Return an immutable snapshot of the entries."""
        return tuple(self._entries)

    def __len__(self):
        return len(self._entries)
