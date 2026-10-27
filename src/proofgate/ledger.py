"""Synthetic in-memory ledger.

All reads are public; mutation requires the gate-held :class:`_Mutator`
capability, which is deliberately absent from ``__all__`` and constructed
only by the enforcement module. Unknown accounts read as balance zero.

``fault_hook`` is a test-only injection point: when set, it is invoked at
the start of every mutation and may raise to simulate a ledger failure.
"""

__all__ = ["LedgerError", "SyntheticLedger"]


class LedgerError(Exception):
    """Raised when a mutation cannot be applied (e.g. insufficient funds)."""


class SyntheticLedger:
    """In-memory balances map with capability-gated mutation."""

    def __init__(self, balances):
        if not isinstance(balances, dict):
            raise LedgerError("balances must be a dict")
        for account, amount in balances.items():
            if not isinstance(account, str) or not account:
                raise LedgerError("account names must be non-empty strings")
            if (
                isinstance(amount, bool)
                or not isinstance(amount, int)
                or amount < 0
            ):
                raise LedgerError(
                    "balances must be non-negative ints: %r" % (account,)
                )
        self._balances = dict(balances)
        self.fault_hook = None

    def balance(self, account):
        """Return the balance of *account* (zero when unknown)."""
        return self._balances.get(account, 0)

    def snapshot(self):
        """Return a copy of the balances map."""
        return dict(self._balances)


class _Mutator:
    """Gate-held mutation capability for a :class:`SyntheticLedger`.

    Not exported: supported callers cannot obtain one except through the
    enforcement entry point. Same-process private access is outside the
    prototype threat model (see threat-model documentation).
    """

    def __init__(self, ledger):
        self._ledger = ledger

    def apply_transfer(self, source, target, amount):
        """Move *amount* from *source* to *target* as one dict update."""
        if self._ledger.fault_hook is not None:
            self._ledger.fault_hook()
        balances = self._ledger._balances
        if balances.get(source, 0) < amount:
            raise LedgerError("insufficient_funds")
        balances[source] = balances.get(source, 0) - amount
        balances[target] = balances.get(target, 0) + amount
        return (balances[source], balances[target])
