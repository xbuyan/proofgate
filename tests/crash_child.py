"""Child worker for real process-crash tests.

Not collected by unittest (filename does not match the discovery
pattern); spawned by ``tests/test_crash_recovery.py`` on isolated
temporary databases only.

Usage: ``crash_child.py <db_path> <op_key> <mode>``

Modes:

- ``before-commit``: SIGKILL inside the redeem transaction, after the
  ledger mutation but before commit (via the audit fault hook at the
  OUTCOME append).
- ``after-commit``: SIGKILL after the redeem commit lands, before the
  gate builds any response (via a transaction-exit wrapper).

Both modes die by SIGKILL; any other exit means the test harness is
broken, not that recovery succeeded.
"""
import os
import signal
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "src")
)

from proofgate.enforcement import Gate
from proofgate.sqlite_backend import SQLiteBackend, _Transaction


def main():
    db_path, op_key, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    backend = SQLiteBackend.open(db_path)
    gate = Gate(policy=backend.get_policy(), storage=backend)
    args = {"source": "alice", "target": "bob", "amount": 100}
    initial = gate.gate({
        "action": "transfer_money", "args": dict(args),
        "idempotency_key": op_key,
    })
    assert initial["status"] == "confirmation_required", initial
    token = initial["confirmation"]
    if mode == "before-commit":
        def kill_on_outcome(kind):
            if kind == "outcome":
                os.kill(os.getpid(), signal.SIGKILL)

        backend.audit.fault_hook = kill_on_outcome
    elif mode == "after-commit":
        real_exit = _Transaction.__exit__

        def exit_then_die(self, exc_type, exc_value, tb):
            result = real_exit(self, exc_type, exc_value, tb)
            if exc_type is None:
                os.kill(os.getpid(), signal.SIGKILL)
            return result

        _Transaction.__exit__ = exit_then_die
    else:
        raise SystemExit("unknown mode: %r" % (mode,))
    gate.gate({
        "action": "transfer_money", "args": dict(args),
        "confirmation": token, "idempotency_key": op_key,
    })
    # Unreachable: both modes die by SIGKILL first.
    raise SystemExit("child survived unexpectedly")


if __name__ == "__main__":
    main()
