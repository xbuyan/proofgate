"""ProofGate synthetic demo (standard library only).

Runs a deterministic end-to-end scenario against the real gate API:
a read-only query, a confirmed transfer, replay and over-limit denials,
an expiry denial, and a degraded-mode plus operator-recovery cycle.
Every step asserts its expected outcome; any mismatch raises and the
process exits non-zero.

No real money, network, or external services are involved. Fault
injection below uses the documented test-only hook to simulate an
infrastructure failure; it is not a supported production API.

Run from the project directory:

    python3 demo.py
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
)

from proofgate.audit import AuditError
from proofgate.confirmations import ConfirmationStore
from proofgate.enforcement import create_gate


class FixedClock:
    """Deterministic clock shared by confirmations and audit stamps."""

    def __init__(self):
        self.now_value = 10000.0

    def __call__(self):
        return self.now_value

    def advance(self, seconds):
        self.now_value += seconds


CHECKS = []


def check(name, condition, detail=""):
    CHECKS.append((name, bool(condition)))
    mark = "ok" if condition else "FAIL"
    print("[%s] %s %s" % (mark, name, detail))
    if not condition:
        raise AssertionError("demo check failed: %s" % name)


def main():
    clock = FixedClock()
    gate = create_gate(balances={"alice": 10000}, clock=clock)
    print("ProofGate demo: synthetic ledger, alice=10000")

    # 1. Read-only query: validated, authorized, audited, no mutation.
    read = gate.gate(
        {"action": "get_balance", "args": {"account": "alice"}}
    )
    check("read-only balance", read["status"] == "allowed"
          and read["balance"] == 10000, "balance=10000")
    check("read leaves no journal", len(gate.journal_entries()) == 0)

    # 2. Confirmation flow: initial request yields a bound token.
    transfer = {"source": "alice", "target": "bob", "amount": 250}
    initial = gate.gate({"action": "transfer_money",
                         "args": dict(transfer)})
    check("confirmation required",
          initial["status"] == "confirmation_required")
    token = initial["confirmation"]
    # Only the short token id is shown; the full token stays in memory.
    print("      token_id=%s (full token withheld from output)"
          % ConfirmationStore.token_id(token))

    # 3. Redemption: policy revalidated against live state, then applied.
    executed = gate.gate({"action": "transfer_money",
                          "args": dict(transfer),
                          "confirmation": token})
    check("transfer allowed", executed["status"] == "allowed")
    receipt = executed["receipt"]
    check("receipt balances",
          (receipt["source_balance"], receipt["target_balance"])
          == (9750, 250), "alice=9750 bob=250")

    # 4. Replay: the single-use token is spent.
    replay = gate.gate({"action": "transfer_money",
                        "args": dict(transfer), "confirmation": token})
    check("replay denied",
          (replay["status"], replay["reason"])
          == ("denied", "confirmation_reused"))

    # 5. Over-limit request is denied before any token is issued.
    denied = gate.gate({"action": "transfer_money",
                        "args": dict(transfer, amount=5000)})
    check("over-limit denied",
          (denied["status"], denied["reason"])
          == ("denied", "policy_limit_exceeded"))
    check("no token on denial", "confirmation" not in denied)

    # 6. Expiry: the token outlives its 300-second binding.
    small = {"source": "alice", "target": "bob", "amount": 50}
    expiring = gate.gate({"action": "transfer_money",
                          "args": dict(small)})["confirmation"]
    clock.advance(301)
    stale = gate.gate({"action": "transfer_money",
                       "args": dict(small),
                       "confirmation": expiring})
    check("expired denied",
          (stale["status"], stale["reason"])
          == ("denied", "confirmation_expired"))

    # 7. Degraded mode: AUTHORIZED cannot be recorded, so nothing runs.
    doomed = gate.gate({"action": "transfer_money",
                        "args": dict(small)})["confirmation"]

    def fail(kind):
        raise AuditError("audit_unavailable")

    gate._audit.fault_hook = fail  # test-only hook: simulated outage
    broken = gate.gate({"action": "transfer_money",
                        "args": dict(small), "confirmation": doomed})
    check("audit failure fails closed",
          (broken["status"], broken["reason"])
          == ("error", "audit_unavailable"))
    incident = gate.status()["incident"]
    check("incident recorded", gate.status()["degraded"]
          and incident["case"] == "audit_unavailable",
          "case=%s" % incident["case"])
    check("nothing mutated",
          gate.ledger_snapshot() == {"alice": 9750, "bob": 250})

    # 8. Operator recovery: fix the cause, reset, resume service.
    gate._audit.fault_hook = None
    reset = gate.operator_reset()
    check("operator reset", reset["status"] == "reset")
    fresh = gate.gate({"action": "transfer_money",
                       "args": dict(small)})["confirmation"]
    resumed = gate.gate({"action": "transfer_money",
                         "args": dict(small), "confirmation": fresh})
    check("service resumed", resumed["status"] == "allowed")

    # 9. Evidence: audit chain verifies and reconciliation is clean.
    health = gate.check_health()
    check("audit verifies", health["audit"]["ok"])
    check("reconciliation clean", health["reconcile"]["clean"])
    check("journal/audit cross-check clean",
          health["cross_check"]["clean"])
    print("audit records: %d, journal entries: %d"
          % (len(gate.audit_records()), len(gate.journal_entries())))

    print("demo complete: %d/%d checks passed"
          % (len(CHECKS), len(CHECKS)))


if __name__ == "__main__":
    main()
