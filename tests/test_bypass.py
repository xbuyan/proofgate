"""Non-vacuous bypass tests over the supported public API surface (Gate C).

Claim under test: no supported public API path mutates ledger state
except through ``Gate.gate()``. Same-process private access is outside
the prototype threat model; the negative-control test uses it only to
prove the probe itself can detect mutation.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import proofgate.enforcement as enforcement_mod
import proofgate.ledger as ledger_mod
import proofgate.tools as tools
from proofgate.enforcement import create_gate
from proofgate.policy import Policy
from proofgate.tools import OperationNotAuthorized


def public_callables(module):
    return sorted(
        name for name in module.__all__
        if callable(getattr(module, name))
    )


class BypassTests(unittest.TestCase):
    def attempt_mutates(self, gate, func, args):
        before = (
            gate.ledger_snapshot(),
            len(gate.journal_entries()),
            gate.status()["daily_spent"],
        )
        try:
            func(*args)
        except Exception:
            pass
        after = (
            gate.ledger_snapshot(),
            len(gate.journal_entries()),
            gate.status()["daily_spent"],
        )
        return before != after

    def test_public_surface_enumerated(self):
        for module in (tools, ledger_mod, enforcement_mod):
            found = public_callables(module)
            self.assertGreater(len(found), 0, module.__name__)
        # Guard against the test passing because a name moved.
        self.assertIn("transfer_money", tools.__all__)
        self.assertIn("get_balance", tools.__all__)
        self.assertIn("Gate", enforcement_mod.__all__)

    def test_mutator_capability_not_exported(self):
        for module in (tools, ledger_mod, enforcement_mod):
            self.assertNotIn("_Mutator", module.__all__)
            self.assertNotIn("Mutator", module.__all__)

    def test_transfer_requires_capability(self):
        gate = create_gate()
        for fake in (None, object(), "forged-capability",
                     gate.ledger_snapshot(), gate):
            with self.assertRaises(OperationNotAuthorized):
                tools.transfer_money(fake, "alice", "bob", 100)
        self.assertEqual(
            gate.ledger_snapshot(), {"alice": 10000}
        )

    def test_no_supported_path_mutates_outside_gate(self):
        gate = create_gate()
        # Private access: the probe needs the live ledger object for
        # read-only calls; production callers go through gate().
        live_ledger = gate._ledger
        valid_args = {
            "source": "alice", "target": "bob", "amount": 100,
        }
        attempts = [
            (tools.transfer_money, (None, "alice", "bob", 100)),
            (tools.transfer_money,
             ("forged", "alice", "bob", 100)),
            (tools.get_balance, (live_ledger, "alice")),
            (tools.validate_args, ("transfer_money", dict(valid_args))),
            (tools.validate_request,
             ({"action": "transfer_money",
               "args": dict(valid_args)},)),
            (live_ledger.balance, ("alice",)),
            (live_ledger.snapshot, ()),
            (gate.update_policy, ("junk",)),
            (gate.update_policy, (Policy.create(
                version="v9", per_transfer_cap=500, daily_cap=1000,
                allowed_targets=("bob", "carol")),)),
            (gate.operator_reset, ()),
            (gate.status, ()),
            (gate.check_health, ()),
            (gate.ledger_snapshot, ()),
            (gate.journal_entries, ()),
            (gate.audit_records, ()),
            (gate.current_policy, ()),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            attempts.append((
                gate.export_audit,
                (os.path.join(tmp, "probe.jsonl"),),
            ))
            for name in public_callables(tools):
                func = getattr(tools, name)
                for junk in ((), (None,), ("x", "y", "z")):
                    attempts.append((func, junk))
            for func, args in attempts:
                label = getattr(func, "__name__", repr(func))
                self.assertFalse(
                    self.attempt_mutates(gate, func, args), label
                )
        # NOTE: gate.gate() is deliberately excluded: it is the single
        # allowed mutation path. The gate still works after the battery.
        response = gate.gate({
            "action": "transfer_money", "args": dict(valid_args),
        })
        self.assertEqual(response["status"], "confirmation_required")

    def test_probe_detects_unguarded_mutation_control(self):
        # Negative control: the same probe MUST catch a deliberately
        # unguarded mutation, proving a clean result is meaningful.
        gate = create_gate()

        def evil_free_money(ledger):
            # Simulated same-process attacker: prevention is out of
            # scope; this exists only to validate probe sensitivity.
            ledger._balances["mallory"] = 999999

        self.assertTrue(
            self.attempt_mutates(gate, evil_free_money, (gate._ledger,))
        )
        clean = create_gate()
        self.assertFalse(
            self.attempt_mutates(
                clean, tools.get_balance, (clean._ledger, "alice")
            )
        )


if __name__ == "__main__":
    unittest.main()
