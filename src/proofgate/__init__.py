"""ProofGate: deterministic authorization gate for consequential tool actions.

Synthetic-only prototype. ``Gate.gate(request)`` is the single supported
entry point for state-changing operations.
"""

from .enforcement import Gate, create_gate

__all__ = ["Gate", "create_gate"]
