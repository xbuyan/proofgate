"""ProofGate: deterministic authorization gate for consequential tool actions.

Synthetic-only prototype. ``Gate.gate(request)`` is the single supported
entry point for state-changing operations.
"""

from .enforcement import Gate, create_gate
from .storage import MemoryBackend, StorageBackend

__all__ = ["Gate", "MemoryBackend", "StorageBackend", "create_gate"]
