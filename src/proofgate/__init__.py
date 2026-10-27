"""ProofGate: deterministic authorization gate for consequential tool actions.

Synthetic-only prototype. ``Gate.gate(request)`` is the single supported
entry point for state-changing operations.
"""

from .enforcement import Gate, create_gate
from .sqlite_backend import SQLiteBackend
from .storage import MemoryBackend, StorageBackend

__all__ = [
    "Gate",
    "MemoryBackend",
    "SQLiteBackend",
    "StorageBackend",
    "create_gate",
]
