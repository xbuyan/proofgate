"""Canonical JSON encoding and argument hashing.

Canonical form: ``json.dumps`` with sorted keys, compact separators, ASCII
output, and no NaN/Infinity, encoded as UTF-8. Amounts must be integers in
minor units (floats are rejected by argument validation); NaN and Infinity
are rejected here as defense in depth.
"""

import hashlib
import json

__all__ = ["CanonicalizationError", "arg_hash", "canonicalize"]


class CanonicalizationError(TypeError):
    """Raised when a value has no canonical JSON representation."""


def canonicalize(obj):
    """Encode *obj* as canonical JSON bytes (deterministic)."""
    try:
        text = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(
            "value is not canonicalizable: %r" % (exc,)
        ) from exc
    return text.encode("utf-8")


def arg_hash(args):
    """Return the hex SHA-256 of the canonical encoding of *args*."""
    return hashlib.sha256(canonicalize(args)).hexdigest()
