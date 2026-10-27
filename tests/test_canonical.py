"""Tests for canonical JSON encoding and argument hashing (Gate B)."""
import os
import string
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from proofgate.canonical import CanonicalizationError, arg_hash, canonicalize


class CanonicalTests(unittest.TestCase):
    def test_compact_sorted_bytes(self):
        self.assertEqual(
            canonicalize({"b": 1, "a": [2, 3]}), b'{"a":[2,3],"b":1}'
        )

    def test_key_order_invariance(self):
        first = {"x": 1, "y": {"m": 1, "n": 2}}
        second = {"y": {"n": 2, "m": 1}, "x": 1}
        self.assertEqual(canonicalize(first), canonicalize(second))
        self.assertEqual(arg_hash(first), arg_hash(second))

    def test_changed_value_changes_hash(self):
        baseline = arg_hash({"amount": 10, "source": "a", "target": "b"})
        changed = arg_hash({"amount": 11, "source": "a", "target": "b"})
        self.assertNotEqual(baseline, changed)

    def test_arg_hash_is_64_lower_hex(self):
        digest = arg_hash({"amount": 10})
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(c in string.hexdigits for c in digest))

    def test_unicode_is_ascii_escaped(self):
        self.assertEqual(
            canonicalize({"k": "caf\u00e9"}), b'{"k":"caf\\u00e9"}'
        )

    def test_nan_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({"v": float("nan")})

    def test_infinity_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({"v": float("inf")})

    def test_non_serializable_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize({"v": object()})


if __name__ == "__main__":
    unittest.main()
