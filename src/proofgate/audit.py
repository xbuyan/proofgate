"""Authoritative in-memory hash-chained audit log.

The in-memory record list is the ONLY authoritative store; there is no
dual-write file mirror. Files appear solely as read-only snapshots via
:meth:`AuditLog.export_jsonl`, so two stores can never disagree.

Record hash: ``sha256(canonical(record fields including prev_hash,
excluding record_hash))``. Genesis uses ``prev_hash == "GENESIS"``.

Every append performs an O(1) re-verification of the previous record's
link before appending; :meth:`AuditLog.verify` performs the full chain
check on demand. The verifier detects edits, deletions, reorderings, and
truncations of a preserved log. It CANNOT detect a full-file rewrite
carrying a valid fresh chain: no external anchoring exists in this
prototype, and no tamper-proof claim is made.

No crash durability is claimed: the authoritative log is in-memory and a
process crash loses it. ``fault_hook`` is a test-only injection point
that may raise :class:`AuditError` to simulate a write failure.
"""

import hashlib
import hmac
import json
import time

from .canonical import CanonicalizationError, canonicalize

__all__ = [
    "GENESIS_PREV_HASH",
    "AuditCorruptionError",
    "AuditError",
    "AuditLog",
    "verify_export",
]

GENESIS_PREV_HASH = "GENESIS"


class AuditError(Exception):
    """Audit write failure; ``reason`` is the machine-readable code."""

    def __init__(self, reason, detail=None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


class AuditCorruptionError(AuditError):
    """A stored record failed hash/link verification."""


def _record_hash(body):
    return hashlib.sha256(canonicalize(body)).hexdigest()


def _verify_chain(records):
    prev = GENESIS_PREV_HASH
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            return (False, {"index": index, "problem": "not_a_record"})
        if record.get("seq") != index + 1:
            return (False, {"index": index, "problem": "bad_seq"})
        if record.get("prev_hash") != prev:
            return (False, {"index": index, "problem": "prev_link"})
        body = {k: v for k, v in record.items() if k != "record_hash"}
        try:
            expected = _record_hash(body)
        except CanonicalizationError:
            return (False, {"index": index, "problem": "unencodable"})
        stored = record.get("record_hash", "")
        if not isinstance(stored, str) or not hmac.compare_digest(
            expected, stored
        ):
            return (False, {"index": index, "problem": "bad_hash"})
        prev = record["record_hash"]
    return (True, {"records": len(records)})


def verify_export(path):
    """Verify a snapshot file previously written by :meth:`export_jsonl`.

    Returns ``(ok, detail)``. A torn trailing line reports
    ``unparseable_line`` with its line number.
    """
    with open(path, "rb") as handle:
        data = handle.read()
    lines = [line for line in data.split(b"\n") if line]
    if not lines:
        return (False, {"problem": "empty"})
    records = []
    for lineno, line in enumerate(lines, start=1):
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return (
                False,
                {"problem": "unparseable_line", "line": lineno},
            )
        records.append(record)
    return _verify_chain(records)


class AuditLog:
    """Authoritative in-memory append-only hash-chained log."""

    def __init__(self, initial_policy_version, prior_export_hash=None,
                 clock=None, fault_hook=None):
        self._records = []
        self._clock = clock or time.time
        self.fault_hook = None
        extra = {}
        if prior_export_hash is not None:
            # Operator-supplied forensic reference only. The new instance
            # performs no lookup or validation of these bytes; this field
            # authenticates nothing and proves no continuity. There is
            # deliberately no `prior_verified` field anywhere.
            extra["prior_export_hash"] = prior_export_hash
        self.append(
            kind="genesis",
            actor="operator",
            action="genesis",
            arg_hash="",
            policy_version=initial_policy_version,
            decision="recorded",
            reason="genesis",
            extra=extra,
        )
        # The fault hook attaches only after genesis: construction itself
        # is never a simulated write failure.
        self.fault_hook = fault_hook

    @property
    def records(self):
        """Return copies of the records (callers cannot mutate the log)."""
        return tuple(dict(record) for record in self._records)

    def __len__(self):
        return len(self._records)

    def append(self, *, kind, actor, action, arg_hash, policy_version,
               decision, reason, token_id=None, extra=None):
        """Append one record; return a copy of it.

        Raises :class:`AuditError` when the fault hook fires (simulated
        write failure; nothing is appended) and :class:`AuditCorruptionError`
        when the previous record's link fails its O(1) re-check.
        """
        if self.fault_hook is not None:
            self.fault_hook(kind)
        if self._records:
            last = self._records[-1]
            body = {k: v for k, v in last.items() if k != "record_hash"}
            try:
                expected = _record_hash(body)
            except CanonicalizationError as exc:
                raise AuditCorruptionError(
                    "audit_corrupt", {"problem": "unencodable_last"}
                ) from exc
            stored = last.get("record_hash", "")
            if not isinstance(stored, str) or not hmac.compare_digest(
                expected, stored
            ):
                raise AuditCorruptionError(
                    "audit_corrupt", {"problem": "last_link"}
                )
            prev_hash = last["record_hash"]
            seq = len(self._records) + 1
        else:
            prev_hash = GENESIS_PREV_HASH
            seq = 1
        body = {
            "kind": kind,
            "seq": seq,
            "ts": self._clock(),
            "actor": actor,
            "action": action,
            "arg_hash": arg_hash,
            "policy_version": policy_version,
            "decision": decision,
            "reason": reason,
            "token_id": token_id,
            "extra": dict(extra) if extra else {},
            "prev_hash": prev_hash,
        }
        record_hash = _record_hash(body)
        record = dict(body)
        record["record_hash"] = record_hash
        if _record_hash(body) != record_hash:  # construction self-check
            raise AuditCorruptionError(
                "audit_corrupt", {"problem": "self_check"}
            )
        self._records.append(record)
        return dict(record)

    def verify(self):
        """Return ``(ok, detail)`` for the full chain check."""
        return _verify_chain(self._records)

    def export_jsonl(self, path):
        """Write a read-only canonical snapshot; return path/records/sha256.

        Export failures are plain I/O errors and never affect gate state.
        """
        blob = b"".join(
            canonicalize(record) + b"\n" for record in self._records
        )
        with open(path, "wb") as handle:
            handle.write(blob)
        return {
            "path": path,
            "records": len(self._records),
            "sha256": hashlib.sha256(blob).hexdigest(),
        }
