"""External audit checkpoints for rollback detection (minimal proof).

A checkpoint is a small JSON file stored OUTSIDE the SQLite database
(and never included in its backup) recording the audit-chain head
(sequence + record hash) of a verified state, bound to an
operator-configured deployment ID. At startup, ``SQLiteBackend.open``
can require the database to match or verifiably extend the checkpoint;
an older snapshot then fails closed instead of serving silently
rolled-back state.

Threat scope is database-only rollback: a host attacker able to
rewrite both the database and the checkpoint file is out of scope,
and unkeyed hashes authenticate nothing on their own.
"""

import json
import os
import tempfile

__all__ = [
    "CHECKPOINT_VERSION",
    "CheckpointError",
    "read_checkpoint",
    "validate_expected_head",
    "write_checkpoint",
]

CHECKPOINT_VERSION = 1


class CheckpointError(Exception):
    """A checkpoint is malformed or refuses an operation."""


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _validated(data, path):
    """Return the normalized checkpoint dict or raise CheckpointError."""
    if not isinstance(data, dict):
        raise CheckpointError(
            "malformed checkpoint at %r: expected a JSON object"
            % (path,)
        )
    version = data.get("format_version")
    if version != CHECKPOINT_VERSION or isinstance(version, bool):
        raise CheckpointError(
            "malformed checkpoint at %r: unsupported version %r"
            % (path, version)
        )
    deployment_id = data.get("deployment_id")
    if not isinstance(deployment_id, str) or not deployment_id:
        raise CheckpointError(
            "malformed checkpoint at %r: bad deployment_id" % (path,)
        )
    seq = data.get("audit_seq")
    if not _is_int(seq) or seq < 1:
        raise CheckpointError(
            "malformed checkpoint at %r: bad audit_seq" % (path,)
        )
    digest = data.get("audit_hash")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise CheckpointError(
            "malformed checkpoint at %r: bad audit_hash" % (path,)
        )
    return {
        "format_version": CHECKPOINT_VERSION,
        "deployment_id": deployment_id,
        "audit_seq": seq,
        "audit_hash": digest,
    }


def validate_expected_head(audit_seq, audit_hash):
    """Validate caller-supplied expected head values for init.

    Returns ``(seq, hash)`` unchanged. Raises :class:`CheckpointError`
    unless the sequence is a positive integer and the hash is a
    64-character lowercase hex digest — the same strictness applied to
    checkpoint files, enforced through the same validator so the two
    cannot drift apart.
    """
    try:
        record = _validated(
            {
                "format_version": CHECKPOINT_VERSION,
                "deployment_id": "expected",
                "audit_seq": audit_seq,
                "audit_hash": audit_hash,
            },
            "<expected head>",
        )
    except CheckpointError as exc:
        raise CheckpointError(
            "bad expected audit head: %s" % (exc,)
        ) from exc
    return record["audit_seq"], record["audit_hash"]


def read_checkpoint(path):
    """Read and validate the checkpoint at *path*.

    Returns the normalized checkpoint dict. Missing files raise
    ``FileNotFoundError`` (never mistaken for a malformed checkpoint);
    anything else unusable raises :class:`CheckpointError`.
    """
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except ValueError as exc:
            raise CheckpointError(
                "malformed checkpoint at %r: invalid JSON" % (path,)
            ) from exc
    return _validated(data, path)


def write_checkpoint(path, deployment_id, audit_seq, audit_hash):
    """Atomically persist a checkpoint; return the normalized dict.

    The record is validated before anything is written. Bytes go to a
    ``0600`` temporary file in the same directory, are flushed and
    fsynced, then ``os.replace()`` atomically swaps the file into
    place; the directory entry is fsynced on POSIX. Failures before
    replacement leave the previous checkpoint untouched. If the
    directory fsync fails after replacement, this function raises even
    though the new checkpoint is already visible and complete — the
    caller must treat that outcome as ambiguous and re-read and
    validate the checkpoint before retrying.

    Replacement is unconditional: passing the database path itself
    would destroy the database. Prefer
    ``SQLiteBackend.checkpoint()``, which refuses database-path
    aliases.
    """
    record = _validated(
        {
            "format_version": CHECKPOINT_VERSION,
            "deployment_id": deployment_id,
            "audit_seq": audit_seq,
            "audit_hash": audit_hash,
        },
        path,
    )
    parent = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(
        dir=parent, prefix=".checkpoint-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, indent=2))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        if os.name == "posix":
            dir_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    return dict(record)
