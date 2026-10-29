"""External checkpoint / rollback-detection proof tests.

Each test uses isolated temporary databases and checkpoint files only.
A checkpoint binds a verified audit-chain head to an operator
deployment ID; startup refuses databases that contradict it. Scope is
database-only rollback: a host attacker able to rewrite both files is
out of scope, and unkeyed hashes authenticate nothing on their own.
"""
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_sqlite_backend

from proofgate.checkpoint import (
    CheckpointError,
    read_checkpoint,
    write_checkpoint,
)
from proofgate.enforcement import Gate
from proofgate.policy import Policy
from proofgate.sqlite_backend import SQLiteBackend, SQLiteBackendError
from proofgate.verify import VerificationError

DEPLOYMENT = "proof-test-1"


def make_policy():
    return Policy.create(
        version="v1", per_transfer_cap=500, daily_cap=1000,
        allowed_targets=("bob", "carol"),
    )


def transfer_args(amount=100, target="bob"):
    return {"source": "alice", "target": target, "amount": amount}


class CheckpointCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._backends = []
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.close_backends)

    def close_backends(self):
        for backend in self._backends:
            try:
                backend.close()
            except Exception:
                pass

    def path(self, name="g.db"):
        return os.path.join(self.tmp.name, name)

    def make_gate(self, name="g.db"):
        backend = SQLiteBackend.create(
            self.path(name), policy=make_policy(),
            balances={"alice": 10000},
        )
        self._backends.append(backend)
        gate = Gate(policy=backend.get_policy(), storage=backend)
        return gate, backend

    def keyed_transfer(self, testcase, gate, key, args):
        initial = gate.gate({
            "action": "transfer_money", "args": dict(args),
            "idempotency_key": key,
        })
        testcase.assertEqual(initial["status"], "confirmation_required")
        redeemed = gate.gate({
            "action": "transfer_money", "args": dict(args),
            "confirmation": initial["confirmation"],
            "idempotency_key": key,
        })
        testcase.assertEqual(redeemed["status"], "allowed")
        return redeemed

    def restore(self, backup_name, live_name="g.db"):
        """Replace the closed live database with a backup's bytes."""
        live = self.path(live_name)
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                os.remove(live + suffix)
            except FileNotFoundError:
                pass
        os.remove(live)
        shutil.copyfile(self.path(backup_name), live)

    def read_bytes(self, name):
        with open(self.path(name), "rb") as handle:
            return handle.read()

    def head_of(self, backend):
        # Test stand-in for the operator's independent record: the
        # fixture database is trusted by construction. These tests pin
        # exact-match enforcement and refusal paths; independence
        # itself is procedural and covered by documentation.
        head = backend.audit.records[-1]
        return head["seq"], head["record_hash"]

    def create(self, name="g.db", **overrides):
        params = {
            "policy": make_policy(),
            "balances": {"alice": 10000},
        }
        params.update(overrides)
        backend = SQLiteBackend.create(self.path(name), **params)
        self._backends.append(backend)
        return backend

    def audit_rows(self, name="g.db"):
        conn = sqlite3.connect(self.path(name))
        try:
            return conn.execute(
                "SELECT kind, seq, ts, actor, action, arg_hash, "
                "policy_version, decision, reason, token_id, "
                "extra_json, prev_hash, record_hash "
                "FROM audit ORDER BY seq"
            ).fetchall()
        finally:
            conn.close()

    def schema_version(self, name="g.db"):
        conn = sqlite3.connect(self.path(name))
        try:
            return conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
        finally:
            conn.close()


class RollbackDetectionTests(CheckpointCase):
    def test_older_backup_rejected(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        backend.backup(self.path("b1.db"))
        self.keyed_transfer(self, gate, "cp-t2", transfer_args(50))
        seq, digest = self.head_of(backend)
        checkpoint = backend.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        self.assertEqual(
            gate.operation_status("cp-t2")["status"], "committed"
        )
        backend.close()
        self.restore("b1.db")
        before = self.read_bytes("g.db")
        with self.assertRaises(VerificationError) as raised:
            SQLiteBackend.open(
                self.path(), checkpoint_path=self.path("c.json"),
                deployment_id=DEPLOYMENT,
            )
        self.assertEqual(raised.exception.category, "checkpoint_ahead")
        # Refusal is read-only: neither database nor checkpoint moved.
        self.assertEqual(self.read_bytes("g.db"), before)
        with open(self.path("c.json"), "r", encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["audit_seq"],
                             checkpoint["audit_seq"])

    def test_extension_recovery_advances(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        first = backend.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        self.keyed_transfer(self, gate, "cp-t2", transfer_args(50))
        backend.close()
        # The database legitimately extends the checkpoint: the prior
        # checkpoint is present in the verified chain, so startup
        # accepts and recovery may advance the file.
        reopened = SQLiteBackend.open(
            self.path(), checkpoint_path=self.path("c.json"),
            deployment_id=DEPLOYMENT,
        )
        self._backends.append(reopened)
        second = reopened.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT
        )
        self.assertGreater(second["audit_seq"], first["audit_seq"])
        head = reopened.audit.records[-1]
        self.assertEqual(second["audit_seq"], head["seq"])
        self.assertEqual(second["audit_hash"], head["record_hash"])
        reopened.close()
        again = SQLiteBackend.open(
            self.path(), checkpoint_path=self.path("c.json"),
            deployment_id=DEPLOYMENT,
        )
        self._backends.append(again)

    def test_mismatch_refused(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        head = backend.audit.records[-1]
        forged = {
            "format_version": 1,
            "deployment_id": DEPLOYMENT,
            "audit_seq": head["seq"],
            "audit_hash": "0" * 64,
        }
        self.assertNotEqual(forged["audit_hash"], head["record_hash"])
        with open(self.path("c.json"), "w", encoding="utf-8") as fh:
            json.dump(forged, fh)
        before = self.read_bytes("c.json")
        with self.assertRaises(CheckpointError):
            backend.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT
            )
        self.assertEqual(self.read_bytes("c.json"), before)
        backend.close()
        db_before = self.read_bytes("g.db")
        with self.assertRaises(VerificationError) as raised:
            SQLiteBackend.open(
                self.path(), checkpoint_path=self.path("c.json"),
                deployment_id=DEPLOYMENT,
            )
        self.assertEqual(raised.exception.category, "checkpoint_mismatch")
        self.assertEqual(self.read_bytes("g.db"), db_before)

    def test_deployment_mismatch_refused(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        backend.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        before = self.read_bytes("c.json")
        with self.assertRaises(CheckpointError):
            backend.checkpoint(
                self.path("c.json"), deployment_id="other-deploy"
            )
        self.assertEqual(self.read_bytes("c.json"), before)
        backend.close()
        with self.assertRaises(VerificationError) as raised:
            SQLiteBackend.open(
                self.path(), checkpoint_path=self.path("c.json"),
                deployment_id="other-deploy",
            )
        self.assertEqual(
            raised.exception.category, "checkpoint_deployment"
        )

    def test_newer_checkpoint_never_overwritten(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        backend.backup(self.path("b1.db"))
        self.keyed_transfer(self, gate, "cp-t2", transfer_args(50))
        seq, digest = self.head_of(backend)
        backend.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        before = self.read_bytes("c.json")
        backend.close()
        self.restore("b1.db")
        # Opened without enforcement, the older database is usable;
        # advancing the checkpoint from it must still be refused.
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        with self.assertRaises(CheckpointError):
            reopened.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT
            )
        self.assertEqual(self.read_bytes("c.json"), before)

    def test_migration_then_refusal_preserves_audit(self):
        # Reuse the historical v1 fixture: its interface needs only
        # self.create/self.path plus assertions, which this case
        # provides with identical semantics.
        test_sqlite_backend.SchemaVersionTests.make_v1_database(
            self, name="g.db"
        )
        before_rows = self.audit_rows("g.db")
        self.assertEqual(self.schema_version("g.db"), "1")
        head_seq = max(row[1] for row in before_rows)
        checkpoint = {
            "format_version": 1,
            "deployment_id": DEPLOYMENT,
            "audit_seq": head_seq + 5,
            "audit_hash": "ab" * 32,
        }
        with open(self.path("c.json"), "w", encoding="utf-8") as fh:
            json.dump(checkpoint, fh)
        before_checkpoint = self.read_bytes("c.json")
        with self.assertRaises(VerificationError) as raised:
            SQLiteBackend.open(
                self.path(), checkpoint_path=self.path("c.json"),
                deployment_id=DEPLOYMENT,
            )
        self.assertEqual(raised.exception.category, "checkpoint_ahead")
        # Migration ran (schema metadata moved), yet the audit chain
        # the checkpoint compared against is exactly untouched — and
        # the failed open wrote no checkpoint bytes.
        self.assertEqual(self.audit_rows("g.db"), before_rows)
        self.assertEqual(self.schema_version("g.db"), "3")
        self.assertEqual(self.read_bytes("c.json"), before_checkpoint)


class CheckpointFormatTests(CheckpointCase):
    def valid_record(self, backend):
        head = backend.audit.records[-1]
        return {
            "format_version": 1,
            "deployment_id": DEPLOYMENT,
            "audit_seq": head["seq"],
            "audit_hash": head["record_hash"],
        }

    def test_malformed_refused(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        base = self.valid_record(backend)
        backend.close()
        db_before = self.read_bytes("g.db")
        cases = {
            "not-json": b"not json",
            "not-object": b"[1, 2]",
            "empty-object": b"{}",
            "bad-version": dict(base, format_version=2),
            "bool-version": dict(base, format_version=True),
            "missing-version": {
                key: base[key] for key in base if key != "format_version"
            },
            "empty-deployment": dict(base, deployment_id=""),
            "missing-deployment": {
                key: base[key] for key in base if key != "deployment_id"
            },
            "zero-seq": dict(base, audit_seq=0),
            "str-seq": dict(base, audit_seq="5"),
            "bool-seq": dict(base, audit_seq=True),
            "short-hash": dict(base, audit_hash="ab12"),
            "nonhex-hash": dict(base, audit_hash="g" * 64),
            "missing-hash": {
                key: base[key] for key in base if key != "audit_hash"
            },
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                with open(self.path("c.json"), "wb") as fh:
                    if isinstance(body, bytes):
                        fh.write(body)
                    else:
                        fh.write(json.dumps(body).encode("utf-8"))
                with self.assertRaises(VerificationError) as raised:
                    SQLiteBackend.open(
                        self.path(), checkpoint_path=self.path("c.json"),
                        deployment_id=DEPLOYMENT,
                    )
                self.assertEqual(
                    raised.exception.category, "checkpoint_malformed"
                )
        self.assertEqual(self.read_bytes("g.db"), db_before)

    def test_malformed_existing_refuses_advance(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        with open(self.path("c.json"), "wb") as fh:
            fh.write(b"junk")
        with self.assertRaises(CheckpointError):
            backend.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT
            )
        with open(self.path("c.json"), "rb") as fh:
            self.assertEqual(fh.read(), b"junk")

    def test_missing_checkpoint_refuses_without_bootstrap(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        backend.close()
        db_before = self.read_bytes("g.db")
        missing = self.path("absent.json")
        with self.assertRaises(VerificationError) as raised:
            SQLiteBackend.open(
                self.path(), checkpoint_path=missing,
                deployment_id=DEPLOYMENT,
            )
        self.assertEqual(raised.exception.category, "checkpoint_missing")
        self.assertFalse(os.path.exists(missing))
        self.assertEqual(self.read_bytes("g.db"), db_before)
        # Explicit initialization: open unenforced, checkpoint, then
        # enforced opens accept.
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        seq, digest = self.head_of(reopened)
        reopened.checkpoint(
            missing, deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        reopened.close()
        enforced = SQLiteBackend.open(
            self.path(), checkpoint_path=missing,
            deployment_id=DEPLOYMENT,
        )
        self._backends.append(enforced)


class CheckpointOperationTests(CheckpointCase):
    def test_open_never_writes_checkpoint(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        backend.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        before = self.read_bytes("c.json")
        backend.close()
        reopened = SQLiteBackend.open(
            self.path(), checkpoint_path=self.path("c.json"),
            deployment_id=DEPLOYMENT,
        )
        self._backends.append(reopened)
        self.assertEqual(self.read_bytes("c.json"), before)
        # Normal operation continues under enforcement.
        gate2 = Gate(policy=reopened.get_policy(), storage=reopened)
        self.keyed_transfer(self, gate2, "cp-t2", transfer_args(50))
        self.assertEqual(
            gate2.operation_status("cp-t2")["status"], "committed"
        )

    def test_checkpoint_guards(self):
        _, backend = self.make_gate()
        with self.assertRaises(ValueError):
            SQLiteBackend.open(
                self.path(), checkpoint_path=self.path("c.json")
            )
        with self.assertRaises(ValueError):
            backend.checkpoint(self.path(), deployment_id=DEPLOYMENT)
        with self.assertRaises(ValueError):
            backend.checkpoint(
                self.path("c.json"), deployment_id=""
            )
        with backend.transaction():
            with self.assertRaises(SQLiteBackendError):
                backend.checkpoint(
                    self.path("c.json"), deployment_id=DEPLOYMENT
                )

    def test_checkpoint_refuses_sidecar_aliases(self):
        _, backend = self.make_gate()
        db_path = self.path("g.db")
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                alias = db_path + suffix
                before = None
                if os.path.exists(alias):
                    with open(alias, "rb") as handle:
                        before = handle.read()
                with self.assertRaises(ValueError):
                    backend.checkpoint(
                        alias, deployment_id=DEPLOYMENT
                    )
                # Rejection precedes any write: live sidecars keep
                # their bytes, absent ones are never created.
                if before is None:
                    self.assertFalse(os.path.exists(alias))
                else:
                    with open(alias, "rb") as handle:
                        self.assertEqual(handle.read(), before)

    @unittest.skipUnless(
        hasattr(os, "umask"), "POSIX umask required"
    )
    def test_checkpoint_file_restrictive_permissions(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        previous = os.umask(0o000)
        try:
            backend.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT,
                expected_seq=seq, expected_hash=digest,
            )
            mode = os.stat(self.path("c.json")).st_mode & 0o777
        finally:
            os.umask(previous)
        self.assertEqual(mode & 0o077, 0)

    @unittest.skipUnless(
        os.name == "posix", "POSIX directory fsync required"
    )
    def test_replace_then_dir_fsync_failure_is_ambiguous(self):
        dest = self.path("c.json")
        write_checkpoint(dest, DEPLOYMENT, 1, "ab" * 32)
        expected = {
            "format_version": 1,
            "deployment_id": DEPLOYMENT,
            "audit_seq": 2,
            "audit_hash": "cd" * 32,
        }
        real_fsync = os.fsync

        def failing_dir_fsync(fd):
            # Fail directory fsyncs only: the checkpoint file's own
            # fsync (and every other fd) behaves normally, so the
            # failure lands strictly after os.replace() succeeded.
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected dir fsync failure")
            return real_fsync(fd)

        os.fsync = failing_dir_fsync
        try:
            with self.assertRaises(OSError):
                write_checkpoint(dest, DEPLOYMENT, 2, "cd" * 32)
        finally:
            os.fsync = real_fsync
        # Ambiguous outcome: the error propagated, yet the complete
        # replacement is visible — never partial JSON.
        with open(dest, "rb") as handle:
            raw = handle.read()
        self.assertEqual(json.loads(raw.decode("utf-8")), expected)
        self.assertEqual(read_checkpoint(dest), expected)
        self.assertEqual(os.listdir(self.tmp.name), ["c.json"])


class InitializationTests(CheckpointCase):
    def test_init_without_expected_refused(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        with self.assertRaises(CheckpointError):
            backend.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT
            )
        self.assertFalse(os.path.exists(self.path("c.json")))

    def test_init_wrong_seq_refused(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        with self.assertRaises(CheckpointError):
            backend.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT,
                expected_seq=seq + 1, expected_hash=digest,
            )
        self.assertFalse(os.path.exists(self.path("c.json")))

    def test_init_wrong_hash_refused(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        wrong = "0" * 64
        self.assertNotEqual(wrong, digest)
        with self.assertRaises(CheckpointError):
            backend.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT,
                expected_seq=seq, expected_hash=wrong,
            )
        self.assertFalse(os.path.exists(self.path("c.json")))

    def test_init_malformed_expected_refused(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        bad_values = [
            ("5", "ab" * 32),
            (0, "ab" * 32),
            (True, "ab" * 32),
            (1, "zz"),
            (1, "AB" * 32),
            (1, None),
        ]
        for seq, digest in bad_values:
            with self.subTest(seq=seq, digest=digest):
                with self.assertRaises(CheckpointError):
                    backend.checkpoint(
                        self.path("c.json"), deployment_id=DEPLOYMENT,
                        expected_seq=seq, expected_hash=digest,
                    )
        self.assertFalse(os.path.exists(self.path("c.json")))

    def test_init_exact_succeeds(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        record = backend.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        self.assertEqual(record["audit_seq"], seq)
        self.assertEqual(record["audit_hash"], digest)
        self.assertEqual(read_checkpoint(self.path("c.json")), record)

    def test_init_rejects_restored_older_database(self):
        gate, backend = self.make_gate()
        backend.backup(self.path("b0.db"))
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        backend.close()
        self.restore("b0.db")
        reopened = SQLiteBackend.open(self.path())
        self._backends.append(reopened)
        # The trusted head is newer than the restored database: init
        # must refuse without creating a checkpoint.
        with self.assertRaises(CheckpointError):
            reopened.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT,
                expected_seq=seq, expected_hash=digest,
            )
        self.assertFalse(os.path.exists(self.path("c.json")))
        self.assertEqual(
            reopened.ledger.snapshot(), {"alice": 10000}
        )

    def test_expected_rejected_when_file_exists(self):
        gate, backend = self.make_gate()
        self.keyed_transfer(self, gate, "cp-t1", transfer_args())
        seq, digest = self.head_of(backend)
        backend.checkpoint(
            self.path("c.json"), deployment_id=DEPLOYMENT,
            expected_seq=seq, expected_hash=digest,
        )
        before = self.read_bytes("c.json")
        # Init arguments cannot bypass the existing file's rules.
        with self.assertRaises(CheckpointError):
            backend.checkpoint(
                self.path("c.json"), deployment_id=DEPLOYMENT,
                expected_seq=seq, expected_hash=digest,
            )
        self.assertEqual(self.read_bytes("c.json"), before)


if __name__ == "__main__":
    unittest.main()
