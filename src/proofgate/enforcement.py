"""Single synchronous enforcement entry point.

:class:`Gate` owns the policy, ledger, journal, audit log, confirmation
store, and the one lock serializing every protected path. ``gate()`` is
the only supported route to ledger mutation: the mutator capability is
constructed here and never leaves this module except as an argument to
the tool handler inside the critical section.

Critical redemption order (all under the lock, no I/O or callbacks
except the audit append, which is the fail-closed point)::

    validate -> token check -> [keyed: identity/conflict/status]
        -> policy/live revalidation -> AUTHORIZED -> [keyed: bind]
        -> consume -> journal -> ledger -> OUTCOME [+op complete]

Response statuses: ``allowed``, ``confirmation_required``, ``denied``,
``error``, ``executed_recording_failed`` (mutation applied but the
OUTCOME record failed — never reported as denied), plus the operator
statuses ``policy_updated`` and ``reset``.

Degraded mode is sticky: once set, protected operations stay blocked
until :meth:`operator_reset` (allowed only when reconciliation,
journal/audit cross-check, and audit verification are all clean) or
operator reconstruction of a fresh instance.
"""

import functools
import sqlite3
import threading

from .audit import AuditError
from .canonical import arg_hash
from .confirmations import ConfirmationError, ConfirmationStore
from .policy import Policy, evaluate, validate_policy_fields
from .sqlite_backend import SQLiteBackendError, _CommitUncertainError
from .storage import MemoryBackend, StorageBackend
from .tools import (
    get_balance as read_balance,
)
from .tools import (
    transfer_money as apply_transfer,
)
from .tools import (
    is_valid_idempotency_key,
    validate_args,
    validate_request,
    ValidationError,
)
from .verify import (
    cross_check_journal_audit,
    operation_receipt_consistent,
    reconcile,
)

__all__ = ["Gate", "create_gate"]

STATUS_ALLOWED = "allowed"
STATUS_CONFIRMATION_REQUIRED = "confirmation_required"
STATUS_DENIED = "denied"
STATUS_ERROR = "error"
STATUS_EXECUTED_RECORDING_FAILED = "executed_recording_failed"
STATUS_POLICY_UPDATED = "policy_updated"
STATUS_RESET = "reset"

REASON_OK = "ok"
REASON_DEGRADED = "degraded"
REASON_AUDIT_UNAVAILABLE = "audit_unavailable"
REASON_EXECUTION_FAILED = "execution_failed"
REASON_OUTCOME_UNRECORDED = "outcome_unrecorded"
REASON_RESET_REFUSED = "reset_refused"
REASON_NOT_DEGRADED = "not_degraded"
REASON_INVALID_POLICY = "invalid_policy"
REASON_VERSION_REUSED = "version_reused"
REASON_VERSION_UNCHANGED = "version_unchanged"
REASON_TOKEN_COMMIT_FAILED = "token_commit_failed"
REASON_STORAGE_UNAVAILABLE = "storage_unavailable"
REASON_OUTCOME_UNCERTAIN = "outcome_uncertain"
REASON_OPERATION_CONFLICT = "operation_conflict"
REASON_OPERATION_UNVERIFIABLE = "operation_unverifiable"

ACTION_BALANCE = "get_balance"
ACTION_TRANSFER = "transfer_money"


def _with_storage_boundary(method):
    """Translate backend storage faults into structured gate results.

    Applied to the transacted gate operations. The wrapped method runs
    its storage transaction normally; if a storage-layer failure
    escapes (the backend already rolled back) or the commit outcome is
    uncertain, the gate is marked degraded and a structured ``error``
    result is returned instead of leaking a raw driver exception. No
    audit evidence is fabricated for the rolled-back attempt, and no
    transfer is claimed to have executed.

    Only storage faults are translated. Programmer errors (including
    backend-misuse errors), fault-hook behavior, and control-flow
    exceptions such as KeyboardInterrupt propagate untouched.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except _CommitUncertainError as exc:
            reason = REASON_OUTCOME_UNCERTAIN
            case = "outcome_uncertain"
            detail = "%s: %s" % (method.__name__, exc)
        except sqlite3.Error as exc:
            reason = REASON_STORAGE_UNAVAILABLE
            case = "storage_unavailable"
            detail = "%s: rolled back: %s" % (method.__name__, exc)
        with self._lock:
            try:
                self._set_degraded(case, detail)
            except sqlite3.Error:
                # The store is unusable even for reads; keep a minimal
                # incident rather than losing the failure entirely.
                self._degraded = {
                    "case": case,
                    "detail": detail,
                    "audit_records": "unknown",
                }
        return {"status": STATUS_ERROR, "reason": reason}
    return wrapper


class Gate:
    """Deterministic enforcement gate over synthetic state."""

    def __init__(self, *, policy, balances=None, ttl_seconds=None,
                 clock=None, prior_export_hash=None, storage=None):
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy")
        validate_policy_fields(
            version=policy.version,
            per_transfer_cap=policy.per_transfer_cap,
            daily_cap=policy.daily_cap,
            allowed_targets=policy.allowed_targets,
        )
        if prior_export_hash is not None and not isinstance(
            prior_export_hash, str
        ):
            raise TypeError("prior_export_hash must be None or a string")
        if storage is None:
            if balances is None:
                raise TypeError(
                    "balances is required unless storage is supplied"
                )
            storage = MemoryBackend(
                policy=policy,
                balances=balances,
                ttl_seconds=ttl_seconds,
                clock=clock,
                prior_export_hash=prior_export_hash,
            )
        else:
            if balances is not None:
                raise TypeError("pass balances or storage, not both")
            if not isinstance(storage, StorageBackend):
                raise TypeError("storage must be a StorageBackend")
        self._lock = threading.Lock()
        self._storage = storage
        # Policy, retired versions, and counters are backend-owned;
        # the gate keeps no mirrors. A supplied policy must agree with
        # the backend's active policy; disagreement is a construction
        # bug, not something to resolve silently.
        if storage.get_policy() != policy:
            raise ValueError(
                "storage active policy does not match supplied policy"
            )
        self._ledger = storage.ledger
        self._opening = storage.get_opening_balances()
        self._mutator = storage.mutator()
        self._journal = storage.journal
        self._audit = storage.audit
        self._confirmations = storage.confirmations
        self._degraded = None

    # ------------------------------------------------------------------
    # internal helpers (all called with the lock held)
    # ------------------------------------------------------------------

    def _live_state(self):
        return {
            "balances": self._ledger.snapshot(),
            "daily_spent": self._storage.get_daily_spent(),
        }

    def _set_degraded(self, case, detail, **extra):
        incident = {
            "case": case,
            "detail": detail,
            "audit_records": len(self._audit),
        }
        incident.update(extra)
        self._degraded = incident

    def _record(self, **fields):
        return self._audit.append(**fields)

    def _deny(self, reason, *, action, digest, actor):
        try:
            self._record(
                kind="decision", actor=actor, action=action,
                arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision=STATUS_DENIED, reason=reason,
            )
        except AuditError:
            self._set_degraded(
                "audit_unavailable",
                "decision record failed; nothing executed",
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_AUDIT_UNAVAILABLE,
            }
        return {"status": STATUS_DENIED, "reason": reason}

    def _degraded_refusal(self, actor, action, digest):
        try:
            self._record(
                kind="decision", actor=actor, action=action,
                arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision=STATUS_ERROR, reason=REASON_DEGRADED,
            )
        except AuditError:
            pass  # standing incident remains the evidence
        return {"status": STATUS_ERROR, "reason": REASON_DEGRADED}

    def _best_effort_outcome(self, actor, digest, token_id, decision,
                             reason, journal_seq):
        try:
            self._record(
                kind="outcome", actor=actor, action=ACTION_TRANSFER,
                arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision=decision, reason=reason, token_id=token_id,
                extra={"journal_seq": journal_seq},
            )
        except AuditError:
            if self._degraded is not None:
                self._degraded["outcome_note"] = (
                    "best-effort OUTCOME record also failed"
                )

    # ------------------------------------------------------------------
    # gate entry point
    # ------------------------------------------------------------------

    @_with_storage_boundary
    def gate(self, request):
        """Validate, authorize, and execute one request."""
        with self._lock, self._storage.transaction():
            try:
                action, actor, args, token, key = validate_request(
                    request
                )
            except ValidationError as exc:
                return self._deny(
                    exc.reason, action=exc.action,
                    digest=exc.arg_hash, actor=exc.actor,
                )
            digest = arg_hash(args)
            if self._degraded is not None and action == ACTION_TRANSFER:
                return self._degraded_refusal(actor, action, digest)
            if action == ACTION_BALANCE:
                return self._read_balance(actor, args, digest)
            if token is None:
                return self._transfer_initial(actor, args, digest, key)
            return self._transfer_redeem(
                actor, args, digest, token, key
            )

    def _read_balance(self, actor, args, digest):
        permitted, reason = evaluate(
            self._storage.get_policy(), ACTION_BALANCE, args,
            self._live_state()
        )
        if not permitted:
            return self._deny(
                reason, action=ACTION_BALANCE, digest=digest,
                actor=actor,
            )
        balance = read_balance(self._ledger, args["account"])
        try:
            self._record(
                kind="decision", actor=actor, action=ACTION_BALANCE,
                arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision=STATUS_ALLOWED, reason=REASON_OK,
            )
        except AuditError:
            self._set_degraded(
                "audit_unavailable",
                "read-only decision unrecorded",
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_AUDIT_UNAVAILABLE,
            }
        return {
            "status": STATUS_ALLOWED,
            "reason": REASON_OK,
            "account": args["account"],
            "balance": balance,
        }

    def _lookup_keyed_operation(self, key, action, digest):
        """Return ``(record_or_None, is_conflict)``. Read-only."""
        record = self._storage.get_operation(key)
        if record is not None and (
            (record["action"], record["arg_hash"])
            != (action, digest)
            # F2: same shape rule as the query path. Unreachable
            # without mid-session tampering (startup verification
            # and the writers forbid malformed rows); fail closed
            # as a conflict so nothing executes on bad evidence.
            or not self._operation_record_valid(record)
        ):
            return None, True
        return record, False

    def _duplicate_return(self, actor, digest, record, token=None):
        """Answer from the stored receipt; never executes anything.

        The receipt is first bound to durable journal/OUTCOME
        evidence; on mismatch the gate degrades and reports an
        error instead of returning a falsified outcome. Records a
        ``decision`` audit event (kind ``decision`` carries no
        journal obligation, so reconciliation and cross-checks are
        unaffected) and returns the committed receipt verbatim with
        a duplicate marker. The caller learns the original outcome.
        """
        problem = operation_receipt_consistent(
            record["action"], record["arg_hash"], record["receipt"],
            self._journal.entries(), self._audit.records,
        )
        if problem is not None:
            self._set_degraded(
                "operation_unverifiable",
                "stored receipt inconsistent with evidence: %s"
                % (problem,),
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_OPERATION_UNVERIFIABLE,
            }
        try:
            self._record(
                kind="decision", actor=actor,
                action=record["action"], arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision="duplicate", reason=REASON_OK,
                token_id=(
                    ConfirmationStore.token_id(token)
                    if token is not None else None
                ),
            )
        except AuditError:
            self._set_degraded(
                "audit_unavailable",
                "duplicate decision unrecorded; nothing executed",
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_AUDIT_UNAVAILABLE,
            }
        return {
            "status": STATUS_ALLOWED,
            "reason": REASON_OK,
            "receipt": record["receipt"],
            "duplicate": True,
        }

    def _transfer_initial(self, actor, args, digest, key):
        if key is not None:
            # Identity before authorization: a committed outcome is
            # historical fact and must be returned even if live
            # policy would deny a fresh attempt. Pending and absent
            # keys still pass policy evaluation below.
            record, conflict = self._lookup_keyed_operation(
                key, ACTION_TRANSFER, digest
            )
            if conflict:
                return self._deny(
                    REASON_OPERATION_CONFLICT,
                    action=ACTION_TRANSFER, digest=digest,
                    actor=actor,
                )
            if record is not None and record["status"] == "committed":
                return self._duplicate_return(actor, digest, record)
        else:
            record = None
        permitted, reason = evaluate(
            self._storage.get_policy(), ACTION_TRANSFER, args,
            self._live_state()
        )
        if not permitted:
            return self._deny(
                reason, action=ACTION_TRANSFER, digest=digest,
                actor=actor,
            )
        if key is not None and record is None:
            self._storage.register_operation(
                key, ACTION_TRANSFER, digest, actor
            )
        token = self._confirmations.issue(
            ACTION_TRANSFER, digest,
            self._storage.get_policy().version,
            op_key=key,
        )
        try:
            self._record(
                kind="decision", actor=actor, action=ACTION_TRANSFER,
                arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision=STATUS_CONFIRMATION_REQUIRED, reason=REASON_OK,
                token_id=ConfirmationStore.token_id(token),
            )
        except AuditError:
            self._set_degraded(
                "audit_unavailable",
                "confirmation decision unrecorded; issued token dies "
                "with the store at reset",
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_AUDIT_UNAVAILABLE,
            }
        return {
            "status": STATUS_CONFIRMATION_REQUIRED,
            "reason": REASON_OK,
            "confirmation": token,
        }

    def _transfer_redeem(self, actor, args, digest, token, key):
        try:
            self._confirmations.check(
                token, ACTION_TRANSFER, digest,
                self._storage.get_policy().version,
            )
        except ConfirmationError as exc:
            return self._deny(
                exc.reason, action=ACTION_TRANSFER, digest=digest,
                actor=actor,
            )
        # Keyed identity resolution, before any authorization or
        # mutation. Epoch/single-use checks above still govern the
        # token itself; the operation record governs at-most-once.
        token_op = self._storage.get_token_operation_key(token)
        if (
            key is not None and token_op is not None
            and key != token_op
        ):
            return self._deny(
                REASON_OPERATION_CONFLICT,
                action=ACTION_TRANSFER, digest=digest,
                actor=actor,
            )
        op_key = token_op if token_op is not None else key
        record = None
        if op_key is not None:
            record, conflict = self._lookup_keyed_operation(
                op_key, ACTION_TRANSFER, digest
            )
            if conflict:
                return self._deny(
                    REASON_OPERATION_CONFLICT,
                    action=ACTION_TRANSFER, digest=digest,
                    actor=actor,
                )
            if record is None and token_op is not None:
                # Linked operation row missing: identity evidence is
                # inconsistent (startup verification forbids this, so
                # only mid-session tampering reaches here). Fail
                # closed without executing.
                return self._deny(
                    REASON_OPERATION_CONFLICT,
                    action=ACTION_TRANSFER, digest=digest,
                    actor=actor,
                )
            if record is not None and record["status"] == "committed":
                return self._duplicate_return(
                    actor, digest, record, token
                )
        permitted, reason = evaluate(
            self._storage.get_policy(), ACTION_TRANSFER, args,
            self._live_state()
        )
        if not permitted:
            return self._deny(
                reason, action=ACTION_TRANSFER, digest=digest,
                actor=actor,
            )
        token_id = ConfirmationStore.token_id(token)
        try:
            self._record(
                kind="authorized", actor=actor, action=ACTION_TRANSFER,
                arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision="authorized", reason=REASON_OK,
                token_id=token_id,
            )
        except AuditError:
            self._set_degraded(
                "audit_unavailable",
                "AUTHORIZED unrecorded; token not consumed, no mutation",
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_AUDIT_UNAVAILABLE,
            }
        if op_key is not None and record is None:
            # Keyed request on an unlinked token: bind the identity
            # before anything executes, so the attempt cannot escape
            # idempotency even if this response is lost.
            self._storage.register_operation(
                op_key, ACTION_TRANSFER, digest, actor
            )
            self._storage.link_token_operation(token, op_key)
        try:
            self._confirmations.consume(token)
        except ConfirmationError:
            # Defensive: unreachable while check-then-consume is
            # serialized under the gate lock. No mutation occurred and
            # nothing diverged, so no degraded mode is set.
            self._best_effort_outcome(
                actor, digest, token_id, STATUS_ERROR,
                REASON_TOKEN_COMMIT_FAILED, None,
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_EXECUTION_FAILED,
            }
        entry = self._journal.append_transfer(
            args["source"], args["target"], args["amount"]
        )
        try:
            new_source, new_target = apply_transfer(
                self._mutator, args["source"], args["target"],
                args["amount"],
            )
        except Exception as exc:
            if isinstance(exc, (sqlite3.Error, SQLiteBackendError)):
                # Storage faults are not ledger logic faults: let the
                # transaction roll back and the storage boundary report
                # them. Fault-hook RuntimeErrors still land below.
                raise
            self._set_degraded(
                "journal_ledger_divergence",
                "journal seq %d appended; ledger apply failed: %s"
                % (entry.seq, exc),
                journal_seq=entry.seq,
            )
            self._best_effort_outcome(
                actor, digest, token_id, STATUS_ERROR,
                REASON_EXECUTION_FAILED, entry.seq,
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_EXECUTION_FAILED,
            }
        self._storage.add_daily_spent(args["amount"])
        try:
            self._record(
                kind="outcome", actor=actor, action=ACTION_TRANSFER,
                arg_hash=digest,
                policy_version=self._storage.get_policy().version,
                decision=STATUS_ALLOWED, reason=REASON_OK,
                token_id=token_id,
                extra={
                    "journal_seq": entry.seq,
                    "source_balance": new_source,
                    "target_balance": new_target,
                },
            )
        except AuditError:
            self._set_degraded(
                "outcome_unrecorded",
                "mutation applied (journal seq %d); OUTCOME "
                "unrecorded" % entry.seq,
                journal_seq=entry.seq,
            )
            return {
                "status": STATUS_EXECUTED_RECORDING_FAILED,
                "reason": REASON_OUTCOME_UNRECORDED,
                "journal_seq": entry.seq,
                "source": args["source"],
                "target": args["target"],
                "amount": args["amount"],
            }
        receipt = {
            "action": ACTION_TRANSFER,
            "source": args["source"],
            "target": args["target"],
            "amount": args["amount"],
            "journal_seq": entry.seq,
            "source_balance": new_source,
            "target_balance": new_target,
            "policy_version": self._storage.get_policy().version,
        }
        if op_key is not None:
            # Atomic with everything above: the committed outcome
            # and its receipt land in the same transaction as the
            # consumption, journal, ledger, and audit writes.
            self._storage.complete_operation(op_key, receipt)
        return {
            "status": STATUS_ALLOWED,
            "reason": REASON_OK,
            "receipt": receipt,
        }

    # ------------------------------------------------------------------
    # operator methods
    # ------------------------------------------------------------------

    @_with_storage_boundary
    def update_policy(self, new_policy):
        """Validate, record, and activate *new_policy* atomically."""
        with self._lock, self._storage.transaction():
            if self._degraded is not None:
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_DEGRADED,
                }
            if not isinstance(new_policy, Policy):
                raise TypeError("new_policy must be a Policy")
            try:
                validate_policy_fields(
                    version=new_policy.version,
                    per_transfer_cap=new_policy.per_transfer_cap,
                    daily_cap=new_policy.daily_cap,
                    allowed_targets=new_policy.allowed_targets,
                )
            except Exception:
                return self._reject_policy_update(
                    new_policy, REASON_INVALID_POLICY
                )
            if new_policy.version == self._storage.get_policy().version:
                return self._reject_policy_update(
                    new_policy, REASON_VERSION_UNCHANGED
                )
            if new_policy.version in self._storage.retired_versions():
                return self._reject_policy_update(
                    new_policy, REASON_VERSION_REUSED
                )
            old_version = self._storage.get_policy().version
            # Count first, mutate later: the audit record must carry
            # the invalidation count, but no state may change before
            # the record succeeds. Under the gate lock (and the SQLite
            # transaction) nothing can interleave, so the later purge
            # removes exactly the counted tokens.
            purged = self._confirmations.count_version(old_version)
            try:
                self._record(
                    kind="policy_updated", actor="operator",
                    action="update_policy", arg_hash="",
                    policy_version=new_policy.version,
                    decision="recorded", reason=REASON_OK,
                    extra={
                        "old_version": old_version,
                        "new_version": new_policy.version,
                        "purged": purged,
                    },
                )
            except AuditError:
                self._set_degraded(
                    "audit_unavailable",
                    "policy update unrecorded; old policy retained",
                )
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_AUDIT_UNAVAILABLE,
                }
            self._confirmations.purge_version(old_version)
            self._storage.activate_policy(new_policy)
            self._storage.reset_daily_spent()
            return {
                "status": STATUS_POLICY_UPDATED,
                "reason": REASON_OK,
                "old_version": old_version,
                "new_version": new_policy.version,
                "purged": purged,
            }

    def _reject_policy_update(self, new_policy, reason):
        try:
            self._record(
                kind="policy_update_rejected", actor="operator",
                action="update_policy", arg_hash="",
                policy_version=self._storage.get_policy().version,
                decision=STATUS_DENIED, reason=reason,
                extra={
                    "proposed_version": getattr(
                        new_policy, "version", "?"
                    )
                },
            )
        except AuditError:
            self._set_degraded(
                "audit_unavailable",
                "policy rejection unrecorded; policy unchanged",
            )
            return {
                "status": STATUS_ERROR,
                "reason": REASON_AUDIT_UNAVAILABLE,
            }
        return {"status": STATUS_DENIED, "reason": reason}

    @_with_storage_boundary
    def operator_reset(self):
        """Clear degraded mode after verifying a clean state.

        Refuses while reconciliation, journal/audit cross-check, or
        audit verification reports any problem; those states require
        reconstruction of a fresh instance instead.
        """
        with self._lock, self._storage.transaction():
            if self._degraded is None:
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_NOT_DEGRADED,
                }
            report = reconcile(
                self._opening, self._journal.entries(),
                self._ledger.snapshot(),
            )
            if not report["clean"]:
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_RESET_REFUSED,
                    "detail": report,
                }
            cross = cross_check_journal_audit(
                self._journal.entries(), self._audit.records
            )
            if not cross["clean"]:
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_RESET_REFUSED,
                    "detail": cross,
                }
            ok, detail = self._audit.verify()
            if not ok:
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_RESET_REFUSED,
                    "detail": detail,
                }
            try:
                self._record(
                    kind="degraded_cleared", actor="operator",
                    action="operator_reset", arg_hash="",
                    policy_version=self._storage.get_policy().version,
                    decision="recorded", reason=REASON_OK,
                    extra={"incident": self._degraded["case"]},
                )
            except AuditError:
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_AUDIT_UNAVAILABLE,
                }
            cleared = self._confirmations.clear()
            self._degraded = None
            return {
                "status": STATUS_RESET,
                "reason": REASON_OK,
                "cleared_tokens": cleared,
            }

    def status(self):
        """Return a read-only health snapshot (safe while degraded)."""
        with self._lock:
            return {
                "degraded": self._degraded is not None,
                "incident": dict(self._degraded)
                if self._degraded is not None else None,
                "policy_version": self._storage.get_policy().version,
                "daily_spent": self._storage.get_daily_spent(),
                "audit_records": len(self._audit),
                "journal_entries": len(self._journal),
                "pending_confirmations":
                    self._confirmations.pending_count(),
            }

    def operation_status(self, key, action=None, args=None):
        """Look up a caller operation by idempotency key. Read-only.

        Returns ``committed`` (with the stored receipt), ``pending``,
        or ``not_found``. ``not_found`` means no record exists in
        this healthy database — never proof of non-execution
        elsewhere. When ``action``/``args`` are supplied they are
        validated and their fingerprint compared, yielding
        ``conflict`` on mismatch. Never redeems, never mutates, never
        authorizes a stale confirmation. Works while degraded; fails
        closed with an ``error`` result when the record cannot be
        read or verified.
        """
        if not is_valid_idempotency_key(key):
            raise ValueError("invalid idempotency_key")
        digest = None
        if action is not None or args is not None:
            if action != ACTION_TRANSFER or args is None:
                raise ValueError(
                    "fingerprint requires the transfer action and args"
                )
            try:
                normalized = validate_args(action, args)
            except ValidationError as exc:
                raise ValueError("invalid fingerprint args") from exc
            digest = arg_hash(normalized)
        with self._lock:
            try:
                record = self._storage.get_operation(key)
            except sqlite3.Error:
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_STORAGE_UNAVAILABLE,
                }
            except SQLiteBackendError:
                # The store answered but its record is invalid
                # (e.g. unparseable receipt): data present, truth
                # unavailable. Never mistaken for not_found.
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_OPERATION_UNVERIFIABLE,
                }
            if record is None:
                return {"status": "not_found", "key": key}
            if not self._operation_record_valid(record):
                return {
                    "status": STATUS_ERROR,
                    "reason": REASON_OPERATION_UNVERIFIABLE,
                }
            if digest is not None and (
                record["action"], record["arg_hash"]
            ) != (action, digest):
                return {"status": "conflict", "key": key}
            if record["status"] == "committed":
                problem = operation_receipt_consistent(
                    record["action"], record["arg_hash"],
                    record["receipt"], self._journal.entries(),
                    self._audit.records,
                )
                if problem is not None:
                    return {
                        "status": STATUS_ERROR,
                        "reason": REASON_OPERATION_UNVERIFIABLE,
                    }
                return {
                    "status": "committed",
                    "key": key,
                    "receipt": record["receipt"],
                }
            return {"status": "pending", "key": key}

    @staticmethod
    def _operation_record_valid(record):
        """Fail-closed shape check for a stored operation record."""
        if record["status"] == "committed":
            receipt_ok = isinstance(record["receipt"], dict)
        elif record["status"] == "pending":
            receipt_ok = record["receipt"] is None
        else:
            return False
        return (
            isinstance(record["action"], str)
            and bool(record["action"])
            and isinstance(record["arg_hash"], str)
            and bool(record["arg_hash"])
            and receipt_ok
        )

    @_with_storage_boundary
    def check_health(self):
        """Reconcile, cross-check, and verify; report the findings.

        Appends a ``verification`` record only when a problem is found
        (best effort); a healthy check is read-only. A detected problem
        degrades the gate immediately so no further protected mutation
        is possible until recovery; an existing incident is never
        overwritten.
        """
        with self._lock, self._storage.transaction():
            recon = reconcile(
                self._opening, self._journal.entries(),
                self._ledger.snapshot(),
                incident_ref=self._degraded["case"]
                if self._degraded is not None else None,
            )
            cross = cross_check_journal_audit(
                self._journal.entries(), self._audit.records
            )
            ok, detail = self._audit.verify()
            report = {
                "reconcile": recon,
                "cross_check": cross,
                "audit": {"ok": ok, "detail": detail},
                "degraded": self._degraded is not None,
                "newly_degraded": False,
            }
            if recon["clean"] and cross["clean"] and ok:
                return report
            if recon["journal_ahead"] is not None:
                reason = "journal_ahead"
            elif not recon["clean"]:
                reason = "balance_mismatch"
            elif not cross["clean"]:
                reason = "audit_gap"
            else:
                reason = "audit_corrupt"
            if self._degraded is None:
                self._set_degraded(
                    "verification_mismatch",
                    "check_health detected: %s" % reason,
                )
                report["newly_degraded"] = True
            report["degraded"] = self._degraded is not None
            try:
                self._record(
                    kind="verification", actor="operator",
                    action="reconcile", arg_hash="",
                    policy_version=self._storage.get_policy().version,
                    decision="mismatch", reason=reason,
                    extra={"report": "see operator log"},
                )
            except AuditError:
                report["verification_record"] = "unwritable"
            return report

    # ------------------------------------------------------------------
    # read-only accessors (copies only)
    # ------------------------------------------------------------------

    def ledger_snapshot(self):
        """Return a copy of current balances."""
        with self._lock:
            return self._ledger.snapshot()

    def journal_entries(self):
        """Return an immutable snapshot of journal entries."""
        with self._lock:
            return self._journal.entries()

    def audit_records(self):
        """Return copies of the audit records."""
        with self._lock:
            return self._audit.records

    def export_audit(self, path):
        """Write a read-only snapshot of the audit log; return report.

        The export derives from the authoritative in-memory log, so the
        two can never disagree. Export I/O errors propagate to the
        caller and never affect gate state.
        """
        with self._lock:
            return self._audit.export_jsonl(path)

    def current_policy(self):
        """Return the active (frozen) policy."""
        with self._lock:
            return self._storage.get_policy()


def create_gate(*, policy=None, balances=None, ttl_seconds=None,
                clock=None, prior_export_hash=None, storage=None):
    """Create a :class:`Gate` with demo defaults unless overridden."""
    if policy is None:
        policy = Policy.create(
            version="v1",
            per_transfer_cap=500,
            daily_cap=1000,
            allowed_targets=("bob", "carol"),
        )
    if balances is None and storage is None:
        balances = {"alice": 10000}
    return Gate(
        policy=policy,
        balances=balances,
        ttl_seconds=ttl_seconds,
        clock=clock,
        prior_export_hash=prior_export_hash,
        storage=storage,
    )
