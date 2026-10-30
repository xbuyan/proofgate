# ProofGate

ProofGate is a deterministic authorization gate for consequential tool actions.
Every state-changing request passes through one synchronous enforcement entry
point that validates arguments, evaluates a trusted policy, requires a
server-issued single-use confirmation, revalidates immediately before mutation,
and records hash-chained audit evidence. The prototype is synthetic-only:
balances and transfers are in-memory data structures. There is no real money,
no network, no database, no UI, and no model integration.

## Quick start

Requirements: Python 3.11+ standard library only. No packages to install.

Run the full test suite from the project directory:

```bash
cd /home/lucciano/projects/proofgate && python3 -m unittest discover -s tests
```

Run the deterministic demo (synthetic data, fixed clock, asserted checks):

```bash
cd /home/lucciano/projects/proofgate && python3 demo.py
```

## Architecture

One process, one lock, one gate. The modules under `src/proofgate/` are:

- `enforcement.py` — `Gate` and `create_gate()`. `Gate.gate(request)` is the
  single supported entry point for state-changing operations. It also owns the
  operator methods `update_policy`, `operator_reset`, `status`,
  `check_health`, read-only accessors, and `export_audit`.
- `tools.py` — strict request/argument validation plus the two synthetic
  tools: read-only `get_balance` and capability-gated `transfer_money`.
- `policy.py` — frozen, versioned, in-memory `Policy` and the pure
  `evaluate()` function. No I/O, no clock, no model input.
- `confirmations.py` — `ConfirmationStore`: server-issued, TTL-bound,
  single-use tokens.
- `ledger.py` — `SyntheticLedger` balances plus the gate-held `_Mutator`
  capability. Supported callers cannot obtain a mutator except through the
  gate's critical section.
- `journal.py` — gate-only append-only `Journal` of applied mutations.
- `audit.py` — authoritative in-memory hash-chained `AuditLog`, the chain
  verifier, and read-only `export_jsonl` snapshots.
- `verify.py` — pure `reconcile` (journal replay vs ledger) and
  `cross_check_journal_audit` (every journal entry needs a successful
  OUTCOME record).
- `canonical.py` — canonical JSON bytes and SHA-256 argument hashing.

## Supported operations

- `get_balance {"account"}` — read-only. Validated, policy-authorized,
  audited. Never mutates state and never appends to the journal.
- `transfer_money {"source", "target", "amount"}` — state-changing. Always
  requires a two-step confirmation flow: an initial request returns
  `confirmation_required` with a token, and a second request redeeming that
  token executes the transfer.

Unknown tools are denied with `unknown_tool`. Malformed requests — wrong
keys, extra keys, wrong types, non-positive or boolean amounts, empty or
identical parties, a confirmation on a read-only call — are denied with
`invalid_arguments`.

## Validation, authorization, confirmation

1. The request shape and arguments are strictly validated first.
2. The current trusted policy is evaluated against live balances and the
   instance's spent counter (per-transfer cap, daily cap, allowed targets,
   sufficient funds).
3. A permitted transfer is issued a token bound to the exact triple of
   (action, canonical-argument hash, policy version). Only an 8-character
   `token_id` prefix ever appears in audit records; the full token is
   returned to the caller alone.
4. Redemption re-checks the token (existence, single-use, expiry at a
   300-second TTL, version binding, action/argument binding) and then
   re-evaluates policy and live limits before anything mutates.
5. Check-then-consume is serialized under the gate lock: failed checks never
   consume the token, and consumption happens after the AUTHORIZED record is
   appended but before the journal and ledger are touched.

## Policy updates and live revalidation

`update_policy()` runs under the same lock: it re-validates all fields
(direct dataclass construction bypasses `Policy.create`, so validation is
repeated here), rejects the current version and any previously used version
(a retired-version set blocks rollback revival), counts old-version tokens,
appends the `policy_updated` record, then purges, activates the new policy,
and resets the spent counter to start a new epoch.

Purge ordering note: the gate counts old-version tokens first so the
purged count is recorded in the event, but the purge itself runs only
after the `policy_updated` append succeeds, followed by activation and
the spent-counter reset. If the append fails, nothing changes — the old
policy stays active with its tokens intact — and the gate enters
degraded mode instead of activating silently.

## Idempotency keys (optional)

A `transfer_money` request may carry `idempotency_key`: a caller-chosen
bearer string (1-128 chars of letters, digits, hyphen, underscore).
Same key plus same action and canonical arguments names the same
intended operation; the key must be chosen before the first attempt so
it survives lost responses and restarts. A retry returns the stored
receipt (`duplicate: true`) instead of executing again; the same key
with different arguments is denied as `operation_conflict` without
executing. `operation_status(key)` reports `committed` (with receipt),
`pending`, `not_found`, or `conflict`; `not_found` means no record in
this database, never proof of non-execution elsewhere. Operation
records survive `operator_reset` and restarts; confirmation expiry and
epoch rules still govern every token. Reopening a database advances
its boot epoch, which invalidates every confirmation token issued
before the restart. Keys are bearer identifiers:
whoever presents one may query or retry its operation — cross-principal
isolation is out of scope.

Scope is strict: within one database, a matching key and fingerprint
causes at most one committed synthetic-ledger transfer. Nothing here
claims exactly-once execution against external services or providers;
absence from this ledger is not proof an external action never ran.

## Audit, journal, ledger, reconciliation

- The in-memory audit list is the only authoritative store. Every gate
  response is recorded unless recording itself fails, in which case the
  response is an explicit error — nothing is ever silently unrecorded.
- Records chain by `prev_hash`/`record_hash` over canonical bytes.
  Verification detects edits that break chain consistency, including
  middle-record deletions and reorderings. Tail truncation — or any
  restoration whose verified audit history ends early — is rejected
  only when checkpoint enforcement is configured and the trusted
  checkpoint (audit sequence plus hash) remains available and
  unchanged; the checkpoint must be preserved independently of the
  database and its backups. This detects nothing if an attacker can
  replace or falsify both artifacts, and it claims no protection
  against arbitrary host-level tampering.
  The regression test
  `test_host_level_rollback_of_database_and_checkpoint_pair` demonstrates
  this boundary: restoring a matching older database and local checkpoint
  is accepted at startup, after which startup appends a new boot-epoch
  record. That new record does not recover the rolled-back operations.
  Protection against this coordinated rollback requires a freshness anchor
  that the host attacker cannot independently restore or falsify; its
  administration, authentication, and failure behavior must be specified
  separately. This test does not establish protection against an attacker
  who can also control that independent anchor or its credentials.
- Files exist only as read-only `export_jsonl` snapshots derived from the
  authoritative list, so two stores can never disagree. `verify_export`
  additionally detects torn trailing lines.
- The journal records each mutation inside the critical section before the
  ledger changes, so any residue is detectable over-recording rather than
  silent mutation.
- `reconcile` replays the journal from opening balances and diffs against
  the ledger; when only the final entry is unexplained it is identified as
  dangling (`journal_ahead` with expected-vs-actual balances). The
  cross-check flags journal entries lacking a successful OUTCOME record.
- `pending_confirmations` in `status()` counts stored token entries,
  including already-consumed ones retained until purge or clear.

## Failure outcomes

The following outcomes distinguish the main failure cases:

- `error` / `audit_unavailable` — recording failed before any mutation.
  Nothing executed, the confirmation was not consumed, degraded mode is set.
- `error` / `execution_failed` — the journal entry was appended but the
  ledger mutation failed. The ledger is known not to have changed, the
  confirmation stays consumed, the AUTHORIZED record and dangling journal
  entry are preserved byte-for-byte, and sticky degraded mode is set. A
  best-effort OUTCOME error record is attempted without overwriting the
  original incident.
- `executed_recording_failed` / `outcome_unrecorded` — the mutation applied
  but the OUTCOME record could not be written. The response names what
  executed (source, target, amount, journal sequence) and degraded mode is
  set. It is never reported as denied.
- `error` / `storage_unavailable` — a storage statement failed and the
  backend observed its rollback succeed. Nothing in the attempt
  committed, the gate is degraded, and no audit evidence is fabricated
  for the rolled-back attempt. This is the known-rollback case only,
  not a blanket claim about every storage error.
- `error` / `outcome_uncertain` — commit failed, or rollback itself
  failed, so the transaction outcome cannot be established. The gate
  is degraded. Treat this as neither success nor denial; resolve it
  through `operation_status` (see Caller recovery).

A potentially executed operation is never reported as `denied`, because a
denial asserts nothing ran. Blurring that line would let callers retry or
reconcile against a false history.

## Degraded mode and operator recovery

While degraded, all protected operations return `error` / `degraded`;
read-only queries are still served whenever their decision record can be
written. `operator_reset()` clears degraded mode only after reconciliation,
the journal/audit cross-check, and audit verification all pass, and it
appends a `degraded_cleared` record plus clears the token store. It refuses
while any divergence residue remains; those states require reconstructing a
fresh instance instead. There is no automatic rollback, silent repair,
truncation, or backfill anywhere.

Reconstruction provenance: a new instance accepts `prior_export_hash`, an
operator-supplied forensic reference string recorded verbatim in its
genesis record. It authenticates nothing, proves no continuity or chain of
custody, and the new instance performs no lookup or validation of the old
bytes. Deliberately, no `prior_verified` field exists.

## Caller recovery

- `denied` — that attempt did not execute. Correct the request and
  submit a new attempt, or abandon it. A denial is returned only
  before any mutation, so it never needs uncertainty handling.
- `allowed` with a receipt — the transfer committed. If
  `duplicate: true`, the receipt is the stored original rather than a
  new execution; use it and stop.
- `error` / `storage_unavailable` — the attempt rolled back and
  nothing committed. Query `operation_status`, then reset or reopen
  before any further transfer.
- `error` / `outcome_uncertain` — commit status is unknown. Assume
  neither success nor failure. Query
  `operation_status(key, action, args)` with the same key, action, and
  arguments; a fingerprint mismatch is reported as `conflict`.
- Status `committed` — use the stored receipt; do not execute again.
- Status `pending` — the operation is recorded but not committed.
  After reset or reopen, resume with the same key and a fresh
  confirmation. Recovery is safe because of the durable pending
  record plus verified storage state, not because of the new token
  alone.
- Status `not_found` — no matching record exists in the currently
  verified database. This is not proof the operation never executed:
  restoring an older backup erases operation records along with
  everything else.
- Status `error` (including `operation_unverifiable`) — stop and
  escalate. Never reinterpret an error as `not_found`, and do not
  retry while the underlying cause remains unresolved. The current
  status cannot establish a trustworthy outcome; resolve the storage
  or integrity problem before querying again or considering further
  action.
- Degraded mode — every `transfer_money` call is refused with `error`
  / `degraded`, including retries that would otherwise return a
  stored duplicate receipt. Recover with `operator_reset()`, which
  requires clean reconciliation, cross-checks, and audit
  verification and clears all confirmation tokens — or reopen, which
  starts an undegraded instance only if startup verification passes.
  Never force reset through a refusal; divergence residue requires
  reconstruction instead.
- Restart — reopening advances the boot epoch, so every pre-restart
  confirmation token is stale. Always obtain a fresh confirmation
  after reopen and never reuse an old token; the same idempotency
  key still deduplicates or resumes across the restart.
- Keyless operations — without a key there is no durable operation
  record, so a keyless retry after an uncertain outcome is a new
  operation that may execute twice. Prefer keys for any transfer the
  caller might retry.

## Backup

An open SQLite database is backed up with `backend.backup(dest)`,
which uses the SQLite backup API (`sqlite3.Connection.backup()`): the
snapshot reflects committed state while the source stays open and
usable, and the destination is verified before success is reported.
The source is never mutated, closed, or advanced by a backup.

Example (synthetic paths):

    backend.backup("/var/backups/proofgate/g-2026-10-29.db")

Copying only the main `.db` file while WAL is active is unsupported
and unsafe: uncheckpointed frames live in `-wal`, so the copy can pass
verification while missing committed transfers. A backup is a
consistent snapshot, not necessarily a current one: restoring an older
valid backup rolls back balances, operation records, and audit
history. This facility provides no rollback protection.

## Checkpoints

A checkpoint is a small JSON file stored outside the database (and
never included in its backup) recording a verified audit-chain head —
sequence plus record hash — bound to an operator-configured
deployment ID. It proves that the recorded audit prefix existed in
this deployment; it proves nothing newer than the last successfully
persisted checkpoint.

An operation counts as checkpointed only when its audit evidence is at
or below the recorded sequence. Commits do not advance the checkpoint
automatically: checkpointing is an explicit operator step, so a
database may legitimately extend its checkpoint.

Initialization is explicit and requires an independently recorded
expected audit head: open the database without enforcement, then call
`backend.checkpoint(path, deployment_id=..., expected_seq=...,
expected_hash=...)` with the sequence and hash from operator records
kept outside the database (for example, a deployment log entry from
the last verified checkpoint advancement). Initialization refuses
unless the verified head matches exactly. Copying the expected values
from the database currently under examination provides no rollback
protection: a restored older database would simply bless itself.
A missing checkpoint never bootstraps trust for an existing database,
and opening never writes the checkpoint file. Never use the database
path itself as the checkpoint destination: replacement is unconditional
and would destroy the database. Prefer `backend.checkpoint()`, which
refuses database-path aliases.

At startup the database must match the checkpoint or verifiably
extend it (full chain verified, checkpoint sequence/hash found in the
chain). A checkpoint ahead of the database, a same-sequence hash
mismatch, a deployment mismatch, or a malformed checkpoint fails
closed. Recovery from a legitimate extension re-verifies the prior
checkpoint in the chain before advancing the file; a newer checkpoint
is never overwritten from an older database state.

Keep the checkpoint on independent storage the database backup cannot
overwrite, with owner-only permissions. Threat scope is database-only
rollback: a host attacker able to rewrite both files is out of scope,
and unkeyed hashes authenticate nothing on their own.

## Verification granularity

Each append re-verifies the previous record's hash link (O(1)). The full
chain is verified on demand by `verify()`, `check_health()`, and before
`operator_reset()`. Consequence: tampering with the latest record fails
closed on the next append, but tampering with a middle record is latent
until the next verification pass — at which point `check_health` degrades
the gate immediately (without overwriting an existing incident) and reset
is refused until reconstruction. Both directions are covered by tests.

## Threat model

In scope: untrusted proposers and inputs through the supported public API —
forged, replayed, expired, mismatched, or superseded confirmations;
malformed arguments; unknown tools; limit and balance violations; audit
tampering detectable by the verifier; concurrent races against limits and
single-use tokens. Out of scope by design: arbitrary code running inside
the same Python process (no memory isolation exists there), the host clock
(audit stamps use wall time; TTL comparisons use a monotonic envelope),
crash recovery, and authenticated caller identity
(`actor` is a self-asserted label).

`KeyboardInterrupt` and `SystemExit` raised during a gate call can
propagate without a response. Because ProofGate currently uses in-memory
state, an embedding host that catches such an exception must not assume
the call either succeeded or failed cleanly. It must treat the gate's
state as suspect, run the available health/reconciliation checks, and
stop using or reconstruct the instance if consistency cannot be
established.

## Limitations (explicit non-claims)

In-memory state only; no crash durability — a process crash loses the
ledger, journal, confirmations, and audit log. Hash chaining without an
external checkpoint cannot detect a full-file rewrite carrying a fresh
valid chain, so nothing here is tamper-proof. No cross-process isolation,
no persistent recovery, no authentication, no production readiness, no
real-money handling, no external service integration, and no live AI-agent
integration. Daily caps accumulate over the instance lifetime (reset only
by policy update); calendar-day rollover is out of scope.

## Test suite map

- `test_canonical.py` — canonical bytes, key-order invariance, rejections.
- `test_policy.py` — frozen model, field validation, evaluator verdicts
  including exact cap boundaries.
- `test_confirmations.py` — lifecycle, binding, expiry boundary, single-use,
  purge/clear, check-without-consume.
- `test_enforcement.py` — gate flows, 21-case malformed battery, token
  flows, reads, transfers, policy updates, ledger/journal units, status.
- `test_bypass.py` — enumerated public-surface probe with valid-arg battery
  and a negative control proving the probe detects mutation.
- `test_audit.py` — chaining, verifier, export round-trip, tamper fixtures,
  response-to-record correspondence.
- `test_verify.py` — reconciliation, cross-check, health checks, provenance
  limits (genuine vs fabricated references).
- `test_concurrency.py` — single-winner redemption race, exact 10/10 capped
  race, mixed load, policy-update atomicity (barriers/joins, no sleeps).
- `test_failures.py` — cases A–D with byte-preservation and reconstruction,
  degraded reads, operator rules, export isolation, defensive branches.
- `test_idempotency.py` — keyed at-most-once transfers, conflicts,
  restarts, expiry, outcome lookup, reset preservation, serialization.
- `test_crash_recovery.py` — real SIGKILL subprocess crashes before and
  after commit on isolated databases, with safe retry (POSIX-only).

## Project layout

```text
src/proofgate/   enforcement, tools, policy, confirmations, ledger,
                 journal, audit, verify, canonical (+ package init)
tests/           test_canonical, test_policy, test_confirmations,
                 test_enforcement, test_bypass, test_audit, test_verify,
                 test_concurrency, test_failures
demo.py          deterministic synthetic demo (stdlib only)
README.md        this file
```
