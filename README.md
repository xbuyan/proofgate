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
epoch rules still govern every token. Keys are bearer identifiers:
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
  middle-record deletions and reorderings. Tail truncation cannot be
  reliably detected without an independently preserved expected-length
  checkpoint, which this prototype does not implement.
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

Three outcomes cover every failure, distinguished so callers can reason:

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
