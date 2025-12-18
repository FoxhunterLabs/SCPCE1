________________________________________
# SCPCE1 — Persistent Context Engine (CLI)

SCPCE1 is an audit-grade command-line interface for managing a Persistent Context Engine (PCE).  
It is designed for **integrity, traceability, and failure-aware operation**, not convenience.

The system treats conversational context as a **hash-chained, append-only log** with explicit
verification, forensic tooling, and controlled rollback.

---

## Design Goals

- **Integrity first** — detect corruption, halt writes on failure
- **Deterministic semantics** — canonical hashing, explicit scope
- **Forensic readiness** — snapshots, reports, and audit artifacts
- **Reversibility** — checkpointed rollback with provenance
- **Graceful degradation** — works even when storage/schema are partially upgraded

This is infrastructure, not a demo.

---

## Core Features

### Hash-Chained Memory
Each frame is cryptographically linked:
- `hash` — semantic frame hash
- `prev_hash` — chain continuity
- `seq` — explicit ordering
- monotonic timestamp checks

Integrity violations trigger **forensic lock mode** (read-only).

---

### Verification & Invariants
Built-in checks include:
- hash correctness
- chain continuity
- sequence monotonicity
- timestamp ordering
- behavioral invariants (e.g. user presence, assistant-only streaks)

Failures are explicit and non-silent.

---

### Snapshots
Creates anchored, portable snapshots:
- full memory capture
- `.sha256` sidecar hash
- suitable for offline verification or incident review

---

### Decision Checkpoints & Rollback
- named decision checkpoints
- rollback only through checkpoints
- pre-rollback snapshot enforced
- post-rollback verification

Rollback is conservative by design.

---

### Forensics
Generates forensic reports including:
- integrity status
- invariant status
- latest frame hash
- snapshot references
- checkpoint inventory

Artifacts are immutable JSON.

---

### Replay (Best-Effort)
Supports replay inspection with:
- bundle hashing
- optional diffs

⚠️ Replay is explicitly **non-deterministic** unless the underlying API supports true incremental replay.

---

## Command Overview

save
load
search
tail [n]
frame
verify [--strict] [--invariants]
snapshot
forensic
checkpoint [--id ID]
rollback <checkpoint_id>
replay --from A --to B [--diff]
shell

---

## Integrity Model (Summary)

- Memory is append-only
- Corruption halts mutation
- Writes are refused while locked
- Hash scope is explicit and stable
- Determinism is never implied without guarantees

This system prefers **safety over liveness**.

---

## Assumptions & Contracts

- `pce.storage` persists frame attributes if present
- `pce.schema` may evolve to formalize hash fields
- CLI enforces integrity; storage should eventually own it

If these assumptions are violated, verification will fail fast.

---

## Non-Goals

- No silent recovery
- No automatic healing
- No speculative determinism
- No hidden mutation

Failures should be visible, explainable, and auditable.

---

## Intended Use

- long-running AI or agent systems
- safety-critical or human-in-the-loop workflows
- research requiring inspectable context evolution
- systems where rollback and provenance matter

---

## License

Internal / experimental.  
Review and adapt before production deployment.
________________________________________
