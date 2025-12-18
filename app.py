# app.py — SCPCE1 unified, corrected CLI for the Persistent Context Engine
from __future__ import annotations

import sys
import json
import hashlib
import os
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pce import api
from pce.storage import MEMORY_FILE, load_all
from pce.schema import RecapFrame, ContextBundle

# =============================================================================
# Engine Metadata
# =============================================================================

ENGINE_VERSION = "SCPCE1"
SCHEMA_VERSION = 2

MEMORY_DIR = os.path.dirname(MEMORY_FILE) or "memory"
SNAPSHOT_DIR = os.path.join(MEMORY_DIR, "snapshots")
FORENSIC_DIR = os.path.join(MEMORY_DIR, "forensics")
CHECKPOINTS_FILE = os.path.join(MEMORY_DIR, "checkpoints.json")

# =============================================================================
# Banner
# =============================================================================

BANNER = f"""
===================================================
      {ENGINE_VERSION} — Persistent Context Engine CLI
===================================================
Commands:
  save
  load
  search <keyword>
  tail [n]
  frame <id>
  verify [--strict] [--invariants]
  snapshot
  forensic
  checkpoint [--id ID]
  rollback <checkpoint_id>
  replay --from A --to B [--diff]
  shell
  help
  exit
===================================================
"""

# =============================================================================
# Utility Primitives
# =============================================================================


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def mkdirp(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def safe_int(v: str, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def pretty(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


# =============================================================================
# Serialization & Hashing (EXPLICIT CONTRACT)
# =============================================================================

HASH_EXCLUDE_FIELDS = {"hash"}


def frame_to_dict(frame: Any) -> Dict[str, Any]:
    """
    Canonical frame serialization for hashing and inspection.
    """
    if hasattr(frame, "to_dict") and callable(frame.to_dict):
        d = frame.to_dict()
    elif is_dataclass(frame):
        d = asdict(frame)
    else:
        d = dict(vars(frame))

    return dict(d)


def canonical_bytes(d: Dict[str, Any]) -> bytes:
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_frame_hash(frame: Any) -> str:
    """
    Deterministic semantic hash of a frame.
    Hash scope is explicitly defined as:
      - all serialized fields EXCEPT 'hash'
    """
    d = frame_to_dict(frame)
    for k in HASH_EXCLUDE_FIELDS:
        d.pop(k, None)
    return sha256_hex(canonical_bytes(d))


def compute_bundle_hash(bundle: Dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(bundle))


# =============================================================================
# Attribute Helpers
# =============================================================================


def get_attr(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default)


def set_attr(obj: Any, name: str, value: Any) -> None:
    try:
        setattr(obj, name, value)
    except Exception:
        pass


# =============================================================================
# Verification Core
# =============================================================================

class VerificationResult:
    def __init__(self) -> None:
        self.ok = True
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def fail(self, msg: str) -> None:
        self.ok = False
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def report(self) -> None:
        print("[OK]" if self.ok else "[ERROR]")
        for w in self.warnings:
            print(f"  [WARN] {w}")
        for e in self.errors:
            print(f"  [FAIL] {e}")


def parse_iso(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def verify_chain(strict: bool) -> VerificationResult:
    res = VerificationResult()

    if not os.path.exists(MEMORY_FILE):
        res.warn("No memory file present.")
        return res

    frames = load_all()
    prev_hash = None
    prev_seq = None
    prev_ts = None

    for idx, f in enumerate(frames):
        stored_hash = get_attr(f, "hash")
        computed = compute_frame_hash(f)

        if strict and not stored_hash:
            res.fail(f"Frame {idx}: missing hash")
        if stored_hash and stored_hash != computed:
            res.fail(f"Frame {idx}: hash mismatch")

        prev = get_attr(f, "prev_hash")
        if idx == 0:
            if strict and prev not in (None, "", "None"):
                res.fail("Frame 0: prev_hash must be empty")
        else:
            if strict and not prev:
                res.fail(f"Frame {idx}: missing prev_hash")
            if prev and prev_hash and prev != prev_hash:
                res.fail(f"Frame {idx}: prev_hash mismatch")

        seq = get_attr(f, "seq")
        if seq is not None:
            try:
                seq = int(seq)
                if prev_seq is not None and seq <= prev_seq:
                    res.fail(f"Frame {idx}: non-monotonic seq")
                prev_seq = seq
            except Exception:
                res.warn(f"Frame {idx}: invalid seq")

        ts = get_attr(f, "timestamp")
        if ts:
            dt = parse_iso(ts)
            if dt and prev_ts and dt <= prev_ts:
                res.fail(f"Frame {idx}: non-monotonic timestamp")
            if dt:
                prev_ts = dt

        prev_hash = stored_hash or computed

    return res


# =============================================================================
# Invariants
# =============================================================================

def verify_invariants(frames: List[Any]) -> VerificationResult:
    res = VerificationResult()
    if not frames:
        return res

    MAX_ASSISTANT_ONLY = 2
    assistant_only = 0

    def has_user(f: Any) -> bool:
        return bool(get_attr(f, "user", "").strip())

    def has_assistant(f: Any) -> bool:
        return bool(get_attr(f, "assistant", "").strip())

    for idx, f in enumerate(frames):
        u = has_user(f)
        a = has_assistant(f)

        if a and not u:
            assistant_only += 1
            if assistant_only > MAX_ASSISTANT_ONLY:
                res.fail(f"INV-05 violated at frame {idx}")
        else:
            assistant_only = 0

    if not any(has_user(f) for f in frames[-20:]):
        res.fail("INV-04 violated: no recent user input")

    return res


def forensic_lock(strict: bool, check_invariants: bool) -> Tuple[bool, VerificationResult, Optional[VerificationResult]]:
    chain = verify_chain(strict)
    inv = None

    if check_invariants and os.path.exists(MEMORY_FILE):
        inv = verify_invariants(load_all())

    locked = (not chain.ok) or (inv and not inv.ok)
    return locked, chain, inv


# =============================================================================
# Snapshot & Forensics
# =============================================================================

def create_snapshot() -> None:
    frames = load_all()
    mkdirp(SNAPSHOT_DIR)

    snap = {
        "engine_version": ENGINE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now_iso(),
        "frames": [],
    }

    for f in frames:
        d = frame_to_dict(f)
        d["hash"] = get_attr(f, "hash") or compute_frame_hash(f)
        snap["frames"].append(d)

    raw = json.dumps(snap, indent=2, ensure_ascii=False).encode("utf-8")
    path = os.path.join(SNAPSHOT_DIR, f"snapshot_{len(frames):06d}.json")

    with open(path, "wb") as fh:
        fh.write(raw)

    with open(path + ".sha256", "w") as fh:
        fh.write(sha256_hex(raw))

    print(f"[OK] Snapshot written → {path}")


def cmd_forensic() -> None:
    mkdirp(FORENSIC_DIR)
    frames = load_all() if os.path.exists(MEMORY_FILE) else []

    chain = verify_chain(strict=True)
    inv = verify_invariants(frames)

    report = {
        "engine_version": ENGINE_VERSION,
        "created_at": utc_now_iso(),
        "total_frames": len(frames),
        "chain_ok": chain.ok,
        "chain_errors": chain.errors,
        "invariant_ok": inv.ok,
        "invariant_errors": inv.errors,
    }

    path = os.path.join(
        FORENSIC_DIR,
        f"forensic_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json",
    )

    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)

    pretty(report)


# =============================================================================
# Replay (Explicitly Non-Deterministic Without API Support)
# =============================================================================

def cmd_replay(start: int, end: int, diff: bool) -> None:
    frames = load_all()
    if not frames:
        print("[EMPTY]")
        return

    print("[REPLAY] NON-DETERMINISTIC — depends on current storage state")

    prev = None
    for i in range(start, min(end + 1, len(frames))):
        bundle = api.load_context()
        bdict = frame_to_dict(bundle)
        h = compute_bundle_hash(bdict)

        print(f"\n--- Step {i} ---")
        print(f"bundle_hash: {h}")

        if diff and prev:
            print("diff:")
            pretty({k: bdict[k] for k in bdict if prev.get(k) != bdict[k]})

        prev = bdict


# =============================================================================
# Save / Load
# =============================================================================

def cmd_save() -> None:
    locked, chain, inv = forensic_lock(strict=True, check_invariants=True)
    if locked:
        print("[LOCKED] Write refused")
        chain.report()
        if inv:
            inv.report()
        return

    user = input("User: ").strip()
    assistant = input("Assistant: ").strip()

    frame = api.save_context(user, assistant)
    frames = load_all()
    idx = len(frames) - 1

    prev = frames[-2] if idx > 0 else None
    prev_hash = get_attr(prev, "hash") if prev else None

    set_attr(frame, "engine_version", ENGINE_VERSION)
    set_attr(frame, "schema_version", SCHEMA_VERSION)
    set_attr(frame, "seq", idx)
    set_attr(frame, "prev_hash", prev_hash)

    h = compute_frame_hash(frame)
    set_attr(frame, "hash", h)

    print(f"[OK] Saved frame {idx} hash={h}")


def cmd_load() -> None:
    bundle = api.load_context()
    pretty(frame_to_dict(bundle))


# =============================================================================
# Shell / Entry
# =============================================================================

def main(argv: List[str]) -> None:
    if len(argv) == 1:
        print(BANNER)
        return

    cmd = argv[1]
    args = argv[2:]

    if cmd == "save":
        cmd_save()
    elif cmd == "load":
        cmd_load()
    elif cmd == "snapshot":
        create_snapshot()
    elif cmd == "forensic":
        cmd_forensic()
    else:
        print(BANNER)


if __name__ == "__main__":
    main(sys.argv)
