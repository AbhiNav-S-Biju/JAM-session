"""CageWatch evidence vault (A7): append-only, hash-chained evidence per incident.

Layout:  shared/runtime/evidence/<incident_id>/
           events.jsonl   copy of the run's events (made by the responder, refreshed at run end)
           capture.pcap   copy of the network capture
           chain.jsonl    the hash chain (this module)
         shared/runtime/anchors.log   one line per seal: incident, chain head, time (print it in the report)

Chain line: {"seq": n, "ts": ..., "record": {...}, "prev_hash": "sha256:<hex>", "hash": "sha256:<hex>"}
  hex_n      = sha256( hex_{n-1} + canonical_json(record_n) )   (UTF-8; hex without the "sha256:" prefix)
  hex_0 prev = "0" * 64                                          (genesis)
  canonical_json = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

Changing, removing or reordering any line breaks every hash after it, so verify_chain() names the first bad seq.
The chain is append-only: sealing again only adds records that are not in it yet.

CLI:
  python3 engine/evidence/vault.py verify <incident_id|path/to/chain.jsonl>
  python3 engine/evidence/vault.py tamper-test <incident_id>   (edits a COPY, shows verification failing)
  python3 engine/evidence/vault.py seal <incident_id>          (re-seal from incidents.json)
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUNTIME = os.path.join(ROOT, "shared", "runtime")
POLICY = os.path.join(ROOT, "shared", "policy.json")
GENESIS = "0" * 64


def iso(t=None):
    t = time.time() if t is None else t
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(t * 1000) % 1000:03d}Z"


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def link_hash(prev_hex, record):
    return hashlib.sha256((prev_hex + canonical_json(record)).encode("utf-8")).hexdigest()


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def strip(h):
    return h.split(":", 1)[1] if h.startswith("sha256:") else h


def incident_dir(incident_id):
    return os.path.join(RUNTIME, "evidence", incident_id)


# ---------------- verify ----------------

def verify_chain(path):
    """Returns (ok, info). info: length, head, and on failure first_bad_seq + reason."""
    prev, n, head = GENESIS, 0, None
    try:
        lines = [l for l in open(path, encoding="utf-8") if l.strip()]
    except OSError as e:
        return False, {"length": 0, "head": None, "first_bad_seq": None, "reason": f"cannot read chain: {e}"}
    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            return False, {"length": i, "head": head, "first_bad_seq": i, "reason": "line is not valid JSON"}
        if entry.get("seq") != i:
            return False, {"length": i, "head": head, "first_bad_seq": i, "reason": f"seq {entry.get('seq')} out of order"}
        if strip(entry.get("prev_hash", "")) != prev:
            return False, {"length": i, "head": head, "first_bad_seq": i, "reason": "prev_hash does not match previous line"}
        expect = link_hash(prev, entry.get("record"))
        if strip(entry.get("hash", "")) != expect:
            return False, {"length": i, "head": head, "first_bad_seq": i,
                           "reason": "record was modified (hash mismatch)"}
        prev, head, n = expect, "sha256:" + expect, i + 1
    return True, {"length": n, "head": head, "first_bad_seq": None, "reason": None}


# ---------------- seal ----------------

def _record_key(rec):
    t = rec["type"]
    if t == "event":
        return "event:" + rec["event"]["id"]
    if t == "action":
        return f"action:{rec['action']}:{rec['ts']}"
    if t == "file":
        return f"file:{rec['name']}:{rec['sha256']}"
    if t == "incident_state":
        return "state:" + canonical_json({k: rec[k] for k in ("status", "risk_score", "chain", "rules")})
    return t + ":" + canonical_json(rec)


def _read_chain(path):
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def _snapshot_files(inc):
    """Refresh the copies of events (only this run) and pcap inside the evidence dir."""
    d = incident_dir(inc["incident_id"])
    os.makedirs(d, exist_ok=True)
    src = os.path.join(RUNTIME, "events.jsonl")
    if os.path.exists(src):
        lines = [l for l in open(src, encoding="utf-8") if l.strip()]
        lines = [l for l in lines if json.loads(l).get("run_id") == inc["run_id"]]
        if lines:
            with open(os.path.join(d, "events.jsonl"), "w", encoding="utf-8") as f:
                f.writelines(lines)
    pcap = os.path.join(RUNTIME, "capture.pcap")
    if os.path.exists(pcap):
        shutil.copy2(pcap, os.path.join(d, "capture.pcap"))
    return d


def seal(inc, refresh=True):
    """Append any new evidence for this incident to its chain. Safe to call many times."""
    d = _snapshot_files(inc) if refresh else incident_dir(inc["incident_id"])
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "chain.jsonl")

    existing = _read_chain(path)
    if existing:
        ok, info = verify_chain(path)
        if not ok:  # never extend a broken chain: that would hide the tampering
            raise RuntimeError(f"refusing to extend tampered chain at seq {info['first_bad_seq']}: {info['reason']}")
    seen = {_record_key(e["record"]) for e in existing}
    prev = strip(existing[-1]["hash"]) if existing else GENESIS

    new = []
    if not existing:
        new.append({"type": "incident_opened", "incident_id": inc["incident_id"], "run_id": inc["run_id"],
                    "first_event_ts": inc.get("first_event_ts"),
                    "policy_sha256": "sha256:" + file_sha256(POLICY) if os.path.exists(POLICY) else None})
    ev_path = os.path.join(d, "events.jsonl")
    if os.path.exists(ev_path):
        for l in open(ev_path, encoding="utf-8"):
            if l.strip():
                new.append({"type": "event", "event": json.loads(l)})
    for a in inc.get("actions_taken", []):
        new.append({"type": "action", **a})
    for name in ("events.jsonl", "capture.pcap"):
        p = os.path.join(d, name)
        if os.path.exists(p):
            new.append({"type": "file", "name": name, "sha256": "sha256:" + file_sha256(p), "bytes": os.path.getsize(p)})
    new.append({"type": "incident_state", "status": inc.get("status"), "severity": inc.get("severity"),
                "risk_score": inc.get("risk_score"), "chain": inc.get("chain"),
                "rules": [r["rule_id"] for r in inc.get("rules_triggered", [])],
                "time_to_detect_ms": inc.get("time_to_detect_ms"), "time_to_contain_ms": inc.get("time_to_contain_ms")})

    added = 0
    with open(path, "a", encoding="utf-8") as f:
        for rec in new:
            k = _record_key(rec)
            if k in seen:
                continue
            seen.add(k)
            h = link_hash(prev, rec)
            f.write(canonical_json({"seq": len(existing) + added, "ts": iso(), "record": rec,
                                    "prev_hash": "sha256:" + prev, "hash": "sha256:" + h}) + "\n")
            prev, added = h, added + 1

    head = "sha256:" + prev
    inc["evidence"]["chain"] = f"evidence/{inc['incident_id']}/chain.jsonl"
    inc["evidence"]["chain_head"] = head
    inc["evidence"]["chain_length"] = len(existing) + added
    if os.path.exists(ev_path):
        inc["evidence"]["log"] = f"evidence/{inc['incident_id']}/events.jsonl"
    if os.path.exists(os.path.join(d, "capture.pcap")):
        inc["evidence"]["pcap"] = f"evidence/{inc['incident_id']}/capture.pcap"
    if added:
        with open(os.path.join(RUNTIME, "anchors.log"), "a", encoding="utf-8") as f:
            f.write(f"{iso()} {inc['incident_id']} length={len(existing) + added} head={head}\n")
    _save_incident(inc)
    return head, added


def _save_incident(inc):
    try:
        from engine.detect import rules
        with rules.LOCK:
            rules.upsert_incident(inc)
    except ImportError:
        p = os.path.join(RUNTIME, "incidents.json")
        items = json.load(open(p)) if os.path.exists(p) else []
        items = [i for i in items if i["incident_id"] != inc["incident_id"]] + [inc]
        tmp = p + ".tmp"
        json.dump(items, open(tmp, "w"), indent=2)
        os.replace(tmp, p)


# ---------------- CLI ----------------

def _chain_path(arg):
    return arg if arg.endswith(".jsonl") else os.path.join(incident_dir(arg), "chain.jsonl")


def main(argv):
    if len(argv) < 3 or argv[1] not in ("verify", "tamper-test", "seal"):
        print(__doc__)
        return 2
    cmd, target = argv[1], argv[2]
    if cmd == "verify":
        ok, info = verify_chain(_chain_path(target))
        print(("VALID  " if ok else "BROKEN ") + json.dumps(info))
        return 0 if ok else 1
    if cmd == "tamper-test":
        src = _chain_path(target)
        ok, info = verify_chain(src)
        print("original :", "VALID" if ok else "BROKEN", json.dumps(info))
        lines = open(src, encoding="utf-8").read().splitlines()
        # An attacker covering tracks: rewrite the first VIOLATION so it looks like a harmless read.
        victim = next((i for i, l in enumerate(lines)
                       if json.loads(l)["record"].get("type") == "event"
                       and json.loads(l)["record"]["event"].get("verdict") == "violation"), None)
        if victim is None:
            print("no violation event in this chain to tamper with")
            return 1
        entry = json.loads(lines[victim])
        ev = entry["record"]["event"]
        print(f"tampering: seq {victim} = {ev['id']} {ev['type']} {ev['detail'].get('path') or ev['detail'].get('dst_ip')}"
              f" verdict={ev['verdict']}  -> rewritten as verdict 'allow' on /data/authorized/report.txt")
        ev["verdict"] = "allow"
        ev["detail"] = {"path": "/data/authorized/report.txt"}
        ev["type"] = "file_read"
        lines[victim] = canonical_json(entry)
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as t:
            t.write("\n".join(lines) + "\n")
        ok2, info2 = verify_chain(t.name)
        print("tampered :", "VALID" if ok2 else "BROKEN", json.dumps(info2))
        os.unlink(t.name)
        return 0 if (ok and not ok2) else 1
    if cmd == "seal":
        sys.path.insert(0, ROOT)
        items = json.load(open(os.path.join(RUNTIME, "incidents.json")))
        inc = next(i for i in items if i["incident_id"] == target)
        head, added = seal(inc)
        print(f"sealed {target}: +{added} records, head {head}")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
