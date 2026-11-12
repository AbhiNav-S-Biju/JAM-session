"""CageWatch external collector (A4). Runs on the HOST, outside the agent's container.

Merges four feeds into shared/runtime/events.jsonl (contract: CLAUDE.md section 6):
  agent_step  -> `docker logs -f` of the agent (structured step lines the agent prints before acting)
  file        -> `inotifywait` on the host side of the bind-mounted data dirs
  network     -> tcpdump in a helper container on the host network (egress from the sandbox subnet),
                 also writes shared/runtime/capture.pcap
  container   -> `docker events` for the agent (start, pause, unpause, network disconnect, die)

Every system event is linked to the agent step that caused it (`step_id`): the latest step the agent
announced at or before the event's timestamp. Events are buffered briefly and written in time order so
late-arriving step lines still link correctly.

Usage (inside WSL, repo root):
  python3 engine/collector/collector.py --run-id run-attack-01 --until-exit
  (then, in another terminal) engine/sandbox/run_agent.sh attack

Detection (A5) plugs in with --rules module:function. The function gets each event dict and returns a
verdict string (allow|suspicious|violation). Without it every event is written with verdict "allow".
"""
import argparse
import importlib
import json
import os
import queue
import signal
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SANDBOX_DATA = os.path.join(ROOT, "engine", "sandbox", "data")
# host dir -> path as the agent sees it inside the container
MOUNTS = {
    os.path.join(SANDBOX_DATA, "authorized"): "/data/authorized",
    os.path.join(SANDBOX_DATA, "untrusted"): "/data/untrusted",
    os.path.join(SANDBOX_DATA, "secrets"): "/secrets",
}
NETMON_IMAGE = "cagewatch-netmon:latest"
NETMON_NAME = "cagewatch-netmon"
FLUSH_DELAY = 0.4  # seconds to hold events so they can be ordered by timestamp

q = queue.Queue()
stop = threading.Event()


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(t * 1000) % 1000:03d}Z"


def parse_iso(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def put(t, source, typ, detail, step_id=None):
    q.put({"_t": t, "source": source, "type": typ, "detail": detail, "step_id": step_id})


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()


# ---------------- feeds ----------------

def follow_agent_logs(container):
    """Agent stdout. Only JSON step/result lines become events."""
    p = subprocess.Popen(["docker", "logs", "-f", container], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        t = parse_iso(d["ts"]) if "ts" in d else time.time()
        ev = d.get("event")
        if ev == "step":
            put(t, "agent_step", "step",
                {"action": d["action"], "target": d["target"], "reason": d["reason"], "tainted": d["tainted"]},
                d["step_id"])
        elif ev == "result":
            put(t, "agent_step", "step_result", {"ok": d["ok"], "error": d["error"]}, d["step_id"])
        if stop.is_set():
            break
    p.terminate()


def watch_files():
    """inotify on the host side of the mounts. OPEN = the agent opened the file (read or write attempt)."""
    dirs = [d for d in MOUNTS if os.path.isdir(d)]
    p = subprocess.Popen(["inotifywait", "-m", "-r", "-q", "-e", "open,modify,delete,create",
                          "--format", "%e|%w%f", *dirs], stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        t = time.time()
        events, _, host_path = line.rstrip("\n").partition("|")
        if "ISDIR" in events:
            typ = "dir_list"
        elif "OPEN" in events:
            typ = "file_read"
        elif "DELETE" in events:
            typ = "file_delete"
        else:
            typ = "file_write"
        cpath = host_path
        for h, c in MOUNTS.items():
            if host_path.startswith(h):
                cpath = c + host_path[len(h):]
                break
        put(t, "file", typ, {"path": cpath, "host_path": host_path, "inotify": events})
        if stop.is_set():
            break
    p.terminate()


def read_exact(stream, n):
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def parse_packet(pkt):
    """Ethernet + IPv4 + TCP/UDP. Returns (src, sport, dst, dport, proto, is_new_flow_packet) or None."""
    if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
        return None
    ip = pkt[14:]
    ihl = (ip[0] & 0x0F) * 4
    proto_num = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    l4 = ip[ihl:]
    if len(l4) < 4:
        return None
    sport, dport = struct.unpack("!HH", l4[:4])
    if proto_num == 6 and len(l4) >= 14:
        flags = l4[13]
        return src, sport, dst, dport, "tcp", bool(flags & 0x02) and not flags & 0x10  # SYN, not SYN-ACK
    if proto_num == 17:
        return src, sport, dst, dport, "udp", True
    return None


def watch_network(bridge, subnet, pcap_path):
    """Egress from the sandbox subnet. tcpdump (in a helper container on the host network) streams raw
    pcap to us; we save it to capture.pcap and turn the first packet of each new flow (TCP SYN or first
    UDP packet) into a net_connect event."""
    bpf = f"src net {subnet} and not dst net {subnet}"
    p = subprocess.Popen(["docker", "run", "--rm", "--name", NETMON_NAME, "--net=host",
                          "--cap-drop=ALL", "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
                          NETMON_IMAGE, "tcpdump", "-i", bridge, "-U", "-n", "-w", "-", bpf],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    seen = set()
    with open(pcap_path, "wb") as out:
        header = read_exact(p.stdout, 24)
        if not header:
            return
        out.write(header)
        endian = "<" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        while not stop.is_set():
            rec = read_exact(p.stdout, 16)
            if not rec:
                break
            sec, usec, incl, _orig = struct.unpack(endian + "IIII", rec)
            pkt = read_exact(p.stdout, incl)
            if pkt is None:
                break
            out.write(rec + pkt)
            out.flush()
            parsed = parse_packet(pkt)
            if not parsed:
                continue
            src, sport, dst, dport, proto, new_flow = parsed
            key = (src, sport, dst, dport, proto)
            if not new_flow or key in seen:  # skip mid-flow packets and SYN retransmits
                continue
            seen.add(key)
            put(sec + usec / 1e6, "network", "net_connect",
                {"src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "proto": proto})
    p.terminate()


def watch_container(container, until_exit):
    """docker events for the agent. Starts the log follower on 'start'; stops the run on 'die'."""
    p = subprocess.Popen(["docker", "events", "--format", "{{json .}}",
                          "--filter", f"container={container}",
                          "--filter", "type=container", "--filter", "type=network"],
                         stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        action = d.get("Action") or d.get("status") or ""
        t = d.get("timeNano", time.time() * 1e9) / 1e9
        if d.get("Type") == "network":
            if action == "disconnect":
                put(t, "container", "disconnect", {"network": d.get("Actor", {}).get("Attributes", {}).get("name")})
            continue
        if action == "start":
            put(t, "container", "start", {"container": container})
            threading.Thread(target=follow_agent_logs, args=(container,), daemon=True).start()
        elif action in ("pause", "unpause", "die", "kill", "stop"):
            put(t, "container", action if action != "die" else "exit",
                {"container": container, "exit_code": d.get("Actor", {}).get("Attributes", {}).get("exitCode")})
            # A run ends when the agent exits, or when it is frozen by containment (a paused agent never exits).
            if action in ("die", "pause") and until_exit:
                time.sleep(FLUSH_DELAY + (2.5 if action == "pause" else 0.5))  # let disconnect events arrive
                stop.set()
                break
        if stop.is_set():
            break
    p.terminate()


def watch_network_events(network, container):
    """docker's container filter does not match network events, so watch the sandbox network separately."""
    p = subprocess.Popen(["docker", "events", "--format", "{{json .}}", "--filter", "type=network",
                          "--filter", f"network={network}"], stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        attrs = d.get("Actor", {}).get("Attributes", {})
        if d.get("Action") == "disconnect":
            cid = attrs.get("container", "")
            name = sh("docker", "inspect", "-f", "{{.Name}}", cid).lstrip("/") if cid else ""
            if name in (container, ""):
                put(d.get("timeNano", time.time() * 1e9) / 1e9, "container", "disconnect",
                    {"container": container, "network": attrs.get("name", network)})
        if stop.is_set():
            break
    p.terminate()


# ---------------- writer ----------------

def writer(out_path, run_id, evaluate):
    pending, steps, n = [], [], 0  # steps: (t, step_id) in time order
    with open(out_path, "w") as f:
        while not (stop.is_set() and q.empty() and not pending):
            try:
                pending.append(q.get(timeout=0.2))
            except queue.Empty:
                pass
            now = time.time()
            pending.sort(key=lambda e: e["_t"])
            ready = [e for e in pending if stop.is_set() or e["_t"] < now - FLUSH_DELAY]
            pending = [e for e in pending if e not in ready]
            for e in ready:
                if e["source"] == "agent_step" and e["type"] == "step":
                    steps.append((e["_t"], e["step_id"]))
                if e["step_id"] is None:  # link to the step that was active at this moment
                    prior = [sid for st, sid in steps if st <= e["_t"] + 0.05]
                    e["step_id"] = prior[-1] if prior else None
                n += 1
                event = {"id": f"evt-{n:04d}", "ts": iso(e["_t"]), "run_id": run_id, "source": e["source"],
                         "type": e["type"], "detail": e["detail"], "step_id": e["step_id"], "verdict": "allow"}
                event["verdict"] = evaluate(event) if evaluate else "allow"
                f.write(json.dumps(event) + "\n")
                f.flush()
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--container", default="cagewatch-agent")
    ap.add_argument("--network", default="cagewatch-net")
    ap.add_argument("--out", default=os.path.join(ROOT, "shared", "runtime"))
    ap.add_argument("--until-exit", action="store_true", help="stop when the agent container exits")
    ap.add_argument("--rules", help="module:function returning a verdict for each event")
    ap.add_argument("--respond", action="store_true",
                    help="auto-contain (pause, disconnect, revoke token, preserve evidence) when risk crosses the policy threshold")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    sys.path.insert(0, ROOT)
    evaluate, respond = None, None
    if a.rules:
        mod, fn = a.rules.split(":")
        rules_mod = importlib.import_module(mod)
        evaluate = getattr(rules_mod, fn)
        if a.respond:
            from engine.respond import respond
            rules_mod.set_responder(respond.on_incident)
            respond.issue_token(a.run_id)

    if not sh("docker", "network", "ls", "-q", "-f", f"name=^{a.network}$"):
        sh("docker", "network", "create", a.network)
    net_id = sh("docker", "network", "inspect", a.network, "-f", "{{.Id}}")
    subnet = sh("docker", "network", "inspect", a.network, "-f", "{{range .IPAM.Config}}{{.Subnet}}{{end}}")
    bridge = "br-" + net_id[:12]
    if not sh("docker", "image", "ls", "-q", NETMON_IMAGE):
        subprocess.run(["docker", "build", "-q", "-t", NETMON_IMAGE, "-f",
                        os.path.join(ROOT, "engine", "collector", "Dockerfile.netmon"),
                        os.path.join(ROOT, "engine", "collector")], check=True)

    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    subprocess.run(["docker", "rm", "-f", NETMON_NAME], capture_output=True)
    for target, args in ((watch_files, ()),
                         (watch_network, (bridge, subnet, os.path.join(a.out, "capture.pcap"))),
                         (watch_container, (a.container, a.until_exit)),
                         (watch_network_events, (a.network, a.container))):
        threading.Thread(target=target, args=args, daemon=True).start()
    # If the agent is already running, attach to its logs now.
    if sh("docker", "ps", "-q", "-f", f"name=^{a.container}$"):
        threading.Thread(target=follow_agent_logs, args=(a.container,), daemon=True).start()

    # Wait until the network monitor is actually running, then tell the caller it is safe to start the agent.
    for _ in range(50):
        if sh("docker", "ps", "-q", "-f", f"name=^{NETMON_NAME}$"):
            break
        time.sleep(0.2)
    time.sleep(1.0)  # inotify watches + tcpdump attach
    out_path = os.path.join(a.out, "events.jsonl")
    print(f"collector: run={a.run_id} bridge={bridge} subnet={subnet} -> {out_path}", flush=True)
    print("collector: ready", flush=True)
    n = writer(out_path, a.run_id, evaluate)
    if respond:
        respond.wait_all()  # do not exit while containment / evidence copy is still running
    subprocess.run(["docker", "rm", "-f", NETMON_NAME], capture_output=True)
    print(f"collector: wrote {n} events", flush=True)


if __name__ == "__main__":
    main()
