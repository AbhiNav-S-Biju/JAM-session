"""PLACEHOLDER agent so the sandbox container runs (A2). Replaced by the real scripted agent in A3."""
import argparse
import json
import time

p = argparse.ArgumentParser()
p.add_argument("--mode", choices=["benign", "attack", "benign_unusual"], default="benign")
args = p.parse_args()

print(json.dumps({"step_id": "step-1", "action": "start", "mode": args.mode, "reason": "placeholder agent", "tainted": False}), flush=True)
time.sleep(600)  # stay alive so the container can be inspected/paused
