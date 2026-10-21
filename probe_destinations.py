#!/usr/bin/env python3
"""Probe: open workspace, switch scheme xdrip, list run destinations."""
import json, os, subprocess, time

WS = os.path.expanduser("~/Downloads/ReXdripswift-aidex/xdrip.xcworkspace")
proc = subprocess.Popen(["xcrun", "mcpbridge"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
rid = [0]


def nid():
    rid[0] += 1
    return rid[0]


def send(params, name, timeout=180):
    i = nid()
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                                 "params": {"name": name, "arguments": params}}) + f"\n")
    proc.stdin.stdin if False else None
    proc.stdin.write("")  # no-op
    proc.stdin.flush()
    i2 = i
    t0 = time.time()
    while time.time() - t0 < timeout:
        line = proc.stdout.readline()
        if not line:
            proc.kill()
            raise SystemExit("mcpbridge closed")
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            print("RAW:", line[:200])
            continue
        if m.get("id") == i2:
            return m


def call(name, params, timeout=180):
    m = send(params, name, timeout)
    res = m.get("result", {})
    txt = "".join(c.get("text", "") for c in res.get("content", []))
    print(f"=== {name} isError={res.get('isError', False)}")
    print(txt[:3000])
    return txt


send_init = proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "initialize", "id": 9000,
    "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "probe", "version": "1"}}}) + "\n")
proc.stdin.flush()
t0 = time.time()
while time.time() - t0 < 30:
    line = proc.stdout.readline().strip()
    if not line:
        continue
    try:
        m = json.loads(line)
    except json.JSONDecodeError:
        print("RAW:", line[:200])
        continue
    if m.get("id") == 9000:
        break
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": None}) + "\n")
proc.stdin.flush()

call("XcodeOpenWorkspace", {"path": WS})
call("XcodeSwitchScheme", {"schemeName": "xdrip"})
call("XcodeListRunDestinations", {})

proc.stdin.close()
try:
    proc.wait(timeout=10)
except subprocess.TimeoutExpired:
    proc.kill()
