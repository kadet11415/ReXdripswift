#!/usr/bin/env python3
"""Build the ReXdripswift workspace through Xcode's MCP bridge (xcrun mcpbridge).

Flow: initialize -> XcodeOpenWorkspace (approval) -> switch scheme xdrip ->
list destinations -> BuildProject -> GetBuildLog.
"""
import json
import os
import subprocess
import time

WS = os.path.expanduser("~/Downloads/ReXdripswift-aidex/xdrip.xcworkspace")

_f = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_build_log.txt"), "a")


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    _f.write(line + "\n")
    _f.flush()


def fail(msg):
    log(f"FAIL: {msg}")
    _f.close()
    print(f"FAIL: {msg}", flush=True)
    raise SystemExit(1)


proc = subprocess.Popen(
    ["xcrun", "mcpbridge"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, text=True, bufsize=1)


def send(method, params, rid):
    m = {"jsonrpc": "2.0", "method": method, "params": params}
    if rid is not None:
        m["id"] = rid
    proc.stdin.write(json.dumps(m) + "\n")
    proc.stdin.flush()


def recv(rid, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        line = proc.stdout.readline()
        if not line:
            fail(f"mcpbridge stdout closed waiting id={rid}")
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            log(f"RAW: {line[:300]}")
            continue
        if m.get("id") == rid:
            return m
    fail(f"no response for id={rid} within {timeout}s")


def call(name, params, rid, timeout=900):
    log(f">> {name} {json.dumps(params)}")
    send("tools/call", {"name": name, "arguments": params}, rid)
    m = recv(rid, timeout)
    if "error" in m:
        fail(f"{name} jsonrpc error: {json.dumps(m['error'])[:2000]}")
    res = m.get("result", {})
    text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
    log(f"<< {name} isError={res.get('isError', False)}")
    log(f"--- {name} result ---\n{text[:4000]}\n---")
    return res


# 1. initialize
send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "hermes", "version": "1.0"}}, 1)
m = recv(1, 30)
log(f"serverInfo={json.dumps(m.get('result', {}).get('serverInfo', {}))}")
send("notifications/initialized", None, None)

# 2. tools list — print schemas we use
send("tools/list", {}, 2)
ml = recv(2, 30)
tools = ml["result"]["tools"]
want = ["XcodeOpenWorkspace", "XcodeSwitchScheme", "BuildProject", "GetBuildLog"]
for t in tools:
    if t["name"] in want:
        log(f"TOOL {t['name']}: schema={json.dumps(t.get('inputSchema', {}))[:800]}")

# 3. open workspace (Xcode asks the user to approve the agent)
res = call("XcodeOpenWorkspace", {"path": WS}, 3, timeout=600)
wsi = WS
if isinstance(res, dict) and res.get("workspaceIdentifier"):
    wsi = res["workspaceIdentifier"]
    log(f"workspaceIdentifier -> {wsi}")
else:
    # fall back: parse from text payload
    t = json.dumps(res)
    import re as _re
    m = _re.search(r'"workspaceIdentifier"\s*:\s*"([^"]+)"', t)
    if m:
        wsi = m.group(1)
        log(f"workspaceIdentifier (parsed) -> {wsi}")

# 4. pick scheme
if any(t["name"] == "XcodeSwitchScheme" for t in tools):
    call("XcodeSwitchScheme", {"schemeName": "xdrip", "workspaceIdentifier": wsi}, 4, timeout=120)

# 5. destinations (context only)
if any(t["name"] == "XcodeListRunDestinations" for t in tools):
    call("XcodeListRunDestinations", {"workspaceIdentifier": wsi}, 5, timeout=120)

# 6. BUILD
t0 = time.time()
call("BuildProject", {"workspaceIdentifier": wsi}, 6, timeout=10800)
log(f"BuildProject wall time: {(time.time() - t0)/60:.1f} min")

# 7. build log
if any(t["name"] == "GetBuildLog" for t in tools):
    call("GetBuildLog", {"workspaceIdentifier": wsi}, 7, timeout=300)

# cleanup
proc.stdin.close()
try:
    proc.wait(timeout=10)
except subprocess.TimeoutExpired:
    proc.kill()
err = proc.stderr.read() if proc.stderr else ""
err = err if err else ""
if err.strip():
    log(f"mcpbridge stderr tail: {err[-2000:]}")
log("DONE")
_f.close()
