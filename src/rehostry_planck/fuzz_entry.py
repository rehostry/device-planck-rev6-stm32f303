# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fuzz-REACH entry point for this row's USB control endpoint (EP0)
(lane s1011-laneAQ, modelled on lane s1011-laneAC's).

WHAT A FUZZER CALLS
-------------------
::

    from rehostry_planck.fuzz_entry import reach_one
    r = reach_one(entry="E_IF1_GET_DESC_REPORT")                # a declared entry, sent FIRST
    r = reach_one(setups=[(0x80, 6, 0x0304, 0, 64)])            # ARBITRARY SETUP packets, in order
    r = reach_one(setups=[(0x21, 9, 0x0200, 0, 1, b"\\x02")])    # with an OUT data stage
    r["handler_hit"], r["credited"], r["live_after"], r["entry_resp"], r["own_fired"], r["spin"]

ONE FRESH BOOT per call, in its own process group, on a copy of ``configs/``,
with a forced exit. The bridge must greet with OUR child's pid and a per-boot
nonce, and the hook log's ``hello`` must carry the same pid.

ENTRY FIRST. The row's host model runs its own enumeration as soon as the
firmware opens EP0, and that script sends this row's GET_DESCRIPTOR entries,
SET_ADDRESS and SET_CONFIGURATION. With ``no_enum=True`` (the default) the probe
empties that script in the emulator process only, so the input is the first
SETUP on the wire; only the bus reset precedes it. ``no_enum=False`` is the
mute control.

GUEST TIME: guest milliseconds of the row's own system-timer model (TIM3
counts advanced by the row's pump, / its programmed frequency), read in-process at every
dispatch pass (see ``bp_handlers/fuzz_reach_probe.py``). Wall-clock is only a
ceiling.

REACH: the FIRST ``own`` hook record after the input is the entry's own handler
(``configs/fuzz_reach_targets.json``, derived from this image by
``tools/fuzz_reach_targets.py``) and carries its identity, all read from guest
state at hit time: the 8 SETUP bytes in the guest's own ``usbp->setup`` equal the
entry's; IPSR is the USB interrupt's exception number; for a
``get_usb_descriptor`` arm ``r1`` is the entry's ``wIndex``; for an OUT-stage
callback the OUT bytes read through the guest's ``usbp->ep0next`` are the
entry's.

LIVENESS: ``SET_ADDRESS(A)`` with A minted per boot, then
``GET_DESCRIPTOR(DEVICE)``, which the host delivers only if the guest's own
device-address register reads A (``FUZZ_REACH_ADDR_GATE``, opt-in, row-local).
Live iff the device answers 18 bytes, the address the guest wrote is A, and the
DEVICE handler fired with its identity. Inverted control: address == A ^ 1.

Ports: slot k owns ``PORT_LOW + 3k .. +2`` (bridge, zmq rx, zmq tx), asserted
inside the lane block before anything is spawned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

from . import paths, spawn

# ---------------------------------------------------------------------------
# ROW ADAPTER
# ---------------------------------------------------------------------------
PKG = "rehostry_planck"
ENV_PORT, ENV_NONCE = "HAL_PLANCK_BRIDGE_PORT", "HAL_PLANCK_NONCE"
ENV_DROP = ("HAL_PLANCK_NO_USB_IRQ", "HAL_PLANCK_STALL_AFTER_BIND", "HAL_PLANCK_SOF_TICKS",
            "HAL_PLANCK_TICKS_PER_BEAT", "HAL_PLANCK_MMIO_PER_BEAT")
BOUND = "UsbHost: HOST-BRIDGE-BOUND tcp/%d pid=%d"
READY = "UsbHost: the firmware opened EP0"
DEFAULT_PORT_LOW = 39970
LIVE_DEV_ENTRY = "X_DEVICE"


def hello_ok(line: str, pid: int, nonce: str) -> bool:
    return line == "HELLO pid=%d device=planck-rev6-stm32f303 nonce=%s" % (pid, nonce)


def req_line(tag: str, s) -> bytes:
    """The probe's non-blocking bridge verb (bp_handlers/fuzz_reach_probe.py)."""
    bm, rq, val, idx, ln = s[:5]
    out = s[5] if len(s) > 5 and s[5] is not None else b""
    return ("REQ %s %02x %02x %04x %04x %04x%s\n"
            % (tag, bm, rq, val, idx, ln, (" " + out.hex()) if out else "")).encode()


def resp_for(lines: List[str], tag: str) -> Optional[dict]:
    """``RESP <tag> ok <hex>`` / ``RESP <tag> stall``."""
    for ln in lines:
        p = ln.split()
        if len(p) >= 3 and p[0] == "RESP" and p[1] == tag:
            return {"status": p[2], "data": bytes.fromhex(p[3]) if len(p) > 3 else b""}
    return None
# ---------------------------------------------------------------------------
# END ROW ADAPTER
# ---------------------------------------------------------------------------


LANE_LOW, LANE_HIGH = 39950, 40049
PORT_LOW = int(os.environ.get("FUZZ_REACH_PORT_LOW", str(DEFAULT_PORT_LOW)))
PORT_HIGH = int(os.environ.get("FUZZ_REACH_PORT_HIGH", str(DEFAULT_PORT_LOW + 19)))
BOOT_WALL = float(os.environ.get("FUZZ_REACH_BOOT_WALL", "300"))
PRE_TICKS = int(os.environ.get("FUZZ_REACH_PRE_TICKS", "200"))
SETTLE_TICKS = int(os.environ.get("FUZZ_REACH_SETTLE_TICKS", "2000"))
AFTER_TICKS = int(os.environ.get("FUZZ_REACH_AFTER_TICKS", "200"))
LIVE_TICKS = int(os.environ.get("FUZZ_REACH_LIVE_TICKS", "3000"))
PHASE_WALL = float(os.environ.get("FUZZ_REACH_PHASE_WALL", "150"))
FROZEN_S = float(os.environ.get("FUZZ_REACH_FROZEN", "30"))
FLOOD_BYTES = int(os.environ.get("FUZZ_REACH_EMU_LOG_CAP", str(32 << 20)))
FAULT_RE = r"UC_ERR|Traceback|unmapped (?:read|write|fetch)|HardFault|Invalid memory|could NOT bind|BIND-FAILED"
PROBE_CLS = PKG + ".bp_handlers.fuzz_reach_probe.FuzzReachProbe"
HIT_KINDS = ("entry", "own", "route", "shared", "capped")
RESERVED_ADDR = (0x2A, 0x2B)   # X_SET_ADDRESS sends 0x2a; A never equals it or its ^1


def targets() -> dict:
    return json.loads((paths.configs_dir() / "fuzz_reach_targets.json").read_text())


def sha256(p) -> Optional[str]:
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return None


def _ports(slot: int) -> List[int]:
    ps = [PORT_LOW + 3 * slot + k for k in range(3)]
    for p in ps:
        if not (LANE_LOW <= p <= LANE_HIGH and PORT_LOW <= p <= PORT_HIGH):
            raise ValueError("port %d outside the lane block %d..%d / row block %d..%d"
                             % (p, LANE_LOW, LANE_HIGH, PORT_LOW, PORT_HIGH))
    return ps


def overlay_yaml(tg: dict) -> str:
    so = int(tg["located"]["setup_off"], 16)
    lines = ["intercepts:"]
    for h in tg["hooks"]:
        a = int(h["addr"], 16)
        lines.append("  - {class: %s, function: fuzzreach_%s_%x, addr: 0x%x, "
                     "registration_args: {kind: %s, label: \"%s\", so: %d, akind: \"%s\"}}"
                     % (PROBE_CLS, h["kind"], a, a, h["kind"], h["label"], so, h.get("akind", "")))
    return "\n".join(lines) + "\n"


def _read_jsonl(path: Path) -> List[dict]:
    out = []
    try:
        for ln in path.read_text(errors="replace").splitlines():
            try:
                out.append(json.loads(ln))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def _ring(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _tuple(s: dict):
    out = bytes.fromhex(s["out_hex"]) if s.get("out_hex") else None
    return (s["bm"], s["req"], s["value"], s["index"], s["length"], out)


def build_input(tg: dict, entry: Optional[str], setups):
    if setups is not None:
        return [tuple(s) for s in setups], {"id": "raw"}
    for e in tg["entries"]:
        if e["id"] == entry:
            return [_tuple(e["setup"])], e
    for c in tg["controls"]:
        if c["id"] == entry:
            return ([] if c["setup"] is None else [_tuple(c["setup"])]), c
    raise KeyError("unknown entry %r" % entry)


class _Bridge:
    def __init__(self, sock: socket.socket) -> None:
        self.s = sock
        self.s.settimeout(0.1)
        self.buf = b""
        self.lines: List[str] = []

    def pump(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not d:
                return
            self.buf += d
            while b"\n" in self.buf:
                ln, self.buf = self.buf.split(b"\n", 1)
                if len(self.lines) < 4000:
                    self.lines.append(ln.decode("ascii", "replace").strip())

    def send(self, b: bytes) -> None:
        self.s.sendall(b)


def _summ(r: Optional[dict]) -> Optional[dict]:
    """Length, status and sha256 only -- no reply bytes are stored."""
    if r is None:
        return None
    return {"status": r["status"], "len": len(r["data"]),
            "sha256": hashlib.sha256(r["data"]).hexdigest() if r["data"] else None}


def reach_one(entry: Optional[str] = None, setups=None, slot: int = 0,
              workdir: Optional[str] = None, python: Optional[str] = None,
              liveness: bool = True, no_enum: bool = True, addr_gate: bool = True,
              gate_wrong: bool = False) -> dict:
    """ONE fresh boot: input first, then liveness, then teardown."""
    tg = targets()
    bp, zrx, ztx = _ports(slot)
    wd = Path(workdir or ("fuzzreach-%d" % os.getpid())).resolve()
    if wd.exists():
        shutil.rmtree(wd)
    cfg = wd / "cfg"
    shutil.copytree(paths.configs_dir(), cfg,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tmp"))
    (cfg / "fuzz_reach_overlay.yaml").write_text(overlay_yaml(tg))
    hook_log, emu_log, ring = wd / "hooks.jsonl", wd / "emulator.txt", wd / "pcring.json"
    sets, meta = build_input(tg, entry, setups)
    nonce = secrets.token_hex(8)
    addr = 0
    while addr in (0,) + RESERVED_ADDR:
        addr = 1 + secrets.randbelow(127)
    res: Dict = {"row": tg["row"], "entry": meta.get("id"), "class": meta.get("class"),
                 "input": [req_line("e%d" % k, s).decode().strip() for k, s in enumerate(sets)],
                 "entry_meta": meta, "ports": [bp, zrx, ztx], "slot": slot,
                 "no_enum": no_enum, "addr_gate": addr_gate, "gate_wrong": gate_wrong,
                 "live_addr": addr if liveness else None,
                 "load_at_start": round(os.getloadavg()[0], 2)}
    pristine = paths.firmware_bin()
    res["bin_sha256_pristine_before"] = sha256(pristine)
    res["bin_sha256_copy"] = sha256(cfg / tg["bin"])
    argv = spawn.spawn_argv(python=python, rx_port=zrx, tx_port=ztx)
    argv += ["-c", "fuzz_reach_overlay.yaml"]
    extra = {ENV_PORT: bp, ENV_NONCE: nonce,
             "FUZZ_REACH_LOG": str(hook_log), "FUZZ_REACH_PCRING": str(ring)}
    if no_enum:
        extra["FUZZ_REACH_NO_ENUM"] = "1"
    if addr_gate and liveness:
        # gate_wrong is the control that the gate BITES: it wants A ^ 1, which the
        # guest was never told, so the liveness GET_DESCRIPTOR must not be delivered.
        extra["FUZZ_REACH_ADDR_GATE"] = str(addr ^ 1 if gate_wrong else addr)
    env = spawn.spawn_env(extra={k: str(v) for k, v in extra.items()})
    for k in ENV_DROP:
        env.pop(k, None)
    if not no_enum:
        env.pop("FUZZ_REACH_NO_ENUM", None)
    proc = subprocess.Popen(argv, cwd=str(cfg), env=env, stdout=open(emu_log, "w"),
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    res["pid"] = proc.pid
    t0 = time.time()
    br: Optional[_Bridge] = None
    sock: Optional[socket.socket] = None

    def ticks() -> int:
        return _ring(ring).get("ticks") or 0

    def wait_ticks(n: int, stop=None) -> Dict:
        start, last, moved, t1 = ticks(), ticks(), time.time(), time.time()
        while True:
            br.pump(0.3)
            tk = ticks()
            if tk != last:
                last, moved = tk, time.time()
            if stop is not None and stop():
                return {"ended": "condition", "ticks": tk - start, "wall": round(time.time() - t1, 1)}
            if tk - start >= n:
                return {"ended": "ticks", "ticks": tk - start, "wall": round(time.time() - t1, 1)}
            if proc.poll() is not None:
                return {"ended": "exited rc=%s" % proc.returncode, "ticks": tk - start}
            if _size(emu_log) > FLOOD_BYTES:
                return {"ended": "log_flood", "ticks": tk - start}
            if time.time() - moved >= FROZEN_S:
                return {"ended": "clock_frozen", "ticks": tk - start,
                        "wall": round(time.time() - t1, 1)}
            if time.time() - t1 >= PHASE_WALL:
                return {"ended": "phase_wall", "ticks": tk - start}

    try:
        ok = False
        while time.time() - t0 < BOOT_WALL:
            if proc.poll() is not None or _size(emu_log) > FLOOD_BYTES:
                break
            txt = emu_log.read_text(errors="replace")
            if re.search(FAULT_RE, txt):
                break
            if (BOUND % (bp, proc.pid)) in txt and READY in txt:
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            res["boot_error"] = "not ready (rc=%s, %.0fs)" % (proc.poll(), time.time() - t0)
            return res
        sock = socket.create_connection(("127.0.0.1", bp), timeout=5)
        sock.settimeout(5)
        hello = b""
        while b"\n" not in hello and len(hello) < 300:
            c = sock.recv(1)
            if not c:
                break
            hello += c
        res["hello"] = hello.decode("ascii", "replace").strip()
        if not hello_ok(res["hello"], proc.pid, nonce):
            res["boot_error"] = "bridge identity mismatch"
            return res
        br = _Bridge(sock)
        res["pre"] = wait_ticks(PRE_TICKS)
        res["boot_s"] = round(time.time() - t0, 1)
        res["boot_bridge_lines"] = len(br.lines)
        br.lines = []
        mark_in = len(_read_jsonl(hook_log))
        res["ticks_at_input"] = ticks()
        # ---- the input, FIRST -------------------------------------------------
        for k, s in enumerate(sets):
            br.send(req_line("e%d" % k, s))
        last = "e%d" % (len(sets) - 1)
        res["entry_settle"] = wait_ticks(
            SETTLE_TICKS, stop=(lambda: resp_for(br.lines, last) is not None) if sets else None)
        res["entry_after"] = wait_ticks(AFTER_TICKS)
        res["entry_resp"] = [_summ(resp_for(br.lines, "e%d" % k)) for k in range(len(sets))]
        br.lines = []
        mark_live = len(_read_jsonl(hook_log))
        res["hook_marks"] = [mark_in, mark_live]
        if liveness and res["entry_after"]["ended"] in ("ticks", "condition", "clock_frozen"):
            br.send(req_line("la", (0x00, 5, addr, 0, 0)))
            res["live_addr_settle"] = wait_ticks(LIVE_TICKS, stop=lambda: resp_for(br.lines, "la") is not None)
            res["live_addr_after"] = wait_ticks(AFTER_TICKS)
            br.send(req_line("ld", (0x80, 6, 0x0100, 0, 18)))
            res["live_dev_settle"] = wait_ticks(LIVE_TICKS, stop=lambda: resp_for(br.lines, "ld") is not None)
            la, ld = resp_for(br.lines, "la"), resp_for(br.lines, "ld")
            res["live_resp"] = {"la": _summ(la), "ld": _summ(ld)}
            res["live_dev_len"] = len(ld["data"]) if ld and ld["status"] == "ok" else None
        res["pcring"] = _ring(ring) or None
        return res
    except Exception as exc:  # noqa: BLE001
        res["harness_error"] = "%s: %s" % (type(exc).__name__, exc)
        return res
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                proc.wait(10)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        res["rc"] = proc.poll()
        res["wall_s"] = round(time.time() - t0, 1)
        res["bin_sha256_pristine_after"] = sha256(pristine)
        res["bin_sha256_copy_after"] = sha256(cfg / tg["bin"])
        txt = emu_log.read_text(errors="replace") if emu_log.exists() else ""
        res["emu_log_bytes"] = len(txt)
        res["faults"] = len(re.findall(FAULT_RE, txt))
        res["fault_lines"] = [ln[:220] for ln in txt.splitlines() if re.search(FAULT_RE, ln)][:6]
        res["host_setups_logged"] = [ln.split("UsbHost: ", 1)[1][:90] for ln in txt.splitlines()
                                     if "UsbHost: SETUP" in ln][:12]
        res["unicorn_backend_sha256"] = _backend_sha(python)
        _trim(emu_log, txt)
        try:
            (cfg / tg["bin"]).unlink()
        except OSError:
            pass
        res["load_at_end"] = round(os.getloadavg()[0], 2)
        _score(tg, res, _read_jsonl(hook_log))


def _backend_sha(python: Optional[str]) -> Optional[str]:
    try:
        import halucinator.backends.unicorn_backend as u  # noqa: PLC0415
        return sha256(u.__file__)
    except Exception:  # noqa: BLE001
        return None


def _trim(p: Path, txt: str) -> None:
    if len(txt) < (1 << 20):
        return
    lines = txt.splitlines()
    keep = lines[:1500] + ["... [%d lines trimmed by fuzz_entry; %d total] ..."
                           % (len(lines) - 1700, len(lines))] + lines[-200:]
    p.write_text("\n".join(keep) + "\n")


# ---- identity --------------------------------------------------------------
def _identity(h: dict, e: dict, tg: dict) -> bool:
    if h.get("k") != "own" or h.get("pc") != int(e["handler"], 16):
        return False
    if h.get("ipsr") != tg["usb_exc"]:
        return False
    if h.get("setup") != e["setup"]["setup_hex"]:
        return False
    if e["handler_kind"] == "gud" and h.get("r1") != e["setup"]["index"]:
        return False
    if e["handler_kind"] == "cb":
        want = e["setup"].get("out_hex", "")[:16]
        if (h.get("out") or "") != want:
            return False
    return True


def _own(hits: List[dict]) -> List[dict]:
    return [h for h in hits if h.get("k") == "own"]


def _hit_for(hits: List[dict], e: dict, tg: dict) -> bool:
    own = _own(hits)
    return bool(own) and _identity(own[0], e, tg)


def _spin(res: dict) -> dict:
    from collections import Counter
    pr = res.get("pcring") or {}
    ring = pr.get("ring") or []
    tail = ring[-16:]
    pcs = [r[0] for r in tail if r and r[0] is not None]
    c = Counter(pcs)
    return {"samples": len(ring), "tail_distinct_pcs": len(c),
            "tail_top": [("0x%x" % a, n) for a, n in c.most_common(4)],
            "tail_ipsr": sorted({r[1] for r in tail if r and r[1] is not None}),
            "ticks": pr.get("ticks"), "passes": pr.get("passes"), "daddr": pr.get("daddr"),
            "async_samples": pr.get("async_samples"), "isr_counts": pr.get("isr_counts"),
            "dropped_total": pr.get("dropped_total")}


def _score(tg: dict, res: dict, hk: List[dict]) -> None:
    hello = [h for h in hk if h.get("k") == "hello"]
    res["hook_log_pid_ok"] = bool(hello) and hello[0].get("pid") == res.get("pid")
    res["hooks_registered"] = sum(1 for h in hk if h.get("k") == "registered")
    res["hooks_expected"] = len(tg["hooks"])
    res["no_enum_patched"] = next((h.get("patched") for h in hk if h.get("k") == "no_enum"), None)
    res["probe_errors"] = [h for h in hk if h.get("k") == "ring_error"][:4]
    marks = res.get("hook_marks") or [len(hk), len(hk)]
    boot = [h for h in hk[:marks[0]] if h.get("k") in HIT_KINDS]
    ent = [h for h in hk[marks[0]:marks[1]] if h.get("k") in HIT_KINDS]
    liv = [h for h in hk[marks[1]:] if h.get("k") in HIT_KINDS]
    res["boot_hit_count"] = len(boot)
    res["boot_hits"] = [(h.get("k"), h.get("label"), h.get("setup")) for h in boot[:12]]
    res["entry_hits"] = [{k: h.get(k) for k in ("k", "pc", "label", "ipsr", "depth", "setup", "r1",
                                                  "out", "daddr", "ticks")} for h in ent[:30]]
    res["live_hits"] = [{k: h.get(k) for k in ("k", "pc", "label", "ipsr", "setup", "daddr")}
                        for h in liv[:12]]
    res["isr"] = [h for h in hk if h.get("k") == "isr"][:8]
    res["guest_setups_in_order"] = [h.get("setup") for h in hk if h.get("k") == "entry"][:12]
    res["ctx"] = next(({k: v for k, v in h.items() if k not in ("k", "t")} for h in hk
                       if h.get("k") == "ctx"), None)
    res["gate"] = [h for h in hk if h.get("k") == "gate"][:4]
    res["spin"] = _spin(res)
    res["own_fired"] = sorted({(h["label"], h.get("setup"), h.get("ipsr"), h.get("depth"))
                               for h in _own(ent)}, key=str)
    res["route_fired"] = sorted({(h["label"], h.get("ipsr")) for h in ent
                                 if h.get("k") in ("route", "entry")}, key=str)
    res["shared_fired"] = sorted({(h["label"], h.get("setup")) for h in ent
                                  if h.get("k") == "shared"}, key=str)
    res["credited"] = [x["id"] for x in tg["entries"] if any(_identity(h, x, tg) for h in _own(ent))]
    if "live_dev_len" in res:
        dev = next(x for x in tg["entries"] if x["id"] == LIVE_DEV_ENTRY)
        live_own = [h for h in _own(liv) if h.get("pc") == int(dev["handler"], 16)
                    and h.get("ipsr") == tg["usb_exc"] and h.get("setup") == "8006000100001200"]
        gate = [g for g in res["gate"] if g.get("tag") == "ld"]
        daddr = gate[0].get("daddr") if gate else (res["spin"].get("daddr"))
        res["live_daddr"] = daddr
        res["live_handler_hit"] = bool(live_own)
        res["live_reply_ok"] = res["live_dev_len"] == 18
        res["live_daddr_ok"] = daddr == res["live_addr"]
        res["live_inverted_control_matched"] = daddr == ((res["live_addr"] or 0) ^ 1)
        res["live_after"] = bool(res["live_reply_ok"] and res["live_daddr_ok"]
                                 and res["live_handler_hit"])
    e = res.get("entry_meta") or {}
    if e.get("id") == "raw":
        res["handler_hit"] = bool(_own(ent))
        return
    if "handler" not in e:
        res["control_scores"] = {
            "declared_entries_credited": res["credited"],
            "first_hit_rule_credited": [x["id"] for x in tg["entries"] if _hit_for(ent, x, tg)],
            "any_own_hit": [h["label"] for h in _own(ent)][:8]}
        return
    res["handler_hit"] = _hit_for(ent, e, tg)
    res["weak_rule_label_hit"] = any(h.get("pc") == int(e["handler"], 16) for h in ent)
    nxt = e.get("next_entry")
    if nxt:
        ne = next(x for x in tg["entries"] if x["id"] == nxt)
        res["control_next_identity"] = {"next": nxt, "scored_true": _hit_for(ent, ne, tg),
                                        "any_true": any(_identity(h, ne, tg) for h in _own(ent))}
    res["credited_other"] = [c for c in res["credited"] if c != e["id"]]


# ---- sweep -----------------------------------------------------------------
def _safe(e: str) -> str:
    return e.encode().hex()


def _child(entry: str, slot: int, outdir: Path, python: Optional[str], extra: List[str]) -> dict:
    out = outdir / ("%s.json" % _safe(entry))
    wd = outdir / ("run-%s" % _safe(entry))
    argv = [python or sys.executable, "-m", PKG + ".fuzz_entry", "--entry", entry,
            "--slot", str(slot), "--out", str(out), "--workdir", str(wd)] + extra
    t0 = time.time()
    p = subprocess.Popen(argv, stdout=open(outdir / ("%s.child.txt" % _safe(entry)), "w"),
                         stderr=subprocess.STDOUT)
    with open(outdir / "pids.txt", "a") as fh:
        fh.write("%s %s slot=%d ports=%s child_pid=%d t=%.0f\n"
                 % (_safe(entry), entry, slot, _ports(slot), p.pid, t0))
    try:
        p.wait(BOOT_WALL + 5 * PHASE_WALL + 120)
    except subprocess.TimeoutExpired:
        p.kill()
    try:
        return json.loads(out.read_text())
    except (OSError, ValueError):
        return {"entry": entry, "harness_error": "child produced no result (rc=%s, %.0fs)"
                % (p.returncode, time.time() - t0)}


def sweep(outdir: Path, workers: int, python: Optional[str], only=None, controls=True,
          extra: Optional[List[str]] = None) -> dict:
    tg = targets()
    ids = [e["id"] for e in tg["entries"]]
    if controls:
        ids += [c["id"] for c in tg["controls"]]
    if only:
        ids = [i for i in ids if i in only]
    outdir.mkdir(parents=True, exist_ok=True)
    _ports(workers - 1)
    free = list(range(workers))
    lk = threading.Lock()

    def job(i):
        with lk:
            s = free.pop(0)
        try:
            return _child(i, s, outdir, python, extra or [])
        finally:
            with lk:
                free.append(s)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(job, ids))
    return {r.get("entry"): r for r in results}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--entry")
    ap.add_argument("--setup", nargs="*", help="SETUPs as bm:req:value:index:length[:outhex] (hex)")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--out")
    ap.add_argument("--workdir")
    ap.add_argument("--no-liveness", action="store_true")
    ap.add_argument("--with-enum", action="store_true",
                    help="mute control: let the host model run its own enumeration first")
    ap.add_argument("--no-addr-gate", action="store_true",
                    help="mute control: deliver the liveness GET_DESCRIPTOR whatever the guest's address")
    ap.add_argument("--gate-wrong", action="store_true",
                    help="control: the gate wants A^1, so liveness must FAIL")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--no-controls", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--outdir")
    a = ap.parse_args(argv)
    if a.sweep:
        ex = (["--with-enum"] if a.with_enum else []) + (["--no-addr-gate"] if a.no_addr_gate else []) \
            + (["--gate-wrong"] if a.gate_wrong else [])
        r = sweep(Path(a.outdir), a.workers, None, a.only, not a.no_controls, ex)
        Path(a.outdir, "sweep.json").write_text(json.dumps(r, indent=1, default=str))
        print(json.dumps({k: {"hit": v.get("handler_hit"), "live": v.get("live_after"),
                              "credited": v.get("credited"),
                              "err": v.get("boot_error") or v.get("harness_error")}
                          for k, v in r.items()}, indent=1))
        sys.stdout.flush()
        os._exit(0)
    setups = None
    if a.setup:
        setups = []
        for f in a.setup:
            p = f.split(":")
            s = tuple(int(x, 16) for x in p[:5])
            setups.append(s + ((bytes.fromhex(p[5]),) if len(p) > 5 else ()))
    r = reach_one(entry=a.entry, setups=setups, slot=a.slot, workdir=a.workdir,
                  liveness=not a.no_liveness, no_enum=not a.with_enum,
                  addr_gate=not a.no_addr_gate, gate_wrong=a.gate_wrong)
    js = json.dumps(r, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(js)
    else:
        print(js)
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
