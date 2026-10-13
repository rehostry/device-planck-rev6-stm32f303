# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Observe-only fuzz-REACH hooks for this row's USB control endpoint (EP0)
(lane s1011-laneAQ; modelled on lane s1011-laneAC's). Row-local and opt-in: loaded only when
``fuzz_entry`` writes it into a per-boot config copy.

Every hook returns ``(False, None)``: the firmware's own instruction still runs.
Every field is read from GUEST state at hit time. Kinds (addresses from
``configs/fuzz_reach_targets.json``, derived from this image):

``entry``   QMK's ``requests_hook_cb`` first instruction: ``r0`` is the guest's
            ``USBDriver *`` (remembered for the other hooks) and its setup bytes.
``own``     an arm that is some entry's own handler.
``route``   an arm on the way (QMK hook declining, ChibiOS' GET_DESCRIPTOR case,
            ``get_usb_descriptor``'s entry, SET_REPORT's setup stage). Never credited.
``shared``  a not-found / stall arm. Never credited.
``isr``     inside the OS tick handler: IPSR and exception depth (the control
            that the IPSR rule can move).

Each ``entry``/``own``/``route``/``shared`` record carries the 8 SETUP bytes read
from the guest's own ``usbp->setup`` (at the offset the hook itself uses), r0-r3,
IPSR, the backend's exception depth, the guest-written device address, and for
an OUT-stage callback the first OUT bytes read through the guest's own
``usbp->ep0next``.

OPT-IN SWITCHES (row-local; this module patches the row's host model IN THIS
PROCESS ONLY; unset, nothing is changed -- the mute control):
* ``FUZZ_REACH_NO_ENUM=1`` -- empty the host model's own enumeration script, so
  the input is the first SETUP on the wire (only the bus reset precedes it).
* ``FUZZ_REACH_ADDR_GATE=<A>`` -- the host delivers the request tagged ``ld``
  only if the GUEST's own device-address register reads ``A`` (a controller
  accepts a SETUP only at its own address). The row's controller model does
  not filter by address, so without this the liveness probe's second half would
  not depend on the firmware having acted on ``A``.

Once per process a chunk hook records (pc, ipsr, guest ticks, passes) into
``$FUZZ_REACH_PCRING``. A log cap passes at most ``FUZZ_REACH_LOG_CAP_PER_MSG``
copies of one rendered message (keyed on its full text).
"""
from __future__ import annotations

import collections
import json
import logging
import os
import threading
import time
from typing import Any

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler


# ---------------------------------------------------------------------------
# ROW ADAPTER
# ---------------------------------------------------------------------------
def _row_ticks():
    """Guest MILLISECONDS: the row's system-timer model's total counts over the
    frequency the firmware programmed. ChibiOS runs tickless here, so TIM3
    interrupt deliveries are sparse alarms, not a clock."""
    from ..peripheral_models import stm32f3_st  # noqa: PLC0415
    t = stm32f3_st.get_timer()
    return int(t.seconds() * 1000) if t is not None and t.frequency() else None


def _row_daddr():
    from ..peripheral_models import stm32f3_usb  # noqa: PLC0415
    u = stm32f3_usb.get_usb()
    return u.daddr() if u is not None else None


def _row_patch_no_enum() -> None:
    from ..peripheral_models import usb_host  # noqa: PLC0415
    usb_host.UsbHost._enumeration = lambda self: []  # noqa: SLF001


def _row_patch_addr_gate(want: int) -> None:
    from ..peripheral_models import usb_host  # noqa: PLC0415
    orig = usb_host.UsbHost._give  # noqa: SLF001

    def gated(self, usb, pma, ep, data, setup=False, _o=orig):
        cur = getattr(self, "_current", None)
        if setup and cur is not None and getattr(cur, "tag", None) == "ld":
            d = usb.daddr()
            ok = d == want
            _emit({"k": "gate", "tag": "ld", "daddr": d, "want": want, "delivered": ok})
            if not ok:
                return None
        return _o(self, usb, pma, ep, data, setup)
    usb_host.UsbHost._give = gated  # noqa: SLF001


def _row_patch_async_req() -> None:
    """Add a NON-BLOCKING verb to the row's bridge, in this process only:
    ``REQ <tag> <bm> <req> <wValue> <wIndex> <wLength> [outhex]`` (hex fields)
    queues one control transfer and returns nothing; when the FIRMWARE has
    finished it (no wall-clock timeout), every bridge client gets
    ``RESP <tag> ok <hex>`` or ``RESP <tag> stall``. The row's own ``CTRL``
    verb blocks with a 20 s wall timeout, which must never decide a verdict."""
    import struct  # noqa: PLC0415
    from ..peripheral_models import usb_host  # noqa: PLC0415
    orig = usb_host.UsbHost._command  # noqa: SLF001

    def command(self, line, _o=orig):
        p = line.split()
        if not p or p[0] != "REQ":
            return _o(self, line)
        tag = p[1]
        bm, rq, wv, wi, wl = (int(x, 16) for x in p[2:7])
        out = bytes.fromhex(p[7]) if len(p) > 7 else b""
        req = usb_host.ControlRequest(struct.pack("<BBHHH", bm, rq, wv, wi, wl), out)
        req.tag = tag
        self._queue.put(req)

        def waiter():
            req.done.wait()
            msg = ("RESP %s stall\n" % tag) if req.stalled else \
                ("RESP %s ok %s\n" % (tag, bytes(req.data).hex()))
            with self._lock:
                for c in list(self._clients):
                    try:
                        c.sendall(msg.encode())
                    except OSError:
                        pass
        threading.Thread(target=waiter, daemon=True).start()
        return None
    usb_host.UsbHost._command = command  # noqa: SLF001


#: Guest RAM the image's own dispatch reads to decide a request it cannot decide
#: from the SETUP alone (literals in this image, see tools/fuzz_reach_targets.py):
#: QMK's per-driver request hooks (requests_hook_cb's decline loop: 3 slots, 0x90
#: apart, function pointer at +0x84 from 0x20000f04), and the GET_REPORT/IDLE
#: interface->slot table (0x20000f00) with each slot's report-storage pointer
#: (+0x8c from the same 0x20000f04 slots). Recorded once, at the first request, as data.
def _row_ctx(qemu) -> dict:
    def w(a):
        m = _mem(qemu, a, 4)
        return ("0x%08x" % int.from_bytes(m, "little")) if m else None
    lut = _mem(qemu, 0x20000F00, 3)
    return {"decline_loop_hooks": [w(0x20000F04 + 0x84 + 0x90 * k) for k in range(3)],
            "iface_slot_lut": lut.hex() if lut else None,
            "report_storage": [w(0x20000F04 + 0x8C + 0x90 * k) for k in range(3)]}
# ---------------------------------------------------------------------------
# END ROW ADAPTER
# ---------------------------------------------------------------------------


_LOCK = threading.Lock()
_FH: Any = None
PER_KEY_CAP = int(os.environ.get("FUZZ_REACH_PER_KEY_CAP", "12"))
LOG_CAP = int(os.environ.get("FUZZ_REACH_LOG_CAP_PER_MSG", "20"))
ISR_SAMPLES = 4
_COUNT: dict = {}
_ISR: dict = {}
_RING: "collections.deque" = collections.deque(maxlen=64)
_DROPPED: "collections.Counter" = collections.Counter()
_ST: dict = {"passes": 0, "installed": False, "last_write": 0.0, "async": 0, "ticks": None,
             "usbp": None}


def _emit(rec: dict) -> None:
    global _FH
    with _LOCK:
        if _FH is None:
            path = os.environ.get("FUZZ_REACH_LOG")
            if not path:
                return
            _FH = open(path, "a", buffering=1)
            _FH.write(json.dumps({"k": "hello", "pid": os.getpid(), "t": time.time()}) + "\n")
        rec["t"] = round(time.time(), 3)
        rec.setdefault("ticks", _ST["ticks"])
        _FH.write(json.dumps(rec) + "\n")


def _uc(qemu):
    return qemu._uc  # noqa: SLF001


def _reg(qemu, name: str):
    try:
        from unicorn import arm_const as A  # type: ignore
        return int(_uc(qemu).reg_read(getattr(A, "UC_ARM_REG_" + name)))
    except Exception:  # noqa: BLE001
        return None


def _ipsr(qemu):
    x = _reg(qemu, "XPSR")
    return (x & 0x1FF) if isinstance(x, int) else None


def _mem(qemu, addr, n):
    try:
        return bytes(_uc(qemu).mem_read(addr, n))
    except Exception:  # noqa: BLE001
        return None


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


def _write_ring(force: bool = False) -> None:
    path = os.environ.get("FUZZ_REACH_PCRING")
    now = time.time()
    if not path or (not force and now - _ST["last_write"] < 0.5):
        return
    _ST["last_write"] = now
    try:
        tmp = path + ".w"
        with open(tmp, "w") as fh:
            json.dump({"pid": os.getpid(), "t": now, "passes": _ST["passes"],
                       "ticks": _ST["ticks"], "daddr": _safe(_row_daddr),
                       "isr_counts": dict(sorted(_ISR.items())),
                       "async_samples": _ST["async"], "ring": list(_RING),
                       "dropped": dict(list(_DROPPED.items())[:12]),
                       "dropped_total": sum(_DROPPED.values())}, fh)
        os.replace(tmp, path)
    except OSError:
        pass


class _CapFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.seen: "collections.Counter" = collections.Counter()

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        self.seen[msg] += 1
        if self.seen[msg] <= LOG_CAP:
            return True
        _DROPPED[msg[:120]] += 1
        return False


def _install_once(qemu) -> None:
    if _ST["installed"]:
        return
    _ST["installed"] = True
    if os.environ.get("FUZZ_REACH_NO_ENUM") == "1":
        _row_patch_no_enum()
        _emit({"k": "no_enum", "patched": True})
    else:
        _emit({"k": "no_enum", "patched": False})
    _row_patch_async_req()
    _emit({"k": "async_req", "patched": True})
    gate = os.environ.get("FUZZ_REACH_ADDR_GATE")
    if gate:
        _row_patch_addr_gate(int(gate))
        _emit({"k": "addr_gate", "want": int(gate)})
    flt = _CapFilter()
    hs = set()
    for name in ["", "HAL_LOG"] + list(logging.root.manager.loggerDict):
        for h in getattr(logging.getLogger(name), "handlers", []):
            hs.add(h)
    for h in hs:
        h.addFilter(flt)

    def _sample() -> None:
        _ST["passes"] += 1
        _ST["last_chunk_t"] = time.time()
        _ST["ticks"] = _safe(_row_ticks)
        _RING.append((_reg(qemu, "PC"), _ipsr(qemu), _ST["ticks"], _ST["passes"]))
        try:
            _write_ring()
        except Exception as exc:  # noqa: BLE001
            _emit({"k": "ring_error", "err": repr(exc)})

    def _watch() -> None:
        while True:
            time.sleep(1.0)
            if time.time() - _ST.get("last_chunk_t", time.time()) >= 2.0:
                _ST["async"] += 1
                _RING.append((_reg(qemu, "PC"), _ipsr(qemu), _safe(_row_ticks), _ST["passes"],
                              "async"))
                _write_ring(force=True)
    _ST["last_chunk_t"] = time.time()
    threading.Thread(target=_watch, daemon=True).start()
    try:
        qemu.add_chunk_hook(_sample)
        _emit({"k": "chunk_hook", "ok": True, "log_handlers_capped": len(hs),
               "irq_chunk": os.environ.get("HAL_IRQ_CHUNK")})
    except Exception as exc:  # noqa: BLE001
        _emit({"k": "chunk_hook", "ok": False, "err": repr(exc)})


class FuzzReachProbe(BPHandler):
    """Observe-only; see the module docstring."""

    def __init__(self, **kwargs: Any) -> None:
        self._kind: dict = {}
        self._label: dict = {}
        self._akind: dict = {}
        self._so: dict = {}

    def register_handler(self, qemu, addr: int, func_name: str, kind: str = "own",
                         label: str = "", so: int = 0x74, akind: str = ""):
        _install_once(qemu)
        self._kind[addr] = kind
        self._label[addr] = label or func_name
        self._so[addr] = so
        self._akind[addr] = akind
        _emit({"k": "registered", "kind": kind, "pc": addr, "label": self._label[addr]})
        return FuzzReachProbe.hit

    @bp_handler([])
    def hit(self, qemu, addr: int):
        kind = self._kind.get(addr, "?")
        ipsr = _ipsr(qemu)
        depth = getattr(qemu, "_exc_depth", None)
        if kind == "isr":
            ck = "0x%x:ipsr%s:depth%s" % (addr, ipsr, depth)
            n = _ISR[ck] = _ISR.get(ck, 0) + 1
            if n <= ISR_SAMPLES:
                _emit({"k": "isr", "pc": addr, "label": self._label.get(addr),
                       "ipsr": ipsr, "depth": depth, "n": n})
            return False, None
        so = self._so.get(addr, 0x74)
        if kind == "entry":
            _ST["usbp"] = _reg(qemu, "R0")
            if not _ST.get("ctx_done"):
                _ST["ctx_done"] = True
                _emit({"k": "ctx", **(_safe(lambda: _row_ctx(qemu)) or {})})
        usbp = _ST["usbp"]
        setup = _mem(qemu, usbp + so, 8) if isinstance(usbp, int) else None
        rec = {"k": kind, "pc": addr, "label": self._label.get(addr), "ipsr": ipsr,
               "depth": depth, "r0": _reg(qemu, "R0"), "r1": _reg(qemu, "R1"),
               "r2": _reg(qemu, "R2"), "r3": _reg(qemu, "R3"), "usbp": usbp,
               "setup": setup.hex() if setup else None, "daddr": _safe(_row_daddr)}
        if self._akind.get(addr) == "cb" and isinstance(usbp, int) and setup:
            nxt = _mem(qemu, usbp + so - 0x0C, 4)
            if nxt:
                p = int.from_bytes(nxt, "little")
                wl = min(int.from_bytes(setup[6:8], "little"), 8)
                d = _mem(qemu, p, wl)
                rec["out"] = d.hex() if d is not None else None
        key = (addr, rec["setup"], rec["r1"], ipsr)
        c = _COUNT[key] = _COUNT.get(key, 0) + 1
        if c > PER_KEY_CAP:
            if c == PER_KEY_CAP + 1:
                _emit({"k": "capped", "kind": kind, "pc": addr, "key": repr(key)[:200],
                       "after": PER_KEY_CAP})
            return False, None
        _emit(rec)
        return False, None
