#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fuzz-REACH hook targets for this row's USB control endpoint (EP0)
(lane s1011-laneAQ; the method is lane s1011-laneAC's, from device-atreus-stm32f103).
Writes ``configs/fuzz_reach_targets.json``; ``--check`` re-derives and compares.

WHAT IS AN INPUT. The census lists three entries for this row, ``iface0..2``: the
three HID interfaces the guest's own CONFIGURATION descriptor declares
(INVENTORY.md). Each is expanded into the control requests addressed to that
interface which the image's own dispatch parses (``E_IFk_*``): HID class and REPORT
descriptors, and QMK's HID class-request arms (GET/SET_REPORT, GET/SET_IDLE,
GET/SET_PROTOCOL). Requests addressed to the device or an endpoint are counted as
extras (``X_*``): ChibiOS' standard-request switch and GET_DESCRIPTOR's
device-recipient arms. IN reports the device emits are not-a-target. The
CONFIGURATION descriptor declares three interrupt IN endpoints and no OUT endpoint,
and no report descriptor uses the raw-HID/VIA usage page 0xFF60, so EP0 is the only
host input and there is no raw-HID/VIA command set in this image.

THE DISPATCH IS LOCATED BY CONTENT, not by name (the image is stripped):
* ``get_usb_descriptor``: the only function that opens ``lsrs r2,r0,#8 ; cmp r2,#3``;
* its single ``bl`` caller is ``get_descriptor_cb``; the literal pointer to that
  callback sits in ChibiOS' ``USBConfig`` ``{event_cb, get_descriptor_cb,
  requests_hook_cb, sof_cb}``, which gives QMK's ``requests_hook_cb``;
* ChibiOS' ``_usb_ep0setup`` is the function that loads ``usbp->config`` and then
  ``config->requests_hook_cb`` (``ldr r3,[r4,#4] ; ldr r3,[r3,#8]``) and falls into
  the standard switch when the hook declines;
* the setup packet's offset in ``USBDriver`` is the hook's own first
  ``ldrb.w r2,[r0,#off]``.

THE ARMS ARE FOUND BY EXECUTING THE FIRMWARE'S OWN DECODE. For each request,
``Arm.run`` executes the dispatcher in a bare unicorn instance holding only this
image and a scratch ``USBDriver`` whose setup bytes are the request. The ARM is
the first instruction executed after the LAST conditional decision (b<cc>,
cbz/cbnz, tbb/tbh, a computed ``ldr pc``) before the first EFFECT (a call, a
return, a store outside the stack, or a load from real SRAM). Chains:
QMK hook -> (its GET_DESCRIPTOR call) -> ``get_usb_descriptor``; or QMK hook
declines -> ChibiOS switch -> (GET_DESCRIPTOR) -> ``get_usb_descriptor``; and for
SET_REPORT the hook is run to its return to recover the OUT-stage callback it
installs (``usbp->ep0endcb``) and buffer (``usbp->ep0next``), and that callback is
run on the entry's OUT bytes. An entry's OWN handler is the deepest arm of its
chain; the others are ROUTE arms, hooked and recorded, never credited.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import capstone  # noqa: E402
import unicorn  # noqa: E402
from unicorn import arm_const as UA  # noqa: E402

# ----------------------------------------------------------------------------
# ROW BLOCK
# ----------------------------------------------------------------------------
from rehostry_planck import paths  # noqa: E402

ROW = "device-planck-rev6-stm32f303"
BIN = "planck.bin"
BASE = 0x08000000
USB_IRQ = 75               # USB_LP after the SYSCFG remap (bp_handlers/irq_pump.USB_LP_IRQ)
TICK_SLOT = 16 + 29        # ChibiOS' system tick is TIM3, IRQ 29 (planck_facts.yaml system_timer)
TICK_NAME = "TIM3_IRQHandler"

#: The census (scratch-batch-s1011/census/interfaces-ALL.tsv) lists THREE entries
#: for this row: iface0, iface1, iface2 -- one per HID interface the guest's own
#: CONFIGURATION descriptor declares (INVENTORY.md). Each is expanded below into
#: the control requests addressed to that interface which the image's own
#: dispatch parses. id -> (bm, bRequest, wValue, wIndex, wLength, OUT bytes or None)
INPUTS = {
    # ---- iface0: boot keyboard, report descriptor 68 B, Output report (LEDs, no ID)
    "E_IF0_GET_DESC_HID": (0x81, 6, 0x2100, 0, 9, None),
    "E_IF0_GET_DESC_REPORT": (0x81, 6, 0x2200, 0, 68, None),
    "E_IF0_GET_REPORT": (0xA1, 1, 0x0100, 0, 8, None),
    "E_IF0_GET_IDLE": (0xA1, 2, 0x0000, 0, 1, None),
    "E_IF0_SET_IDLE": (0x21, 0x0A, 0x0000, 0, 0, None),
    "E_IF0_GET_PROTOCOL": (0xA1, 3, 0x0000, 0, 1, None),
    "E_IF0_SET_PROTOCOL": (0x21, 0x0B, 0x0001, 0, 0, None),
    "E_IF0_SET_REPORT_OUT": (0x21, 9, 0x0200, 0, 1, b"\x02"),
    # ---- iface1: shared EP, 182 B: Report IDs 2 mouse, 3 system, 4 consumer, 6 NKRO (+ Output)
    "E_IF1_GET_DESC_HID": (0x81, 6, 0x2100, 1, 9, None),
    "E_IF1_GET_DESC_REPORT": (0x81, 6, 0x2200, 1, 182, None),
    "E_IF1_GET_REPORT": (0xA1, 1, 0x0106, 1, 32, None),
    "E_IF1_GET_IDLE": (0xA1, 2, 0x0000, 1, 1, None),
    "E_IF1_SET_IDLE": (0x21, 0x0A, 0x0000, 1, 0, None),
    "E_IF1_SET_PROTOCOL": (0x21, 0x0B, 0x0001, 1, 0, None),
    "E_IF1_SET_REPORT_OUT_ID6": (0x21, 9, 0x0206, 1, 2, b"\x06\x02"),
    # ---- iface2: QMK console, usage page 0xFF31, 21 B, IN-only
    "E_IF2_GET_DESC_HID": (0x81, 6, 0x2100, 2, 9, None),
    "E_IF2_GET_DESC_REPORT": (0x81, 6, 0x2200, 2, 21, None),
    "E_IF2_GET_REPORT": (0xA1, 1, 0x0100, 2, 32, None),
    "E_IF2_GET_IDLE": (0xA1, 2, 0x0000, 2, 1, None),
    "E_IF2_SET_IDLE": (0x21, 0x0A, 0x0000, 2, 0, None),
    "E_IF2_SET_PROTOCOL": (0x21, 0x0B, 0x0001, 2, 0, None),
}
CENSUS_OF = {k: k[2:5].lower() for k in INPUTS}   # E_IF0_* -> iface0
OUTPUTS = {
    "O_IF0_IN": "emit-only: the boot keyboard INPUT report the device sends on EP 0x81",
    "O_IF1_IN_ID2": "emit-only: Report ID 2 INPUT (mouse) the device sends on EP 0x82",
    "O_IF1_IN_ID3": "emit-only: Report ID 3 INPUT (system) the device sends on EP 0x82",
    "O_IF1_IN_ID4": "emit-only: Report ID 4 INPUT (consumer) the device sends on EP 0x82",
    "O_IF1_IN_ID6": "emit-only: Report ID 6 INPUT (NKRO) the device sends on EP 0x82",
    "O_IF2_IN": "emit-only: the console INPUT report the device sends on EP 0x83",
}
CENSUS_ALIAS: dict = {}
NOTES = {
    "E_IF1_SET_PROTOCOL": "QMK's hook ACKs SET_PROTOCOL on a non-zero interface without acting on it "
                          "(its own arm, distinct from iface0's)",
    "E_IF2_SET_PROTOCOL": "same arm as E_IF1_SET_PROTOCOL: shared label, credited by identity only",
    "E_IF0_SET_REPORT_OUT": "the OUT-stage callback's 1-byte arm (wLength != 2: the byte is the LED state)",
    "E_IF1_SET_REPORT_OUT_ID6": "the OUT-stage callback's 2-byte arm taken for Report ID 1 or 6",
}
# ----------------------------------------------------------------------------
# END ROW BLOCK
# ----------------------------------------------------------------------------

#: Requests the image's own dispatch parses that are addressed to the DEVICE or an
#: ENDPOINT, not to one of the three census interfaces: ChibiOS' standard-request
#: switch (and GET_DESCRIPTOR's device-recipient arms).
EXTRAS = {
    "X_DEVICE": (0x80, 6, 0x0100, 0, 18, None),
    "X_CONFIG": (0x80, 6, 0x0200, 0, 84, None),
    "X_STRING_0": (0x80, 6, 0x0300, 0, 4, None),
    "X_STRING_1": (0x80, 6, 0x0301, 0x0409, 255, None),
    "X_STRING_2": (0x80, 6, 0x0302, 0x0409, 255, None),
    "X_STRING_3": (0x80, 6, 0x0303, 0x0409, 255, None),
    "X_GET_STATUS_DEV": (0x80, 0, 0, 0, 2, None),
    "X_GET_STATUS_IF": (0x81, 0, 0, 0, 2, None),
    "X_GET_STATUS_EP_IN": (0x82, 0, 0, 0x81, 2, None),
    "X_GET_STATUS_EP_OUT": (0x82, 0, 0, 0x01, 2, None),
    "X_CLEAR_FEATURE_DEV_RW": (0x00, 1, 1, 0, 0, None),
    "X_SET_FEATURE_DEV_RW": (0x00, 3, 1, 0, 0, None),
    "X_CLEAR_FEATURE_EP_IN": (0x02, 1, 0, 0x81, 0, None),
    "X_CLEAR_FEATURE_EP_OUT": (0x02, 1, 0, 0x01, 0, None),
    "X_SET_FEATURE_EP_IN": (0x02, 3, 0, 0x81, 0, None),
    "X_SET_FEATURE_EP_OUT": (0x02, 3, 0, 0x01, 0, None),
    "X_SET_ADDRESS": (0x00, 5, 0x002A, 0, 0, None),
    "X_GET_CONFIGURATION": (0x80, 8, 0, 0, 1, None),
    "X_SET_CONFIGURATION": (0x00, 9, 1, 0, 0, None),
    "X_SYNCH_FRAME": (0x82, 0x0C, 0, 0x81, 2, None),
}
#: Undeclared or out-of-range requests: they must reach NO entry's own handler.
CONTROLS = {
    "ctl-desc-type-0x99": (0x80, 6, 0x9900, 0, 16, None),
    "ctl-string-index-4": (0x80, 6, 0x0304, 0x0409, 64, None),
    "ctl-hid-class-iface-9": (0x81, 6, 0x2100, 9, 9, None),
    "ctl-report-iface-9": (0x81, 6, 0x2200, 9, 64, None),
    "ctl-get-report-iface-9": (0xA1, 1, 0x0100, 9, 8, None),
    "ctl-get-report-id-9": (0xA1, 1, 0x0109, 0, 8, None),
    "ctl-get-idle-iface-9": (0xA1, 2, 0x0000, 9, 1, None),
    "ctl-set-idle-iface-9": (0x21, 0x0A, 0x0000, 9, 0, None),
    "ctl-get-protocol-iface-1": (0xA1, 3, 0, 1, 1, None),
    "ctl-set-report-iface-2": (0x21, 9, 0x0200, 2, 1, b"\x02"),
    "ctl-set-report-id-5": (0x21, 9, 0x0205, 1, 2, b"\x05\x02"),
    "ctl-vendor-request": (0x40, 0x5A, 0, 0, 0, None),
    "ctl-class-req-0x20-iface-0": (0x21, 0x20, 0, 0, 7, b"\x00" * 7),
    "ctl-get-interface": (0x81, 0x0A, 0, 0, 1, None),
    "ctl-silence": None,
}
#: Malformed lengths on declared requests. Recorded, NOT asserted: a handler that
#: does not read wLength is reached whatever it says.
MALFORMED = {
    "mal-device-wlength-0": (0x80, 6, 0x0100, 0, 0, None),
    "mal-get-idle-wlength-0": (0xA1, 2, 0x0000, 0, 0, None),
    "mal-set-report-if0-wlength-0": (0x21, 9, 0x0200, 0, 0, None),
}

FAKE = 0x30000000
USBP = FAKE + 0x1000
CFG = FAKE + 0x2000
STACK_LO, STACK_HI = FAKE + 0x6000, FAKE + 0x8000
SRAM = 0x20000000
CONDB = {"beq", "bne", "bhi", "bls", "bcs", "bcc", "bhs", "blo", "bmi", "bpl", "bge", "blt",
         "bgt", "ble", "bvs", "bvc", "cbz", "cbnz", "tbb", "tbh"}

_CS = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
_CS.skipdata = True


def _need(cond, msg):
    if not cond:
        raise SystemExit("fuzz_reach_targets: " + msg)


class Arm:
    """Executes a dispatcher of THIS image on one request; see the module doc."""

    def __init__(self, img: bytes, setup_off: int):
        self.img, self.so = img, setup_off
        self._ic: dict = {}

    def ins(self, a):
        if a not in self._ic:
            self._ic[a] = next(_CS.disasm(self.img[a - BASE:a - BASE + 4], a), None)
        return self._ic[a]

    def run(self, start, regs, setup, cfg, ram=None, allow=(), cont=False, maxn=400):
        uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS)
        uc.mem_map(BASE, (len(self.img) + 0xFFF) & ~0xFFF)
        uc.mem_write(BASE, self.img)
        uc.mem_map(FAKE, 0x10000)
        uc.mem_map(SRAM, 0x20000)
        for a, data in (ram or {}).items():
            uc.mem_write(a, data)
        uc.mem_write(USBP + self.so, setup)
        uc.mem_write(USBP + 4, struct.pack("<I", CFG))
        uc.mem_write(CFG, struct.pack("<4I", *cfg))
        uc.reg_write(UA.UC_ARM_REG_SP, STACK_HI - 0x100)
        for k, v in regs.items():
            uc.reg_write(getattr(UA, "UC_ARM_REG_" + k.upper()), v)
        st = {"arm": start, "dec": None, "stop": None, "stop_pc": None, "call": None,
              "stores": {}, "n": 0, "trace": [], "regs_at_arm": None}

        def code(u, addr, size, _):
            st["n"] += 1
            i = self.ins(addr)
            m = i.mnemonic if i else "?"
            if st["dec"] is not None:
                st["arm"], st["dec"] = addr, None
                st["regs_at_arm"] = [u.reg_read(getattr(UA, "UC_ARM_REG_R%d" % k)) for k in range(4)]
            st["trace"].append("%x:%s %s" % (addr, m, i.op_str if i else ""))
            if st["n"] > maxn:
                st["stop"], st["stop_pc"] = "budget", addr
                u.emu_stop()
                return
            if m in ("bl", "blx"):
                tgt = int(i.op_str[1:], 16) if i.op_str.startswith("#") else \
                    u.reg_read(getattr(UA, "UC_ARM_REG_" + i.op_str.upper()))
                st["call"] = tgt & ~1
                if not cont:
                    st["stop"], st["stop_pc"] = "call", addr
                    u.emu_stop()
                return
            if m.startswith("ldr") and i.op_str.startswith("pc"):
                st["dec"] = addr
                return
            if (m == "bx" and i.op_str == "lr") or (m.startswith("pop") and "pc" in i.op_str):
                st["stop"], st["stop_pc"] = "ret", addr
                u.emu_stop()
                return
            if m in CONDB or (m.endswith(".w") and m[:-2] in CONDB):
                st["dec"] = addr

        def mem(u, access, addr, size, value, _):
            pc = u.reg_read(UA.UC_ARM_REG_PC)
            if access == unicorn.UC_MEM_WRITE:
                if STACK_LO <= addr < STACK_HI:
                    return
                if cont:
                    st["stores"][addr - USBP] = value
                    return
                st["stop"], st["stop_pc"] = "store", pc
                u.emu_stop()
            elif SRAM <= addr < SRAM + 0x20000 and not cont \
                    and not any(lo <= addr < hi for lo, hi in allow):
                st["stop"], st["stop_pc"] = "ramload", pc
                u.emu_stop()

        uc.hook_add(unicorn.UC_HOOK_CODE, code)
        uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, mem)
        try:
            uc.emu_start(start | 1, 0xFFFFFFFE, count=maxn + 5)
        except unicorn.UcError as exc:
            st["stop"], st["stop_pc"] = "fault:%s" % exc, uc.reg_read(UA.UC_ARM_REG_PC)
        return st


def _all_ins(img):
    return list(_CS.disasm(img, BASE))


def locate(img):
    ins = _all_ins(img)
    idx = {i.address: k for k, i in enumerate(ins)}
    gud = [i.address for k, i in enumerate(ins) if i.mnemonic == "lsrs" and i.op_str == "r2, r0, #8"
           and any(j.mnemonic == "cmp" and j.op_str.startswith("r2, #3") for j in ins[k + 1:k + 3])]
    _need(len(gud) == 1, "get_usb_descriptor candidates %r" % [hex(x) for x in gud])
    gud = gud[0]
    callers = [i.address for i in ins if i.mnemonic == "bl" and i.op_str == "#0x%x" % gud]
    _need(len(callers) == 1, "get_usb_descriptor callers %r" % callers)
    k = idx[callers[0]]
    while not ins[k].mnemonic.startswith("push"):
        k -= 1
    gdcb = ins[k].address
    lits = [BASE + o for o in range(0, len(img) - 3, 4)
            if struct.unpack_from("<I", img, o)[0] == gdcb | 1]
    _need(len(lits) == 1, "USBConfig literal %r" % lits)
    usbcfg = lits[0] - 4
    ev, gd, hook, sof = struct.unpack_from("<4I", img, usbcfg - BASE)
    _need(gd == gdcb | 1 and hook & 1, "USBConfig %x" % usbcfg)
    hook &= ~1
    h0 = ins[idx[hook] + 1]
    _need(h0.mnemonic == "ldrb.w" and h0.op_str.startswith("r2, [r0, #"), "hook prologue %s" % h0.op_str)
    so = int(h0.op_str.split("#")[1].rstrip("]"), 16)
    sites = []
    for k, i in enumerate(ins[:-3]):
        if i.mnemonic == "ldr" and i.op_str == "r3, [r4, #4]" and ins[k + 1].op_str == "r3, [r3, #8]" \
                and ins[k + 2].mnemonic == "cbnz" \
                and ins[k + 3].mnemonic == "ldrb.w" and ins[k + 3].op_str == "r3, [r4, #0x%x]" % so:
            sites.append(i.address)
    _need(len(sites) == 1, "_usb_ep0setup hook-load sites %r" % sites)
    return {"gud": gud, "gdcb": gdcb, "usbcfg": usbcfg, "hook": hook, "ep0sw": sites[0],
            "setup_off": so, "gud_caller": callers[0]}


def chain(a: Arm, L: dict, req):
    bm, rq, wv, wi, wl, out = req
    setup = struct.pack("<BBHHH", bm, rq, wv, wi, wl)
    cfg = (0, L["gdcb"] | 1, 0, 0)
    path = []

    def gud():
        g = a.run(L["gud"], {"r0": wv, "r1": wi, "r2": wl, "r3": USBP + 0x200}, setup, cfg)
        path.append({"kind": "gud", "arm": g["arm"], "stop": g["stop"], "r": g["regs_at_arm"]})
        return g
    q = a.run(L["hook"], {"r0": USBP}, setup, cfg)
    path.append({"kind": "hook", "arm": q["arm"], "stop": q["stop"], "r": q["regs_at_arm"]})
    if q["stop"] == "call" and q["call"] == L["gdcb"]:
        gud()
    elif q["stop"] == "call":
        # The hook called a helper (SET_IDLE stores the idle rate first) and then
        # goes on deciding. Resume after the call; if a further decision is taken,
        # the hook's arm is a ROUTE and the continuation's arm is the own handler.
        k = a.run(q["stop_pc"] + 4, {"r0": USBP, "r4": USBP}, setup, cfg)
        if k["arm"] != q["stop_pc"] + 4:
            path.append({"kind": "hookcont", "arm": k["arm"], "stop": k["stop"], "r": k["regs_at_arm"]})
    elif q["arm"] == L["hook_nf"]:
        c = a.run(L["ep0sw"], {"r4": USBP}, setup, cfg)
        path.append({"kind": "std", "arm": c["arm"], "stop": c["stop"], "r": c["regs_at_arm"]})
        if c["stop"] == "call" and c["call"] == L["gdcb"]:
            gud()
    if out is not None and path[-1]["kind"] == "hook" and path[-1]["arm"] != L["hook_nf"]:
        full = a.run(L["hook"], {"r0": USBP}, setup, cfg, cont=True)
        nxt = full["stores"].get(L["setup_off"] - 0x0C)
        cb = full["stores"].get(L["setup_off"] - 0x04)
        if cb:
            r = a.run(cb & ~1, {"r0": USBP}, setup, cfg, ram={nxt: out}, allow=[(nxt, nxt + len(out))])
            path.append({"kind": "cb", "arm": r["arm"], "stop": r["stop"], "r": r["regs_at_arm"],
                         "cb": cb & ~1, "buf": nxt})
    return path


def _req(t):
    bm, rq, wv, wi, wl, out = t
    d = {"bm": bm, "req": rq, "value": wv, "index": wi, "length": wl,
         "setup_hex": struct.pack("<BBHHH", bm, rq, wv, wi, wl).hex()}
    if out is not None:
        d["out_hex"] = out.hex()
    return d


def derive() -> dict:
    img = paths.firmware_bin().read_bytes()
    _need(not (set(INPUTS) & set(OUTPUTS)) and set(CENSUS_OF.values()) == {"if0", "if1", "if2"},
          "inputs/outputs overlap or an interface has no input")
    L = locate(img)
    a = Arm(img, L["setup_off"])
    cfg = (0, L["gdcb"] | 1, 0, 0)
    L["hook_nf"] = a.run(L["hook"], {"r0": USBP}, struct.pack("<BBHHH", 0x40, 0x5A, 0, 0, 0), cfg)["arm"]
    std_nf = a.run(L["ep0sw"], {"r4": USBP}, struct.pack("<BBHHH", 0x40, 0x5A, 0, 0, 0), cfg)["arm"]
    gud_nf = a.run(L["gud"], {"r0": 0x9900, "r1": 0, "r2": 16, "r3": USBP + 0x200},
                   b"\0" * 8, cfg)["arm"]
    rows = [("input", eid, t) for eid, t in INPUTS.items()]
    for eid, t in EXTRAS.items():
        rows.append(("extra", eid, t))
    entries = []
    for cls, eid, t in rows:
        p = chain(a, L, t)
        own = p[-1]
        _need(own["arm"] not in (L["hook_nf"], std_nf, gud_nf),
              "%s reaches a not-found arm 0x%x" % (eid, own["arm"]))
        e = {"id": eid, "class": cls, "census_id": ("iface" + CENSUS_OF[eid][2]) if eid in CENSUS_OF else None,
             "setup": _req(t), "handler": "0x%x" % own["arm"], "handler_kind": own["kind"],
             "route": ["%s:0x%x" % (x["kind"], x["arm"]) for x in p[:-1]],
             "chain_stops": [x["stop"] for x in p]}
        if own["kind"] == "gud":
            e["gud_r1_at_arm"] = own["r"][1] if own["r"] else None
        if own["kind"] == "cb":
            e["out_cb"] = "0x%x" % own["cb"]
        if eid in NOTES:
            e["note"] = NOTES[eid]
        entries.append(e)
    own_set = {int(e["handler"], 16) for e in entries}
    for e in entries:
        for r in e["route"]:
            _need(int(r.split(":")[1], 16) not in own_set,
                  "%s routes through another entry's own handler %s" % (e["id"], r))
    by_h: dict = {}
    for e in entries:
        by_h.setdefault(e["handler"], []).append(e["id"])
    for e in entries:
        e["handler_shared_with"] = [x for x in by_h[e["handler"]] if x != e["id"]]
    for k, e in enumerate(entries):
        e["next_entry"] = entries[(k + 1) % len(entries)]["id"]
    controls = []
    for cid, t in CONTROLS.items():
        if t is None:
            controls.append({"id": cid, "setup": None})
            continue
        p = chain(a, L, t)
        _need(p[-1]["arm"] not in own_set, "control %s reaches an own handler 0x%x" % (cid, p[-1]["arm"]))
        controls.append({"id": cid, "setup": _req(t),
                         "static_path": ["%s:0x%x" % (x["kind"], x["arm"]) for x in p]})
    for cid, t in MALFORMED.items():
        p = chain(a, L, t)
        controls.append({"id": cid, "malformed": True, "setup": _req(t),
                         "static_path": ["%s:0x%x" % (x["kind"], x["arm"]) for x in p],
                         "static_reaches_own": p[-1]["arm"] in own_set})
    vt = [struct.unpack_from("<I", img, 4 * x)[0] for x in range(16 + USB_IRQ + 1)]
    tk = vt[TICK_SLOT] & ~1
    tk_i = list(_CS.disasm(img[tk - BASE:tk - BASE + 8], tk))
    _need(not tk_i[0].mnemonic.startswith("b"), "%s is a thunk" % TICK_NAME)
    hooks = [{"kind": "entry", "addr": "0x%x" % L["hook"], "label": "requests_hook_cb"},
             {"kind": "route", "addr": "0x%x" % L["gud"], "label": "get_usb_descriptor"}]
    seen = {L["hook"], L["gud"]}
    for e in entries:
        h = int(e["handler"], 16)
        if h not in seen:
            seen.add(h)
            hooks.append({"kind": "own", "addr": e["handler"], "label": "+".join(by_h[e["handler"]]),
                          "akind": e["handler_kind"]})
    for e in entries:
        for r in e["route"]:
            k, h = r.split(":")
            if int(h, 16) not in seen:
                seen.add(int(h, 16))
                hooks.append({"kind": "route", "addr": h, "label": "route-%s-%s" % (k, h)})
    for nm, h in (("hook-declines", L["hook_nf"]), ("std-stall", std_nf), ("gud-not-found", gud_nf)):
        if h not in seen:
            seen.add(h)
            hooks.append({"kind": "shared", "addr": "0x%x" % h, "label": nm})
    for c in controls:
        for x in c.get("static_path", []):
            h = int(x.split(":")[1], 16)
            if h not in seen and h not in own_set:
                seen.add(h)
                hooks.append({"kind": "shared", "addr": "0x%x" % h, "label": "arm-of-%s" % c["id"]})
    hooks.append({"kind": "isr", "addr": "0x%x" % tk_i[1].address,
                  "label": "%s+2(exc%d)" % (TICK_NAME, TICK_SLOT)})
    return {
        "row": ROW, "lane": "s1011-laneAQ", "bin": BIN,
        "bin_sha256": hashlib.sha256(img).hexdigest(),
        "inventory_source": "census interfaces-ALL.tsv rows iface0/iface1/iface2 (INVENTORY.md), each "
                            "expanded into the requests the image's own dispatch parses for that interface",
        "located": {k: ("0x%x" % v if isinstance(v, int) else v) for k, v in L.items()},
        "not_found": {"hook_declines": "0x%x" % L["hook_nf"], "std_stall": "0x%x" % std_nf,
                      "gud_not_found": "0x%x" % gud_nf},
        "usb_exc": 16 + USB_IRQ, "tick_exc": TICK_SLOT,
        "entries": entries, "outputs": OUTPUTS, "controls": controls, "hooks": hooks,
    }


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    d = derive()
    out = paths.configs_dir() / "fuzz_reach_targets.json"
    js = json.dumps(d, indent=1) + "\n"
    if "--check" in argv:
        ok = out.exists() and out.read_text() == js
        print("fuzz_reach_targets --check: %s (%d entries, %d hooks, bin %s)"
              % ("PASS" if ok else "FAIL", len(d["entries"]), len(d["hooks"]), d["bin_sha256"][:16]))
        return 0 if ok else 1
    out.write_text(js)
    print("wrote %s: %d entries (%d census inputs, %d extras), %d hooks"
          % (out, len(d["entries"]), sum(e["class"] == "input" for e in d["entries"]),
             sum(e["class"] == "extra" for e in d["entries"]), len(d["hooks"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
