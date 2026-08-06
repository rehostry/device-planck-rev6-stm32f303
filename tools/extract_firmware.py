#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive this device's flash image and its generated address map from the
vendor artifact -- and HARD-FAIL if anything the config depends on has moved.

The vendor artifact is a **raw `.bin` with a 16-byte DFU suffix appended**
(playbook trap 180: PlatformIO/`dfu-suffix` do this and the result is *not* a
flash image).  Everything below is recovered from the bytes; nothing is
hardcoded that could silently drift when the firmware is rebuilt:

* the DFU suffix is parsed, its CRC-32 recomputed, and stripped -- and the
  payload length it implies is cross-checked against the reset handler's own
  ``.data`` copy bounds, so a wrong payload length is *arithmetically*
  impossible rather than merely unlikely (playbook trap 141/2.81);
* the seams the config intercepts (ChibiOS' idle ``wfi``, its halt self-loops,
  ``chSysPolledDelayX``) are located by instruction **shape**, so a rebuild
  moves them with the code instead of leaving them pointing at unrelated bytes
  (playbook traps 2.26 / 2.148);
* the USB descriptors the M4 prediction is made of are recovered by decoding
  the firmware's own ``usb_get_descriptor_cb`` dispatch table, and their bytes
  are printed so PROVENANCE.md can be checked against the image at any time.

Run it with no arguments and it will find the vendor artifact in the usual
place; ``--src`` overrides.  Output goes to ``src/rehostry_planck/configs/``.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import zlib
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
DEFAULT_SRC = Path("/Users/user/Development/firmware-incoming/W3a-usb-hid/"
                   "planck_rev6_stm32f303/planck_rev6_default.bin")
DEFAULT_OUT = HERE.parent / "src" / "rehostry_planck" / "configs"

#: sha256 of the vendor artifact this device was derived from (with suffix).
VENDOR_SHA256 = ("dd753dab8717c6c95c3cad83d04cddf4a895558f95df3e710843a4e85"
                 "101f178")

FLASH_BASE = 0x08000000
SRAM_BASE = 0x20000000

#: Everything the config hardcodes, asserted against the recovered image.
EXPECT_INIT_SP = 0x20000400          # vector[0] -- the MAIN stack top
EXPECT_RESET = 0x080002BD            # vector[1] (Thumb)
EXPECT_UNHANDLED = 0x080002BF        # ChibiOS' weak `_unhandled_exception`
EXPECT_USB_LP_IRQ = 75               # the *remapped* USB low-priority line
#: The system tick is DERIVED (see find_system_timer) -- these are only the
#: values this device was built against, asserted so a rebuild that moves the
#: timer fails here instead of silently injecting into an unrelated vector.
EXPECT_ST_BASE = 0x40000400          # TIM3, NOT TIM2
EXPECT_ST_IRQ = 29
EXPECT_ST_BITS = 16                  # TIM3 is a 16-bit counter on the F3
EXPECT_PAYLOAD_LEN = 0xF140          # 61760 B, i.e. the file minus the suffix

#: The DFU suffix identifies the bootloader the vendor targets.
EXPECT_DFU_VID = 0x0483              # STMicroelectronics
EXPECT_DFU_PID = 0xDF11              # STM32 system-memory DFU


class Fail(SystemExit):
    def __init__(self, msg: str) -> None:
        super().__init__("EXTRACTION FAILED: " + msg)


def u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


# ---------------------------------------------------------------------------
# 1. the DFU suffix
# ---------------------------------------------------------------------------
def strip_dfu_suffix(raw: bytes) -> bytes:
    """Validate and remove the 16-byte DFU suffix; return the flash image.

    A `.bin` that has been through `dfu-suffix` is not a flash image: the last
    16 bytes are metadata, and loading them as code puts garbage at the end of
    flash (playbook trap 180).  The suffix is self-checking -- it carries a
    CRC-32 over everything before it -- so this is a *proof*, not a heuristic.
    """
    if len(raw) < 16:
        raise Fail("artifact is too small to hold a DFU suffix")
    suffix = raw[-16:]
    if suffix[8:11] != b"UFD":
        raise Fail("no DFU suffix signature ('UFD') at the end of the image; "
                   "this build is shaped differently from the one this device "
                   "was derived from -- re-derive before trusting anything")
    if suffix[11] != 16:
        raise Fail("DFU suffix bLength is %d, expected 16" % suffix[11])
    _bcd_dev, pid, vid, _bcd_dfu = struct.unpack_from("<HHHH", suffix, 0)
    stored = u32(suffix, 12)
    # dfu-suffix's CRC is the *running* CRC-32 (no final complement) over every
    # byte up to but excluding dwCRC itself.
    computed = zlib.crc32(raw[:-4]) ^ 0xFFFFFFFF
    if computed != stored:
        raise Fail("DFU suffix CRC mismatch: stored 0x%08X, computed 0x%08X"
                   % (stored, computed))
    if (vid, pid) != (EXPECT_DFU_VID, EXPECT_DFU_PID):
        raise Fail("DFU suffix targets %04x:%04x, expected %04x:%04x "
                   "(STM32 system-memory DFU)"
                   % (vid, pid, EXPECT_DFU_VID, EXPECT_DFU_PID))
    print("DFU suffix: %04x:%04x, CRC-32 0x%08X VERIFIED -- stripping 16 bytes"
          % (vid, pid, stored))
    return raw[:-16]


# ---------------------------------------------------------------------------
# 2. the vector table + the load base, proven arithmetically
# ---------------------------------------------------------------------------
def check_vectors(img: bytes) -> None:
    sp, reset = u32(img, 0), u32(img, 4)
    if sp != EXPECT_INIT_SP:
        raise Fail("vector[0] (init SP) is 0x%08X, config says 0x%08X"
                   % (sp, EXPECT_INIT_SP))
    if reset != EXPECT_RESET:
        raise Fail("vector[1] (reset) is 0x%08X, config says 0x%08X"
                   % (reset, EXPECT_RESET))
    stub = u32(img, 2 * 4)
    if stub != EXPECT_UNHANDLED:
        raise Fail("vector[2] is 0x%08X; expected ChibiOS' weak stub 0x%08X"
                   % (stub, EXPECT_UNHANDLED))
    # A vector-name/stub guard is VACUOUS unless it can also FAIL (playbook
    # traps 118/151/161).  So: the two lines this device injects must NOT be
    # the stub, and a line the board genuinely does not use MUST be.
    for irq, who in ((EXPECT_ST_IRQ, "the RTOS system tick (DERIVED)"),
                     (EXPECT_USB_LP_IRQ, "USB low-priority (remapped)")):
        v = u32(img, (16 + irq) * 4)
        if v == stub:
            raise Fail("IRQ %d (%s) points at the unhandled-exception stub -- "
                       "this build does not wire it up" % (irq, who))
        print("IRQ %-3d %-32s -> 0x%08X (live)" % (irq, who, v))
    # Maximally pointed control set: IRQ 19/20 are the *non*-remapped
    # USB_HP_CAN_TX / USB_LP_CAN_RX0 lines.  Requiring them to be the stub does
    # not merely show the guard can fail -- it refutes "just inject IRQ 20, it
    # is the USB interrupt on an F3", which is what a datasheet would tell you.
    for irq in (19, 20, 33):
        if u32(img, (16 + irq) * 4) != stub:
            raise Fail("control IRQ %d is NOT the stub, so 'is it the stub?' "
                       "cannot discriminate anything on this image" % irq)
    print("control: IRQs 19/20 (the NON-remapped USB lines) and 33 are the "
          "stub, so the guard above can fail")


def check_load_base(img: bytes) -> dict:
    """Recover crt0's own copy bounds and prove the payload length from them.

    The reset stub is the board's datasheet (playbook trap 129).  This one
    ends with a ``.data`` copy whose *load* pointer plus the ``.data`` size
    must land exactly on the end of the payload -- the image ends on the last
    byte of ``.data``.  That is an independent, arithmetic confirmation of both
    the load base and the DFU-suffix strip (playbook trap 147).
    """
    # crt0's literal pool, immediately after the reset code at 0x08000280.
    lit = {name: u32(img, off) for name, off in (
        ("msp_top", 0x280), ("psp_top", 0x284), ("vtor", 0x288),
        ("main_stack_base", 0x290), ("process_stack_base", 0x294),
        ("data_load", 0x298), ("data_start", 0x29C), ("data_end", 0x2A0),
        ("bss_start", 0x2A4), ("bss_end", 0x2A8))}
    for k, v in lit.items():
        print("crt0 %-19s = 0x%08X" % (k, v))
    if lit["vtor"] != FLASH_BASE:
        raise Fail("crt0 writes SCB->VTOR = 0x%08X, not the load base 0x%08X"
                   % (lit["vtor"], FLASH_BASE))
    if lit["msp_top"] != EXPECT_INIT_SP:
        raise Fail("crt0's MSP top (0x%08X) disagrees with vector[0]"
                   % lit["msp_top"])
    data_len = lit["data_end"] - lit["data_start"]
    end = lit["data_load"] + data_len
    if end != FLASH_BASE + len(img):
        raise Fail(".data load 0x%08X + size 0x%X = 0x%08X, but the payload "
                   "ends at 0x%08X -- the load base or the suffix strip is "
                   "wrong" % (lit["data_load"], data_len, end,
                              FLASH_BASE + len(img)))
    print(".data: load 0x%08X -> RAM 0x%08X..0x%08X (0x%X bytes); "
          "load+size == end of payload  PROVEN"
          % (lit["data_load"], lit["data_start"], lit["data_end"], data_len))
    if len(img) != EXPECT_PAYLOAD_LEN:
        raise Fail("payload is %d bytes, expected %d"
                   % (len(img), EXPECT_PAYLOAD_LEN))
    return lit


def data_initial(img: bytes, lit: dict, ram_addr: int, n: int) -> bytes:
    """The initial value a ``.data`` variable gets, read from the flash image."""
    if not lit["data_start"] <= ram_addr < lit["data_end"]:
        raise Fail("0x%08X is not in .data" % ram_addr)
    off = lit["data_load"] - FLASH_BASE + (ram_addr - lit["data_start"])
    return img[off:off + n]


# ---------------------------------------------------------------------------
# 3. seams, located by instruction shape
# ---------------------------------------------------------------------------
def find_seams(img: bytes) -> dict:
    words = {}
    for o in range(0, len(img) - 3, 4):
        words.setdefault(u32(img, o), []).append(o)

    # -- ChibiOS' idle thread.  Built with CORTEX_ENABLE_WFI_IDLE TRUE here, so
    #    it is `wfi ; b .-2`.  Distinguish it from any other `wfi` the way
    #    device-nanovna-h4 does for its `b .`: the idle thread is the only one
    #    whose `address | 1` appears as a word-aligned literal, because
    #    `port_init_context` stores it as a THREAD ENTRY POINT.
    wfi = [o for o in range(0, len(img) - 1, 2)
           if img[o] == 0x30 and img[o + 1] == 0xBF]
    idle = []
    for o in wfi:
        addr = FLASH_BASE + o
        if any(FLASH_BASE + r >= 0x08000190 for r in words.get(addr | 1, [])):
            idle.append(addr)
    if len(idle) != 1:
        raise Fail("expected exactly one `wfi` referenced as a thread entry "
                   "point (ChibiOS' idle thread); found %s"
                   % [hex(a) for a in idle])
    print("idle thread (wfi seam) : 0x%08X   (of %d `wfi` in the image)"
          % (idle[0], len(wfi)))

    # -- ChibiOS' halt self-loops (`b .`), purely diagnostic seams.
    halts = [FLASH_BASE + o for o in range(0, len(img) - 1, 2)
             if img[o] == 0xFE and img[o + 1] == 0xE7]
    if not halts:
        raise Fail("no `b .` self-loop found; this is not a ChibiOS image")
    print("halt self-loops        : %s" % " ".join("0x%08X" % a for a in halts))

    # -- chSysPolledDelayX: `ldr r2,=0xE0001000 ; ldr r1,[r2,#4] ;
    #    loop: ldr r3,[r2,#4] ; subs r3,r3,r1 ; cmp r0,r3 ; bhi loop ; bx lr`.
    #    It spins on DWT->CYCCNT, which is inside the PPB and NEVER advances
    #    under unicorn, so the loop cannot terminate (playbook trap 174).
    #    Found by its literal + the exact instruction shape.
    polled = []
    for o in words.get(0xE0001000, []):
        for start in range(max(0, o - 0x20), o):
            if img[start:start + 12] == bytes.fromhex(
                    "5168" "5368" "5b1a" "9842" "fbd8" "7047"):
                polled.append(FLASH_BASE + start - 2)
    polled = sorted(set(polled))
    if len(polled) != 1:
        raise Fail("expected exactly one chSysPolledDelayX; found %s"
                   % [hex(a) for a in polled])
    print("chSysPolledDelayX      : 0x%08X" % polled[0])

    return {"idle": idle[0], "halts": halts, "polled_delay": polled[0]}


def _bl_target(img: bytes, off: int) -> Optional[int]:
    """Decode a Thumb-2 ``bl`` at ``off``; None if there is not one there."""
    if off + 4 > len(img):
        return None
    h1, h2 = u16(img, off), u16(img, off + 2)
    if (h1 & 0xF800) != 0xF000 or (h2 & 0xD000) != 0xD000:
        return None
    s = (h1 >> 10) & 1
    imm10, imm11 = h1 & 0x3FF, h2 & 0x7FF
    j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
    i1, i2 = 1 - (j1 ^ s), 1 - (j2 ^ s)
    delta = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
    if s:
        delta -= 1 << 25
    return FLASH_BASE + off + 4 + delta


def find_system_timer(img: bytes) -> dict:
    """Derive which timer ChibiOS ticks on, its width, and its interrupt line.

    **Never copy this from a sibling device** (playbook trap 141). The sibling
    STM32F303/ChibiOS rehost in this fleet (device-nanovna-h4) ticks on
    **TIM2 / IRQ 28**; this image ticks on **TIM3 / IRQ 29**, and IRQ 28 is
    *also live* here (QMK drives TIM2 as a PWM/GPT), so "is the vector the weak
    stub?" answers YES for the wrong timer and a copied number injects into a
    real, unrelated handler. That mistake was made on this device's first boot
    and cost a run.

    Everything below is decoded instead:

    * ``st_lld_get_counter()`` is four instructions and gives the base *and*
      the counter width -- a ``uxth`` after the load means a 16-bit timer::

          08008724:  ldr  r3, =0x40000400
                     ldr  r0, [r3, #0x24]     ; TIMx->CNT
                     uxth r0, r0              ; <- 16-bit
                     bx   lr

    * ``st_lld_start_alarm()`` must write ``CCR1`` (+0x34), clear ``SR``
      (+0x10) and set ``DIER`` (+0x0C) at that same base.
    * the interrupt line is the **unique** live vector whose handler reaches a
      function that carries that base in its literal pool (playbook trap 197 --
      derive the line from what the handler CALLS, not from a datasheet).
    """
    cands = []
    for shape, bits in ((bytes.fromhex("014b" "586a" "80b2" "7047"), 16),
                        (bytes.fromhex("014b" "586a" "7047"), 32)):
        start = 0
        while True:
            o = img.find(shape, start)
            if o < 0:
                break
            start = o + 2
            lit = ((o + 4) & ~3) + 4            # `ldr r3,[pc,#4]`
            cands.append((FLASH_BASE + o, u32(img, lit), bits))
    if len(cands) != 1:
        raise Fail("expected exactly one st_lld_get_counter shape; found %s"
                   % [(hex(a), hex(b), w) for a, b, w in cands])
    getter, base, bits = cands[0]
    print("st_lld_get_counter    : 0x%08X -> timer at 0x%08X, %d-bit counter"
          % (getter, base, bits))

    # st_lld_start_alarm: CCR1 <- t ; SR <- 0 ; DIER <- CC1IE, at the same base.
    alarm = bytes.fromhex("034b" "0022" "5863" "1a61" "0222" "da60" "7047")
    o = img.find(alarm)
    if o < 0:
        raise Fail("st_lld_start_alarm's CCR1/SR/DIER sequence not found")
    lit = ((o + 4) & ~3) + 4 * 3
    if u32(img, lit) != base:
        raise Fail("st_lld_start_alarm programs 0x%08X but st_lld_get_counter "
                   "reads 0x%08X" % (u32(img, lit), base))
    print("st_lld_start_alarm    : 0x%08X (CCR1/SR/DIER at the same base)"
          % (FLASH_BASE + o))

    stub = u32(img, 2 * 4)
    hits = []
    for irq in range(84):
        v = u32(img, (16 + irq) * 4)
        if v == stub:
            continue
        entry = (v & ~1) - FLASH_BASE
        for probe in (entry, entry + 2, entry + 4, entry + 6):
            target = _bl_target(img, probe)
            if target is None:
                continue
            f = (target & ~1) - FLASH_BASE
            if any(u32(img, f + i) == base
                   for i in range(0, 0x60, 4) if f + i + 4 <= len(img)):
                hits.append((irq, v, target))
                break
    if len(hits) != 1:
        raise Fail("expected exactly one live vector whose handler reaches the "
                   "system timer; found %s" % [(i, hex(v)) for i, v, _ in hits])
    irq, vec, serve = hits[0]
    print("system tick           : IRQ %d, vector 0x%08X -> serve 0x%08X"
          % (irq, vec, serve))
    if (base, irq, bits) != (EXPECT_ST_BASE, EXPECT_ST_IRQ, EXPECT_ST_BITS):
        raise Fail("system tick moved: derived (0x%08X, IRQ %d, %d-bit), the "
                   "config was built against (0x%08X, IRQ %d, %d-bit)"
                   % (base, irq, bits, EXPECT_ST_BASE, EXPECT_ST_IRQ,
                      EXPECT_ST_BITS))
    # Pointed control: the sibling F303/ChibiOS device in this fleet ticks on
    # TIM2/IRQ 28, and IRQ 28 is LIVE here too -- so a "is it the stub?" check
    # on the copied number passes. Assert the derivation actually rejects it.
    if irq == 28 or base == 0x40000000:
        raise Fail("the derivation returned the sibling device's TIM2/IRQ 28, "
                   "which means it is not discriminating")
    if u32(img, (16 + 28) * 4) == stub:
        raise Fail("IRQ 28 is the stub on this image, so 'the derivation "
                   "rejected a LIVE wrong candidate' is not demonstrated")
    print("control: IRQ 28 (TIM2) is LIVE here and was still rejected, so the "
          "derivation discriminates rather than just avoiding the stub")
    return {"base": base, "irq": irq, "bits": bits, "vector": vec,
            "serve": serve, "getter": getter}


# ---------------------------------------------------------------------------
# 4. the USB descriptors -- decoded from the firmware's own dispatch
# ---------------------------------------------------------------------------
def find_descriptors(img: bytes) -> dict:
    """Recover every descriptor ``usb_get_descriptor_cb`` can return.

    Anchored on the device descriptor's own bytes rather than on an address:
    a USB device descriptor is 18 bytes beginning ``12 01`` and carrying the
    vendor and product ids, so it can be located without trusting any pointer.
    Everything else is then reached from the tables the firmware itself
    indexes.
    """
    out = {}
    dev = None
    for o in range(0, len(img) - 18):
        if img[o] == 0x12 and img[o + 1] == 0x01 and u16(img, o + 8) == 0x03A8:
            dev = o
            break
    if dev is None:
        raise Fail("no USB device descriptor with idVendor 0x03A8 (OLKB)")
    out["device"] = (FLASH_BASE + dev, bytes(img[dev:dev + 18]))
    vid, pid, bcd = u16(img, dev + 8), u16(img, dev + 10), u16(img, dev + 12)
    print("device descriptor      : 0x%08X  VID %04X PID %04X bcdDevice %04X"
          % (FLASH_BASE + dev, vid, pid, bcd))
    if (vid, pid) != (0x03A8, 0xA4F9):
        raise Fail("VID:PID is %04x:%04x, expected 03a8:a4f9 (OLKB Planck)"
                   % (vid, pid))

    # The configuration descriptor: `09 02 <wTotalLength> ...`, and its total
    # length must close over its own interface/HID/endpoint descriptors.
    cfg = None
    for o in range(0, len(img) - 9):
        if img[o] == 0x09 and img[o + 1] == 0x02:
            total = u16(img, o + 2)
            if 9 < total < 512 and img[o + 4] in (1, 2, 3, 4):
                # walk it: every sub-descriptor must have a sane length
                i, ok = o, True
                while i < o + total:
                    if img[i] == 0 or i + img[i] > o + total:
                        ok = False
                        break
                    i += img[i]
                if ok and i == o + total:
                    cfg = o
                    break
    if cfg is None:
        raise Fail("no self-consistent configuration descriptor found")
    total = u16(img, cfg + 2)
    out["config"] = (FLASH_BASE + cfg, bytes(img[cfg:cfg + total]))
    print("config descriptor      : 0x%08X  %d bytes, %d interfaces"
          % (FLASH_BASE + cfg, total, img[cfg + 4]))

    # HID report descriptors: the firmware keeps a pointer table and a
    # parallel byte-length table, indexed by interface number.  Find the
    # pointer table by looking for three consecutive in-flash pointers whose
    # targets start with a HID_RI_USAGE_PAGE item (0x05 or 0x06).
    ptr_tbl = None
    for o in range(0, len(img) - 12, 4):
        ptrs = [u32(img, o + 4 * i) for i in range(3)]
        if not all(FLASH_BASE <= p < FLASH_BASE + len(img) for p in ptrs):
            continue
        if all(img[p - FLASH_BASE] in (0x05, 0x06) for p in ptrs):
            ptr_tbl = (o, ptrs)
            break
    if ptr_tbl is None:
        raise Fail("no HID report-descriptor pointer table found")
    tbl_off, ptrs = ptr_tbl
    lens = img[tbl_off - 4:tbl_off - 1]
    reports = []
    for i, (p, n) in enumerate(zip(ptrs, lens)):
        body = bytes(img[p - FLASH_BASE:p - FLASH_BASE + n])
        if body[-1] != 0xC0:
            raise Fail("report descriptor %d does not end in END_COLLECTION"
                       % i)
        reports.append((p, body))
        print("HID report descriptor %d: 0x%08X  %3d bytes" % (i, p, n))
    out["reports"] = reports

    # String descriptors, found by their own shape (`<len> 03 <UTF-16LE>`).
    strings = []
    for o in range(0, len(img) - 4):
        n = img[o]
        if img[o + 1] != 0x03 or n < 4 or n % 2 or o + n > len(img):
            continue
        body = img[o + 2:o + n]
        if all(32 <= body[i] < 127 and body[i + 1] == 0
               for i in range(0, len(body), 2)):
            text = body.decode("utf-16-le")
            strings.append((FLASH_BASE + o, bytes(img[o:o + n]), text))
    out["strings"] = strings
    for a, b, t in strings:
        print("string descriptor      : 0x%08X  %2d bytes  %r" % (a, len(b), t))
    if not any(t == "OLKB" for _, _, t in strings) or \
            not any(t == "Planck" for _, _, t in strings):
        raise Fail("the OLKB/Planck string descriptors are not both present")
    return out


# ---------------------------------------------------------------------------
# 5. the matrix + the keymap, read out of the firmware
# ---------------------------------------------------------------------------
def find_matrix(img: bytes) -> dict:
    """Recover QMK's column/row pin tables and the keymap the build shipped."""
    # `keymap_key_to_keycode_raw` is a tiny, distinctive function:
    #   cbnz r0,<oob> ; cmp r1,#7 ; bhi <oob> ; cmp r2,#5 ; bhi <oob> ;
    #   movs r3,#6 ; mla r2,r3,r1,r2 ; ldr r3,=keymaps ; ldrh.w r0,[r3,r2,lsl#1]
    shape = bytes.fromhex("0623" "03fb" "0122")  # movs r3,#6 ; mla r2,r3,r1,r2
    hit = img.find(shape)
    if hit < 0:
        raise Fail("keymap_key_to_keycode_raw's `6*row + col` shape not found")
    if img[hit - 7] != 0x29 or img[hit - 3] != 0x2A:
        raise Fail("the matrix bound checks are not the expected cmp r1/r2")
    rows = img[hit - 8] + 1                      # `cmp r1,#ROWS-1` immediate
    cols = img[hit - 4] + 1                      # `cmp r2,#COLS-1` immediate
    if img[hit] != 0x06 or cols != 6:
        raise Fail("the stride constant (%d) and MATRIX_COLS (%d) disagree"
                   % (img[hit], cols))
    # `ldr r3,[pc,#imm8*4]` sits immediately after the mla; decode it rather
    # than assuming an alignment, or the recovered base is silently wrong.
    ldr_at = hit + 6
    if img[ldr_at + 1] != 0x4B:
        raise Fail("expected `ldr r3,[pc,#N]` after the mla")
    lit = ((ldr_at + 4) & ~3) + 4 * img[ldr_at]
    keymap_base = u32(img, lit)
    if not FLASH_BASE <= keymap_base < FLASH_BASE + len(img):
        raise Fail("recovered keymaps[] base 0x%08X is not in flash"
                   % keymap_base)
    n = rows * cols
    keymap = [u16(img, keymap_base - FLASH_BASE + 2 * i) for i in range(n)]
    print("matrix                 : %d rows x %d cols" % (rows, cols))
    print("keymaps[]              : 0x%08X, one layer, %d entries"
          % (keymap_base, n))
    distinct = sorted(set(keymap))
    print("keymap distinct values : %s" % " ".join("0x%04X" % v
                                                   for v in distinct[:8]))

    # The pin tables: `ioline_t` values are (GPIO base | pad), and this SoC
    # puts GPIOA..GPIOF at 0x48000000 + 0x400*n.
    def is_line(w):
        return 0x48000000 <= w < 0x48001800 and (w & 0x3F0) == 0

    best = None
    for o in range(0, len(img) - 4 * (rows + cols), 4):
        block = [u32(img, o + 4 * i) for i in range(cols + rows)]
        if all(is_line(w) for w in block):
            best = (o, block)
            break
    if best is None:
        raise Fail("no contiguous col+row ioline_t table found")
    o, block = best
    col_pins, row_pins = block[:cols], block[cols:]
    names = "ABCDEF"

    def nm(w):
        return "%s%d" % (names[(w >> 10) & 7], w & 0xF)
    print("MATRIX_COL_PINS @0x%08X: %s"
          % (FLASH_BASE + o, " ".join(nm(w) for w in col_pins)))
    print("MATRIX_ROW_PINS @0x%08X: %s"
          % (FLASH_BASE + o + 4 * cols, " ".join(nm(w) for w in row_pins)))
    return {"rows": rows, "cols": cols, "keymap_base": keymap_base,
            "keymap": keymap, "col_pins": col_pins, "row_pins": row_pins,
            "col_pins_addr": FLASH_BASE + o,
            "row_pins_addr": FLASH_BASE + o + 4 * cols}


# ---------------------------------------------------------------------------
# 6. QMK's HID host state (the attack's firmware-side witness)
# ---------------------------------------------------------------------------
def find_host_state(img: bytes, lit: dict) -> dict:
    """Locate `keyboard_idle` / `keyboard_led_state` / `keyboard_protocol`.

    `get_keyboard_protocol()` is three instructions:
        ldr r3,[pc,#4] ; ldrb r0,[r3,#2] ; bx lr ; nop ; .word <base>
    so the base address of QMK's host state block falls straight out, and the
    variables' power-on values can then be read from the `.data` initialiser
    image rather than guessed (playbook trap 163: derive an initial-value
    prediction from what the boot path actually loads).
    """
    shape = bytes.fromhex("014b" "9878" "7047" "00bf")
    hit = img.find(shape)
    if hit < 0:
        raise Fail("get_keyboard_protocol()'s shape not found")
    base = u32(img, hit + 8)
    if not SRAM_BASE <= base < SRAM_BASE + 0x10000:
        raise Fail("recovered host-state base 0x%08X is not in SRAM" % base)
    init = data_initial(img, lit, base, 3)
    print("QMK host state         : 0x%08X  idle=0x%02X led=0x%02X "
          "protocol=0x%02X (from the .data image)"
          % (base, init[0], init[1], init[2]))
    if init[2] != 1:
        raise Fail("keyboard_protocol's power-on value is 0x%02X, not 1 "
                   "(report protocol) -- the attack's prediction is stale"
                   % init[2])
    return {"base": base, "idle": base, "led_state": base + 1,
            "protocol": base + 2, "init": init}


# ---------------------------------------------------------------------------
def emit_yaml(out_dir: Path, seams: dict, matrix: dict, host: dict,
              descs: dict, timer: dict) -> None:
    lines = [
        "# GENERATED by tools/extract_firmware.py -- do not hand-edit.",
        "#",
        "# `intercepts:` keys APPEND across config files (hal_config.py's",
        "# _parse_intercepts appends, it does not override), so this is loaded",
        "# alongside planck_config.yaml.",
        "#",
        "# Every address here is DERIVED by scanning the image, so a firmware",
        "# rebuild moves the seam with the code rather than leaving it on",
        "# unrelated bytes (playbook trap 2.26).",
        "intercepts:",
        "  # ChibiOS' idle thread: `wfi ; b .-2`.  The kernel STATING that it",
        "  # has nothing runnable -- where guest time is advanced and the TIM2",
        "  # and USB interrupts are delivered (playbook traps 121/218).",
        "  - class: rehostry_planck.bp_handlers.irq_pump.IrqPump",
        "    function: irq_pump",
        "    addr: 0x%08X" % seams["idle"],
        "  # chSysPolledDelayX spins on DWT->CYCCNT, which lives in the PPB and",
        "  # never advances under unicorn, so the loop cannot terminate",
        "  # (playbook trap 174).  It is a void busy-wait with no side effects,",
        "  # so answering it at its own call boundary is exactly right.",
        "  - class: rehostry_planck.bp_handlers.polled_delay.PolledDelay",
        "    function: polled_delay",
        "    addr: 0x%08X" % seams["polled_delay"],
    ]
    for a in seams["halts"]:
        lines += [
            "  # A ChibiOS halt self-loop (panic / _unhandled_exception /",
            "  # thread-returned).  Diagnostic only: without it a kernel panic",
            "  # is an anonymous hang (playbook trap 67).",
            "  - class: rehostry_planck.bp_handlers.halt_probe.HaltProbe",
            "    function: halt_probe",
            "    addr: 0x%08X" % a,
        ]
    (out_dir / "planck_addrs.yaml").write_text("\n".join(lines) + "\n")
    print("wrote %s" % (out_dir / "planck_addrs.yaml"))

    facts = [
        "# GENERATED by tools/extract_firmware.py -- do not hand-edit.",
        "#",
        "# The system tick is DERIVED, never copied from a sibling device",
        "# (playbook trap 141): this image ticks on TIM3/IRQ 29, while the",
        "# fleet's other STM32F303/ChibiOS rehost ticks on TIM2/IRQ 28 -- and",
        "# IRQ 28 is live here too, so a copied number injects into a real,",
        "# unrelated handler with nothing looking wrong.",
        "#",
        "# Facts recovered from the firmware image, consumed by the device's",
        "# models, its attack and its tests.  Keeping them here (rather than as",
        "# literals in Python) means a rebuild that moves anything fails at",
        "# EXTRACTION rather than as a confusing runtime symptom.",
        "system_timer:",
        "  base: 0x%08X" % timer["base"],
        "  irq: %d" % timer["irq"],
        "  bits: %d" % timer["bits"],
        "  vector: 0x%08X" % timer["vector"],
        "  serve: 0x%08X" % timer["serve"],
        "matrix:",
        "  rows: %d" % matrix["rows"],
        "  cols: %d" % matrix["cols"],
        "  col_pins_addr: 0x%08X" % matrix["col_pins_addr"],
        "  row_pins_addr: 0x%08X" % matrix["row_pins_addr"],
        "  col_pins: [%s]" % ", ".join("0x%08X" % w
                                       for w in matrix["col_pins"]),
        "  row_pins: [%s]" % ", ".join("0x%08X" % w
                                       for w in matrix["row_pins"]),
        "  keymap_base: 0x%08X" % matrix["keymap_base"],
        "  keymap_layers: 1",
        "  keymap_all_transparent: %s"
        % str(all(v == 1 for v in matrix["keymap"])).lower(),
        "host_state:",
        "  keyboard_idle: 0x%08X" % host["idle"],
        "  keyboard_led_state: 0x%08X" % host["led_state"],
        "  keyboard_protocol: 0x%08X" % host["protocol"],
        "  power_on: [0x%02X, 0x%02X, 0x%02X]" % tuple(host["init"]),
        "usb:",
        "  device_descriptor_addr: 0x%08X" % descs["device"][0],
        "  device_descriptor: %s" % descs["device"][1].hex(),
        "  config_descriptor_addr: 0x%08X" % descs["config"][0],
        "  config_descriptor: %s" % descs["config"][1].hex(),
        "  report_descriptors:",
    ]
    for a, b in descs["reports"]:
        facts += ["    - addr: 0x%08X" % a,
                  "      bytes: %s" % b.hex()]
    facts += ["  strings:"]
    for a, b, t in descs["strings"]:
        facts += ["    - addr: 0x%08X" % a,
                  "      text: %r" % t,
                  "      bytes: %s" % b.hex()]
    (out_dir / "planck_facts.yaml").write_text("\n".join(facts) + "\n")
    print("wrote %s" % (out_dir / "planck_facts.yaml"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC,
                    help="the vendor .bin (with its DFU suffix)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help="configs/ directory to write into")
    ap.add_argument("--no-sha-check", action="store_true",
                    help="allow a different vendor artifact (prints the sha)")
    args = ap.parse_args(argv)

    if not args.src.is_file():
        raise Fail("vendor artifact not found: %s" % args.src)
    raw = args.src.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    print("vendor artifact        : %s" % args.src)
    print("  %d bytes, sha256 %s" % (len(raw), sha))
    if sha != VENDOR_SHA256 and not args.no_sha_check:
        raise Fail("sha256 mismatch (expected %s); pass --no-sha-check to "
                   "re-derive from a different build" % VENDOR_SHA256)

    img = strip_dfu_suffix(raw)
    print("flash image            : %d bytes at 0x%08X, sha256 %s"
          % (len(img), FLASH_BASE, hashlib.sha256(img).hexdigest()))
    check_vectors(img)
    lit = check_load_base(img)
    seams = find_seams(img)
    timer = find_system_timer(img)
    descs = find_descriptors(img)
    matrix = find_matrix(img)
    host = find_host_state(img, lit)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "planck.bin").write_bytes(img)
    print("wrote %s" % (args.out / "planck.bin"))
    emit_yaml(args.out, seams, matrix, host, descs, timer)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
