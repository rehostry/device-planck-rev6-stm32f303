# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The STM32F303 USB device peripheral -- the wire the VNA's shell speaks on.

**This is the seam.** The firmware's compiled-in configuration puts its command
shell on ``SDU1`` (USB CDC), not on the UART, and the shell task blocks until
``USBD1.state == USB_ACTIVE``. So unlike most devices in this fleet there is no
cheaper transport to fall back on: the USB device peripheral has to be modelled,
and something has to act as the **host** (``usb_host.py``).

THE F303 USB BLOCK IS THE F1/F072 ONE, NOT THE OTG CORE. It is worth saying
explicitly because the family number invites the wrong assumption: an STM32F4's
USB is a Synopsys DWC OTG core with FIFOs at 0x50000000, and none of it applies
here. The F303 has the classic ST "USB device FS" peripheral -- eight
bidirectional endpoints, a shared packet-memory area, a buffer descriptor table
-- register-for-register the same block as the STM32F103 (RM0316 §30 vs
RM0008 §23).

TWO REGIONS:

``USB registers`` at 0x40005C00
    ``EP0R..EP7R`` (0x00..0x1C), ``CNTR`` (0x40), ``ISTR`` (0x44), ``FNR``
    (0x48), ``DADDR`` (0x4C), ``BTABLE`` (0x50).

``Packet memory (PMA)`` at 0x40006000
    512 bytes of dedicated buffer SRAM. On this part the CPU sees it as
    **16-bit halfwords in 32-bit slots**, so PMA byte offset ``n`` is at CPU
    address ``0x40006000 + n*2``. Getting that stride wrong silently halves or
    doubles every buffer address, and the firmware then parses descriptors out
    of the wrong place -- which reads as a protocol bug, not an addressing one
    (playbook trap 80). ``HAL_PLANCK_PMA_SCHEME=1x16`` switches to the flat
    layout used by the F0/F303xD-E parts, and the model logs the observed
    buffer-descriptor stride so the choice is checkable rather than assumed.

THE ENDPOINT REGISTERS ARE NOT ORDINARY STORAGE, and this is where a naive model
breaks. Each ``EPnR`` mixes three kinds of bit:

  * **toggle** bits -- ``STAT_TX`` (5:4), ``STAT_RX`` (13:12), ``DTOG_TX`` (6),
    ``DTOG_RX`` (14). A write does not set them, it **XORs** them.
  * **write-0-to-clear** bits -- ``CTR_TX`` (7), ``CTR_RX`` (15). Writing 1
    leaves them alone; only a 0 clears them.
  * plain read/write bits -- endpoint type, kind and address.

So the firmware's idiom is a read-modify-write with the toggle bits masked, and
a model that simply stores the written word reports endpoint states the firmware
never asked for.

THE PAGE IS SHARED. A peripheral region must be a 4 kB-aligned multiple of 4 kB
(playbook trap 61), and 0x40005400 in the same page is I2C1, which this board
does not use. Only the USB offsets are served here; every other offset in the
page falls back to the catch-all, so it keeps the busy-wait breaker and its MMIO
recording rather than silently becoming plain storage (playbook trap 61).

THE PACKET-MEMORY STRIDE IS FAMILY-SPECIFIC AND FAILS SILENTLY. The STM32F303xB/C
(this part) uses the F1's "halfwords in 32-bit slots" layout, while the F0/L0 and
the F303xD/E use a flat one; ChibiOS picks between them with
``STM32_USB_ACCESS_SCHEME_2x16`` (playbook traps 190 / 2.144). Get it wrong and
every buffer address is halved or doubled, and the firmware parses descriptors
out of the wrong place -- which reads as a protocol bug and is an addressing one.
``HAL_PLANCK_PMA_SCHEME=1x16`` switches, so the choice is checkable.
"""
from __future__ import annotations

import os
import struct
import threading
from typing import Any, Dict, List, Optional

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

# --- register offsets within the 0x40005000 page ---------------------------
USB_BASE_IN_PAGE = 0xC00          # 0x40005C00
USB_LIMIT_IN_PAGE = USB_BASE_IN_PAGE + 0x60

EP0R = 0x00
CNTR, ISTR, FNR, DADDR, BTABLE = 0x40, 0x44, 0x48, 0x4C, 0x50
N_ENDPOINTS = 8

# EPnR bit fields (RM0316 §30.6.2)
EP_CTR_RX = 1 << 15
EP_DTOG_RX = 1 << 14
EP_STAT_RX = 0x3 << 12
EP_SETUP = 1 << 11
EP_TYPE = 0x3 << 9
EP_KIND = 1 << 8
EP_CTR_TX = 1 << 7
EP_DTOG_TX = 1 << 6
EP_STAT_TX = 0x3 << 4
EP_EA = 0x0F

#: Bits a write XORs rather than assigns.
EP_TOGGLE_MASK = EP_STAT_RX | EP_DTOG_RX | EP_STAT_TX | EP_DTOG_TX
#: Bits a write clears only when written as 0.
EP_W0C_MASK = EP_CTR_RX | EP_CTR_TX
#: Everything else is plain read/write.
EP_RW_MASK = EP_TYPE | EP_KIND | EP_EA

STAT_DISABLED, STAT_STALL, STAT_NAK, STAT_VALID = 0, 1, 2, 3

CNTR_FRES = 1 << 0
CNTR_PDWN = 1 << 1

ISTR_CTR = 1 << 15
ISTR_RESET = 1 << 10
ISTR_SOF = 1 << 9
ISTR_ESOF = 1 << 8
ISTR_EP_ID = 0x0F
ISTR_DIR = 1 << 4

CNTR_SOFM = 1 << 9

PMA_SIZE = 512

_REGS: Optional["Stm32f3UsbRegs"] = None
_PMA: Optional["Stm32f3UsbPma"] = None


def get_usb() -> Optional["Stm32f3UsbRegs"]:
    """The live USB register model (the host-side driver talks to it)."""
    return _REGS


def get_pma() -> Optional["Stm32f3UsbPma"]:
    return _PMA


class Stm32f3UsbPma(SocCatchAll):
    """USB packet memory: 512 bytes seen as halfwords in 32-bit slots.

    The doubling is the whole subtlety. A buffer descriptor holds a PMA *byte*
    offset; the CPU reaches that byte at ``0x40006000 + offset*2``. Both views
    are needed -- the firmware writes through the CPU view, the modelled host
    reads through the flat view -- so this keeps one flat 512-byte array and
    translates on every access.
    """

    #: "2x16" = halfwords in 32-bit slots (F1/F303xB-C). "1x16" = flat
    #: halfwords (F0/F303xD-E).
    SCHEME = os.environ.get("HAL_PLANCK_PMA_SCHEME", "2x16")

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.mem = bytearray(PMA_SIZE)
        self._lock = threading.RLock()
        self._stride_reported = False
        global _PMA
        _PMA = self
        log.info("Stm32f3UsbPma: %d bytes of packet memory at 0x%08x "
                 "(access scheme %s)", PMA_SIZE, address, self.SCHEME)

    # -- flat view, for the modelled host ----------------------------------
    def read_flat(self, offset: int, length: int) -> bytes:
        with self._lock:
            return bytes(self.mem[offset:offset + length])

    def write_flat(self, offset: int, data: bytes) -> None:
        with self._lock:
            self.mem[offset:offset + len(data)] = data

    # -- CPU view -----------------------------------------------------------
    def _flat(self, offset: int) -> int:
        if self.SCHEME == "1x16":
            return (offset // 2) * 2
        return (offset // 4) * 2              # 32-bit slot -> byte pair

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        flat = self._flat(offset)
        if flat + 1 >= PMA_SIZE:
            return 0
        with self._lock:
            return struct.unpack_from("<H", self.mem, flat)[0]

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        flat = self._flat(offset)
        if flat + 1 >= PMA_SIZE:
            return True
        with self._lock:
            struct.pack_into("<H", self.mem, flat, value & 0xFFFF)
        return True


class Stm32f3UsbRegs(SocCatchAll):
    """The USB control/endpoint registers, with correct toggle semantics.

    Also the router for the shared 0x40005000 page (see the module docstring).
    """

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.base = address
        self.regs: Dict[int, int] = {}         # USB registers
        self.epr: List[int] = [0] * N_ENDPOINTS
        self.istr = 0
        self.enabled = False
        self.resets = 0
        self.sofs = 0
        self._lock = threading.RLock()
        self._trace = os.environ.get("HAL_PLANCK_USB_TRACE") == "1"
        global _REGS
        _REGS = self
        log.info("Stm32f3UsbRegs: modelling the USB device peripheral at "
                 "0x%08x (the F1-style block, not an OTG core)",
                 address + USB_BASE_IN_PAGE)

    # -- interface for the modelled host -----------------------------------
    def btable(self) -> int:
        with self._lock:
            return self.regs.get(BTABLE, 0) & 0xFFF8

    def daddr(self) -> int:
        with self._lock:
            return self.regs.get(DADDR, 0) & 0x7F

    def daddr_enabled(self) -> bool:
        """DADDR.EF -- the firmware has enabled the USB function."""
        with self._lock:
            return bool(self.regs.get(DADDR, 0) & 0x80)

    def ep_stat_rx(self, ep: int) -> int:
        return (self.epr[ep] & EP_STAT_RX) >> 12

    def ep_stat_tx(self, ep: int) -> int:
        return (self.epr[ep] & EP_STAT_TX) >> 4

    def raise_ctr_rx(self, ep: int, setup: bool = False) -> None:
        """Signal 'a packet arrived on this endpoint' the way the silicon does."""
        with self._lock:
            self.epr[ep] |= EP_CTR_RX
            if setup:
                self.epr[ep] |= EP_SETUP
            else:
                self.epr[ep] &= ~EP_SETUP
            # Receiving a packet leaves the endpoint NAK until the firmware
            # re-arms it, exactly as the hardware does.
            self.epr[ep] = (self.epr[ep] & ~EP_STAT_RX) | (STAT_NAK << 12)

    def raise_ctr_tx(self, ep: int) -> None:
        with self._lock:
            self.epr[ep] |= EP_CTR_TX
            self.epr[ep] = (self.epr[ep] & ~EP_STAT_TX) | (STAT_NAK << 4)

    def raise_reset(self) -> None:
        with self._lock:
            self.istr |= ISTR_RESET
            self.resets += 1

    def raise_sof(self) -> bool:
        """Latch a Start-Of-Frame. Returns True if the firmware wants the IRQ.

        A USB host emits a SOF token every millisecond, and that tick is **load
        bearing**, not decoration. ChibiOS' serial-over-USB driver writes into
        an *output buffered queue* and only hands a buffer to the endpoint when
        it is FULL; a partially-filled one is flushed by ``sduSOFHookI()``,
        which the board's SOF callback calls. So without SOF the firmware
        composes its whole reply, buffers it, and sits on it -- the shell
        banner (21 bytes into a 64-byte buffer) never leaves the device.

        Measured: ``EP1R = 0x3021`` -- the OUT endpoint armed and VALID, the IN
        endpoint NAK -- for the entire run, which reads exactly like firmware
        that has decided not to answer. It is the same class of failure as
        playbook trap 70 (a reply that only moves when the next input arrives),
        one layer up: here nothing moves it at all.
        """
        with self._lock:
            self.istr |= ISTR_SOF
            self.sofs += 1
            return bool(self.regs.get(CNTR, 0) & CNTR_SOFM)

    def _istr_value(self) -> int:
        """ISTR as the silicon computes it.

        ``ISTR.CTR`` (15), ``EP_ID`` (3:0) and ``DIR`` (4) are **read-only**:
        the hardware derives them from the endpoint registers every time the
        register is read, and the firmware clears the condition by clearing
        ``CTR_RX``/``CTR_TX`` in ``EPnR`` -- *not* by writing ISTR.

        Latching CTR instead (the obvious "set a bit when a packet arrives"
        model) deadlocks ChibiOS' ISR, which is literally::

            while ((istr = STM32_USB->ISTR) & ISTR_CTR) { ...serve EP... }

        so a CTR bit that survives the endpoint being serviced makes that loop
        run for ever, and the device answers no SETUP at all -- which reads as
        a firmware that has decided not to enumerate. Only RESET/SOF/ESOF and
        the error bits are latched, and those really are write-0-to-clear.
        """
        value = self.istr
        for ep, epr in enumerate(self.epr):
            if epr & (EP_CTR_RX | EP_CTR_TX):
                value |= ISTR_CTR | (ep & ISTR_EP_ID)
                # DIR = 1 means the transaction was OUT/SETUP (CTR_RX);
                # DIR = 0 means IN (CTR_TX).  RM0316 Table: it is the
                # direction of the *successful* transaction, not a mask.
                if epr & EP_CTR_RX:
                    value |= ISTR_DIR
                break
        return value

    # -- MMIO ---------------------------------------------------------------
    @staticmethod
    def _usb_off(offset: int) -> Optional[int]:
        if USB_BASE_IN_PAGE <= offset < USB_LIMIT_IN_PAGE:
            return offset - USB_BASE_IN_PAGE
        return None

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        off = self._usb_off(offset)
        if off is None:
            return super().hw_read(offset, size, pc=pc, **kwargs)
        with self._lock:
            if off < N_ENDPOINTS * 4:
                value = self.epr[off // 4]
            elif off == ISTR:
                value = self._istr_value()
            elif off == FNR:
                value = 0
            else:
                value = self.regs.get(off, 0)
        if self._trace:
            log.info("Usb: READ  pc=0x%08x +0x%02x -> 0x%04x", pc, off, value)
        return value

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        off = self._usb_off(offset)
        if off is None:
            return super().hw_write(offset, size, value, pc=pc, **kwargs)
        value &= 0xFFFF
        with self._lock:
            if off < N_ENDPOINTS * 4:
                ep = off // 4
                cur = self.epr[ep]
                # toggle bits XOR; write-0-to-clear bits clear only on 0;
                # everything else assigns.
                new = (cur & EP_TOGGLE_MASK) ^ (value & EP_TOGGLE_MASK)
                new |= (cur & EP_W0C_MASK) & (value & EP_W0C_MASK)
                new |= value & EP_RW_MASK
                new |= value & EP_SETUP & cur     # SETUP is read-only
                self.epr[ep] = new & 0xFFFF
                if self._trace:
                    log.info("Usb: EP%dR pc=0x%08x write 0x%04x: 0x%04x -> "
                             "0x%04x (STAT_RX=%d STAT_TX=%d)", ep, pc, value,
                             cur, self.epr[ep], self.ep_stat_rx(ep),
                             self.ep_stat_tx(ep))
                return True
            if off == ISTR:
                # Only the LATCHED bits are writable, and they are
                # write-0-to-clear. CTR/EP_ID/DIR are read-only and derived.
                if self._trace:
                    log.info("Usb: ISTR  pc=0x%08x write 0x%04x: latched "
                             "0x%04x -> 0x%04x", pc, value, self.istr,
                             self.istr & value & ~(ISTR_CTR | ISTR_DIR
                                                   | ISTR_EP_ID))
                self.istr &= value & ~(ISTR_CTR | ISTR_DIR | ISTR_EP_ID)
                return True
            if off == CNTR:
                was = self.enabled
                self.enabled = not (value & (CNTR_PDWN | CNTR_FRES))
                if self.enabled and not was:
                    log.info("Usb: firmware brought the USB device out of "
                             "reset (CNTR=0x%04x) -- it is ready to enumerate",
                             value)
                self.regs[off] = value
                return True
            if off == DADDR:
                prev = self.regs.get(off, 0)
                self.regs[off] = value
                if (value & 0x7F) != (prev & 0x7F) and (value & 0x7F):
                    log.info("Usb: firmware accepted USB address %d",
                             value & 0x7F)
                if (value & 0x80) and not (prev & 0x80):
                    log.info("Usb: firmware enabled the USB function "
                             "(DADDR.EF)")
                return True
            self.regs[off] = value
        if self._trace:
            log.info("Usb: WRITE pc=0x%08x +0x%02x = 0x%04x", pc, off, value)
        return True
