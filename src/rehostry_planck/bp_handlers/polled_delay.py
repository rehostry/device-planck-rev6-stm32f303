# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Answer ChibiOS' ``chSysPolledDelayX`` -- it spins on a counter that cannot move.

``chSysPolledDelayX(cycles)`` is six instructions and it is a trap for every
rehost of a ChibiOS image (playbook trap 174)::

    08007dc0:  ldr  r2, =0xE0001000     ; DWT
               ldr  r1, [r2, #4]        ; DWT->CYCCNT, the reference
    L:         ldr  r3, [r2, #4]        ; DWT->CYCCNT again
               subs r3, r3, r1
               cmp  r0, r3
               bhi  L
               bx   lr

``DWT->CYCCNT`` lives in the ARMv7-M **private peripheral bus**, which the
backend maps as ordinary RW memory. It therefore never advances, the subtraction
is always 0, and the loop cannot terminate. There is no fault, no MMIO worth
reading and nothing in any log -- just one PC for ever.

**Do not fix this by modelling the PPB.** Owning `0xE0001000` means owning the
whole 1 MB region (the backend auto-maps it in one call, so a partial overlap
leaves the remainder unmapped -- playbook trap 68), and the core maintains
``SCB->ICSR``'s ``VECTACTIVE``/``RETTOBASE`` *by writing that memory*. ChibiOS'
ARMv7-M ISR epilogue skips its entire reschedule when ``RETTOBASE`` is clear, so
taking the PPB over means re-implementing that correctly for no gain (playbook
traps 56 / 217).

The routine is a ``void`` busy-wait with no side effects whatsoever, so
answering it at its own call boundary is exactly right and costs nothing else:
return ``(True, 0)`` and the framework performs the function return. It is
reached from ``usb_lld``, from QMK's ``matrix_io_delay()`` between selecting a
row and sampling the columns, and from clock bring-up -- early, and constantly.

The number of cycles asked for is accumulated so the cost is *visible* in the
log rather than silently skipped.
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler
from halucinator import hal_log

log = hal_log.getHalLogger()


class PolledDelay(BPHandler):
    """Complete `chSysPolledDelayX` immediately, and count what was skipped."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.calls = 0
        self.cycles = 0
        self._announced = False

    @bp_handler(["polled_delay"])
    def delay(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        self.calls += 1
        try:
            self.cycles += qemu.read_register("r0")
        except Exception:                       # noqa: BLE001 - diagnostic
            pass
        if not self._announced:
            self._announced = True
            log.info("PolledDelay: answering chSysPolledDelayX at 0x%08x -- it "
                     "spins on DWT->CYCCNT, which never advances under unicorn",
                     bp_addr)
        if self.calls % 200000 == 0:
            log.info("PolledDelay: %d calls, %d guest cycles skipped",
                     self.calls, self.cycles)
        # (True, value) means "I supplied the result": the framework sets
        # pc = lr, which is a real function return -- correct at a call
        # boundary, and this IS one.
        return True, 0
