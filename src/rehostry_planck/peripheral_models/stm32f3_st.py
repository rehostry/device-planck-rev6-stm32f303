# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ChibiOS' system tick on this board -- TIM3 -- and therefore the whole clock.

**ChibiOS does NOT use SysTick here.** The vector table proves it: index 15 is
still the weak ``_unhandled_exception`` stub while ``st_lld_init``'s register
sequence is linked in (playbook trap 41). Every ``chThdSleep``, every virtual
timer and every driver timeout in this firmware hangs off one interrupt.

**AND IT IS NOT THE SIBLING'S TIMER.** device-nanovna-h4 is the same SoC, the
same RTOS and the same USB block, and it ticks on **TIM2 / IRQ 28**. This image
ticks on **TIM3 / IRQ 29**, and TIM2 *is also live here* -- QMK drives it as a
PWM -- so the obvious guard ("is IRQ 28's vector the weak stub?") answers NO
for the wrong timer and a copied number injects into a real, unrelated handler
with nothing looking wrong. That mistake was made on this device's first boot
and is exactly playbook trap 141. The base, the width and the interrupt line
are therefore **derived from the image** by ``tools/extract_firmware.py``
(``system_timer:`` in ``planck_facts.yaml``) and loaded here:

    st_lld_get_counter():   ldr r3,=0x40000400 ; ldr r0,[r3,#0x24] ; uxth r0,r0
                                                                     ^^^^ 16-bit
    st_lld_start_alarm(t):  CCR1 = t ; SR = 0 ; DIER = CC1IE
    vector[16+29] -> 0x0800A191 -> st_lld_serve_interrupt (0x0800A164)

**THE COUNTER IS 16-BIT.** TIM3 on an STM32F3 is 16 bits wide, and the
firmware's own accessor says so with that ``uxth``. A 32-bit counter mask on a
16-bit timer makes every deadline compare wrap late and the kernel's arithmetic
silently wrong (playbook trap 141 step 5).

A free-running counter is not a clock -- what makes the kernel move is the
capture/compare interrupt (playbook trap 89). Modelling ``CNT`` so it advances
looks like it should be enough (the firmware reads plausible timestamps and
computes correct deltas) and nothing happens: no ``chThdSleep`` ever returns.

FOUR INVARIANTS (playbook trap 66), each of which breaks differently:

1. **A read must not advance the counter.** Otherwise the kernel re-arms
   "now + delta" for ever and the deadline recedes as fast as it is chased.
2. **It must never move backwards**, or the delta list walks a NULL.
3. **The compare fires ONCE per arming, from ONE place** -- never on a
   status-register read. Code that merely inspects ``SR`` would otherwise
   consume the pending compare and no interrupt is ever injected.
4. The counter is advanced by the **idle seam** (``bp_handlers/irq_pump.py``),
   i.e. only when the guest has told us it has nothing to do.

THE DEADLINE IS ANCHORED, NOT COMPARED MODULO (playbook trap 101). ``CCR1`` is
an absolute 32-bit time on a wrapping counter, so ``cnt >= CCR1`` fires every
armed alarm at once on each wrap, and "is the counter a short distance past
CCR1" cannot tell "just passed" from "almost a whole wrap away". Instead the
counter is recorded at the moment of arming and the alarm fires once that much
has *elapsed* -- unambiguous over any span, and it matches how the driver thinks
(``st_lld_start_alarm`` is called with a ``now`` it has just read).
"""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, Optional

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

# STM32 general-purpose timer register offsets (RM0316 §21.4).
CR1, CR2, SMCR, DIER, SR, EGR = 0x00, 0x04, 0x08, 0x0C, 0x10, 0x14
CCMR1, CCMR2, CCER, CNT, PSC, ARR, RCR, CCR1 = (0x18, 0x1C, 0x20, 0x24,
                                                0x28, 0x2C, 0x30, 0x34)

CR1_CEN = 1 << 0
DIER_CC1IE = 1 << 1
SR_UIF = 1 << 0
SR_CC1IF = 1 << 1
EGR_UG = 1 << 0

#: The 4 kB page at 0x40000000 holds TIM2 (+0x000), TIM3 (+0x400) and TIM4
#: (+0x800); a peripheral region must be a 4 kB-aligned multiple of 4 kB
#: (playbook trap 61), so this model necessarily covers all three. It owns only
#: the ONE the firmware ticks on -- the offset is derived, not assumed -- and
#: delegates the other two back to the catch-all, because a page silently
#: turned into plain storage is worse than the catch-all.
TIMER_BLOCK = 0x400

#: ChibiOS' system-tick frequency, DERIVED from the prescaler the firmware
#: itself programs (72 MHz / (PSC + 1)) rather than assumed -- see
#: :meth:`Stm32f3SystemTimer.frequency`. This is only the fallback used before
#: the firmware has written PSC.
ST_FREQUENCY = 100000

#: The PLL output this board runs at (HSE 8 MHz x 9), used only to turn the
#: firmware's own TIM2 prescaler into a tick rate for display.
SYSCLK_HZ = 72000000

_TIMER: Optional["Stm32f3SystemTimer"] = None


def get_timer() -> Optional["Stm32f3SystemTimer"]:
    """The live TIM2 model (the interrupt pump drives and drains it)."""
    return _TIMER


class Stm32f3SystemTimer(SocCatchAll):
    """TIM2 as a monotonic free-running counter with a one-shot CC1 compare."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        from .. import facts
        st = facts.load()["system_timer"]
        #: Offset of the tick timer inside this 4 kB page, and its width.
        self.st_offset: int = st["base"] - address
        self.bits: int = st["bits"]
        self.mask: int = (1 << self.bits) - 1
        self.irq: int = st["irq"]
        self.regs: Dict[int, int] = {}
        self.cnt = 0
        #: A monotonic total that does NOT wrap. `cnt` is the register the
        #: firmware sees and it is only 16 bits wide, so it wraps every
        #: 6.55 s at this build's 10 kHz -- reporting `cnt / frequency` as
        #: "guest uptime" would sawtooth and read like the clock going
        #: backwards. The firmware never sees this one.
        self.total = 0
        self.sr = 0
        self.running = False
        self.armed = False
        self.arm_cnt = 0
        self.arm_delta = 0
        self.elapsed_since_arm = 0
        self.fires = 0
        self.pending_irq = False
        self._lock = threading.RLock()
        self._trace = os.environ.get("HAL_PLANCK_TIM_TRACE") == "1"
        global _TIMER
        _TIMER = self
        log.info("Stm32f3SystemTimer: ChibiOS' system tick is the timer at "
                 "0x%08x (page 0x%08x + 0x%03x), %d-bit counter, IRQ %d -- "
                 "DERIVED from the image, not copied from the sibling F303 "
                 "device, which ticks on TIM2/IRQ 28",
                 st["base"], address, self.st_offset, self.bits, self.irq)

    # -- driven by the interrupt pump ---------------------------------------
    def advance(self, ticks: int) -> None:
        """Move guest time forward. Monotonic, and never called from a read."""
        if ticks <= 0:
            return
        with self._lock:
            if not self.running:
                return
            self.cnt = (self.cnt + ticks) & self.mask
            self.total += ticks
            if not self.armed:
                return
            self.elapsed_since_arm += ticks
            if self.elapsed_since_arm >= self.arm_delta:
                self.armed = False               # ONE-SHOT (playbook trap 128)
                self.sr |= SR_CC1IF
                self.fires += 1
                if self.regs.get(DIER, 0) & DIER_CC1IE:
                    self.pending_irq = True
                if self._trace or self.fires in (1, 10, 100):
                    log.info("Stm32f3SystemTimer: CC1 compare #%d fired "
                             "(cnt=0x%08x ccr1=0x%08x)", self.fires, self.cnt,
                             self.regs.get(CCR1, 0))

    def mmio_tick(self, ticks: int = 1) -> None:
        """Advance from peripheral activity, for waits that never reach idle.

        An MMIO access is evidence that the guest is executing; a thread that
        polls a status register instead of blocking would otherwise stop time
        for the whole device (playbook trap 77).
        """
        self.advance(ticks)

    def take_pending_irq(self) -> bool:
        with self._lock:
            if self.pending_irq:
                self.pending_irq = False
                return True
            return False

    def frequency(self) -> int:
        """The tick rate the FIRMWARE chose: 72 MHz / (PSC + 1).

        Reading it back out of the register the firmware programmed, rather
        than hardcoding a number from a header, means a rebuild that changes
        ``CH_CFG_ST_FREQUENCY`` changes the reported clock too instead of
        silently mis-scaling every timestamp this device prints.
        """
        psc = self.regs.get(PSC, 0)
        return int(SYSCLK_HZ // (psc + 1)) if psc else ST_FREQUENCY

    def seconds(self) -> float:
        """Guest uptime, from the non-wrapping total. Monotonic, and it only
        advances when the guest executes -- explicitly NOT calibrated to wall
        time (PROVENANCE.md §5.1)."""
        return self.total / float(self.frequency())

    # -- MMIO ---------------------------------------------------------------
    def _arm(self) -> None:
        """(Re)anchor the compare against the counter value right now."""
        ccr1 = self.regs.get(CCR1, 0) & self.mask
        delta = (ccr1 - self.cnt) & self.mask
        if delta > (self.mask >> 1):
            delta = 0                            # the deadline is already past
        self.armed = True
        self.arm_cnt = self.cnt
        self.arm_delta = delta
        self.elapsed_since_arm = 0

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if not self.st_offset <= offset < self.st_offset + TIMER_BLOCK:
            return super().hw_read(offset, size, pc=pc, **kwargs)
        word = (offset - self.st_offset) & ~0x3
        with self._lock:
            if word == CNT:
                # Reading the counter MUST NOT advance it (invariant 1).
                return self.cnt
            if word == SR:
                # Reading the status MUST NOT consume the pending compare
                # (invariant 3): the injection is the pump's job alone.
                return self.sr
            return self.regs.get(word, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        if not self.st_offset <= offset < self.st_offset + TIMER_BLOCK:
            return super().hw_write(offset, size, value, pc=pc, **kwargs)
        word = (offset - self.st_offset) & ~0x3
        value &= 0xFFFFFFFF
        with self._lock:
            if word == SR:
                # STM32 timer status bits are write-ZERO-to-clear; ChibiOS'
                # handler does `TIM2->SR = 0`. Storing the written value would
                # make the flag immortal (playbook trap 67).
                self.sr &= value
                return True
            if word == CNT:
                self.cnt = value & self.mask
                return True
            if word == EGR:
                if value & EGR_UG:
                    self.cnt = 0                 # UG reloads the counter
                return True
            self.regs[word] = value
            if word == CR1:
                was = self.running
                self.running = bool(value & CR1_CEN)
                if self.running and not was:
                    log.info("Stm32f3SystemTimer: firmware started the tick timer "
                             "(CR1=0x%08x, PSC=%d, ARR=0x%08x) -- ChibiOS' "
                             "clock is now running", value,
                             self.regs.get(PSC, 0), self.regs.get(ARR, 0))
            elif word == CCR1:
                self._arm()
                if self._trace:
                    log.info("Stm32f3SystemTimer: alarm armed at 0x%08x "
                             "(cnt=0x%08x, +%d ticks) pc=0x%08x", value,
                             self.cnt, self.arm_delta, pc)
            elif word == DIER:
                if value & DIER_CC1IE:
                    if not self.armed:
                        self._arm()
                else:
                    self.armed = False           # st_lld_stop_alarm
        return True
