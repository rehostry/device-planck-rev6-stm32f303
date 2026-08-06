# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Advance guest time and deliver interrupts -- from TWO places, one deliverer.

THE IDLE SEAM IS CORRECT AND, ON THIS FIRMWARE, NOT ENOUGH.

ChibiOS' ``_idle_thread`` is compiled here with ``CORTEX_ENABLE_WFI_IDLE``
**TRUE**, so it is four bytes::

    08008208:  bf30   wfi
    0800820a:  e7fd   b  0x08008208

That is the kernel *stating* that it has nothing runnable and nothing to do
until an exception arrives -- the best place there is to deliver a tick, because
it cannot fire at a moment the firmware is not expecting one (playbook trap
121). unicorn treats ``wfi`` as a no-op, so without a pump the loop spins at
100 % CPU with no fault, no MMIO and nothing in any log.

**But QMK's protocol task never blocks.** ``main()`` is
``while (true) { protocol_task(); housekeeping_task(); }`` and ``matrix_task()``
rescans the whole 6x8 matrix every pass, so from the moment the keyboard
finishes initialising the CPU **never idles again** -- and an idle-only pump
goes permanently deaf exactly when the device starts working (playbook trap
192). Measured here: enumeration completed, all nine descriptors were
transmitted, and then nothing ever moved again. Guest time therefore has to be
advanced by something that ticks whenever the *guest* is executing (playbook
traps 77 / 145), and the hottest such thing on a keyboard is the matrix scan's
own GPIO reads.

So there are two entry points and **exactly one deliverer** (playbook traps 74 /
75): both call :func:`service`, and only :func:`_raise` ever raises a line.

HOW EACH ENTRY POINT RAISES IT MATTERS
--------------------------------------

* From the **bp_handler** (the idle seam) the dispatch thread is between
  instructions, so ``qemu.inject_irq()`` is safe.
* From the **MMIO callback** it is not: ``inject_irq`` calls ``emu_stop()``,
  which abandons the store the callback is inside (playbook trap 99). A bare
  ``list.append`` onto the backend's own ``_pending_irqs`` *is* safe -- and it
  only drains at an instruction-chunk boundary, so ``HAL_IRQ_CHUNK`` must be
  set or the drain point is never reached at all, because ``irq_chunk``
  defaults to **0** on ``cortex-m`` (playbook traps 50 / 152). ``spawn.py``
  sets it.

THREE GUARDS BEFORE ANY DELIVERY, each of which has cost a fleet device a
bring-up:

* ``IPSR != 0`` -- never stack an exception on a handler that has not yet run
  an instruction (playbook trap 98). Read it from unicorn directly:
  HALucinator's register map has no ``"ipsr"``, and the natural ``"cpsr"``
  fallback carries A-profile mode bits and reads non-zero in ordinary thread
  mode, so a pump using it concludes it is *permanently* inside a handler and
  delivers nothing, for ever, with no fault (playbook trap 185).
* ``PRIMASK``/``BASEPRI`` set -- ChibiOS raises BASEPRI across every ready-list
  and virtual-timer edit, and injecting there corrupts the ready list into a
  cycle the kernel then walks for ever (playbook trap 218).
* the queue must be empty -- two entries in it is a *nested* exception, not two
  interrupts (playbook trap 98).

USB IS ON THE **REMAPPED** LINE. This build wires IRQ **75** (``USB_LP`` after
the SYSCFG remap), not the classic IRQ 20 ``USB_LP_CAN_RX0`` a datasheet points
at; IRQ 19 and 20 are both the weak stub in this image, and the extractor
asserts it. The system-tick line is **derived** from the image and read off the
live timer model, because the sibling STM32F303/ChibiOS device ticks on IRQ 28
and this one on IRQ 29 (playbook trap 141).
"""
from __future__ import annotations

import os
from typing import Any, Optional, Tuple

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler
from halucinator import hal_log

from ..peripheral_models import stm32f3_st as st_mod

log = hal_log.getHalLogger()

#: The USB low-priority line, after the SYSCFG remap this build uses.
USB_LP_IRQ = 75

#: Tick-timer counts added per pump beat. Too few and an emulated second takes
#: hours; too many and periodic work runs before the code that initialises what
#: it operates on (playbook trap 124).
TICKS_PER_BEAT = int(os.environ.get("HAL_PLANCK_TICKS_PER_BEAT", "4"))

#: GPIO input reads per pump beat. The matrix scan reads six column pins per
#: row and eight rows per scan, so this is a few beats per scan.
MMIO_PER_BEAT = int(os.environ.get("HAL_PLANCK_MMIO_PER_BEAT", "8"))

#: Start-Of-Frame period, in tick-timer counts. A USB host emits one SOF per
#: millisecond, so this is DERIVED from the tick rate the firmware itself
#: programmed -- this build runs TIM3 at 72 MHz / 7200 = 10 kHz, so 1 ms is 10
#: counts, and the sibling F303 device's 100 would have been a 10 ms frame.
SOF_TICKS_OVERRIDE = os.environ.get("HAL_PLANCK_SOF_TICKS")

#: Beats between unconditional state dumps. Without one, "the pump is running
#: but nothing is armed" and "the pump is never reached" look identical.
HEARTBEAT = int(os.environ.get("HAL_PLANCK_HEARTBEAT", "400000"))

#: Diagnostic lever: the pump still advances the clock and the whole host stack
#: stays alive (the bridge binds, the client connects, every request is logged)
#: but the guest's USB line is never raised. That is the control which
#: separates "the guest computed this" from "a host model computed this" --
#: something SIGSTOP cannot do, because the models are threads inside the same
#: process (playbook traps 183 / 187).
NO_USB_IRQ = os.environ.get("HAL_PLANCK_NO_USB_IRQ") == "1"

#: The live backend, stashed by the bp_handler -- a peripheral model is never
#: handed one (playbook trap 95).
_BACKEND = None

_STATE = {"beats": 0, "ticks": 0, "usb": 0, "sof": 0, "last_sof": 0,
          "mmio": 0, "prefer_usb": True, "announced": False}


# ---------------------------------------------------------------------------
def _ipsr(qemu) -> int:  # noqa: ANN001
    """The active exception number, read from unicorn itself."""
    try:
        from unicorn import arm_const
        return qemu._uc.reg_read(arm_const.UC_ARM_REG_IPSR) & 0x1FF
    except Exception:                          # noqa: BLE001 - be conservative
        return 1                               # "assume we are in a handler"


def _masked(qemu) -> bool:  # noqa: ANN001
    """PRIMASK or BASEPRI set: the firmware is inside a critical section."""
    try:
        from unicorn import arm_const
        uc = qemu._uc
        if uc.reg_read(arm_const.UC_ARM_REG_PRIMASK) & 1:
            return True
        return bool(uc.reg_read(arm_const.UC_ARM_REG_BASEPRI) & 0xFF)
    except Exception:                          # noqa: BLE001
        return True


def _deliverable(qemu) -> bool:  # noqa: ANN001
    if qemu is None:
        return False
    if getattr(qemu, "_pending_irqs", None):
        return False                           # one outstanding delivery only
    return _ipsr(qemu) == 0 and not _masked(qemu)


def _raise(qemu, irq: int, from_bp: bool) -> None:  # noqa: ANN001
    """THE ONLY PLACE A LINE IS RAISED (playbook trap 74)."""
    if from_bp:
        qemu.inject_irq(irq)
    else:
        # From an MMIO callback a bare append is safe; `emu_stop` (which
        # inject_irq calls) is not -- it abandons the store we are inside
        # (playbook trap 99). Drained at the next instruction-chunk boundary,
        # which is why spawn.py sets HAL_IRQ_CHUNK (trap 50).
        qemu._pending_irqs.append(int(irq))


# ---------------------------------------------------------------------------
def service(qemu, from_bp: bool) -> None:  # noqa: ANN001
    """One pump beat: advance guest time, then offer at most one interrupt."""
    _STATE["beats"] += 1
    timer = st_mod.get_timer()
    if timer is None:
        return
    timer.advance(TICKS_PER_BEAT)

    if _STATE["beats"] % HEARTBEAT == 0:
        _heartbeat(timer)

    if not _deliverable(qemu):
        return

    from ..peripheral_models import stm32f3_usb as usb_mod
    from ..peripheral_models import usb_host as host_mod
    usb = usb_mod.get_usb()
    pma = usb_mod.get_pma()
    usb_ready = usb is not None and pma is not None and usb.enabled

    # Round-robin between the two lines. A fixed order starves the loser: the
    # tick's flag stays latched until its ISR runs, so once its delivery has
    # been deferred once it would win every beat (playbook trap 127).
    order = ("usb", "tick") if _STATE["prefer_usb"] else ("tick", "usb")
    _STATE["prefer_usb"] = not _STATE["prefer_usb"]

    for who in order:
        if who == "usb" and usb_ready:
            host = host_mod.get_host()
            period = (int(SOF_TICKS_OVERRIDE) if SOF_TICKS_OVERRIDE
                      else max(1, timer.frequency() // 1000))
            if ((timer.cnt - _STATE["last_sof"]) & timer.mask) >= period:
                _STATE["last_sof"] = timer.cnt
                if host.sof(usb) and not NO_USB_IRQ:
                    _raise(qemu, USB_LP_IRQ, from_bp)
                    _STATE["sof"] += 1
                    return
            if host.step(usb, pma) and host.pending_irq and not NO_USB_IRQ:
                _raise(qemu, USB_LP_IRQ, from_bp)
                _STATE["usb"] += 1
                if _STATE["usb"] in (1, 10, 100):
                    log.info("IrqPump: delivered USB IRQ %d (#%d)",
                             USB_LP_IRQ, _STATE["usb"])
                return
        elif who == "tick":
            if timer.take_pending_irq():
                _raise(qemu, timer.irq, from_bp)
                _STATE["ticks"] += 1
                if _STATE["ticks"] in (1, 10, 100) or \
                        _STATE["ticks"] % 50000 == 0:
                    log.info("IrqPump: delivered %d tick(s) on IRQ %d; guest "
                             "clock %.3f s (beats=%d)", _STATE["ticks"],
                             timer.irq, timer.seconds(), _STATE["beats"])
                return


def mmio_beat() -> None:
    """Called from the GPIO model on guest activity (playbook traps 77 / 145).

    An MMIO access is evidence that the guest is executing, so this keeps the
    clock monotonic and "only moving when the guest runs" -- explicitly not
    calibrated to wall time.
    """
    _STATE["mmio"] += 1
    if _STATE["mmio"] % MMIO_PER_BEAT:
        return
    if _BACKEND is None:
        return
    service(_BACKEND, from_bp=False)


def stats() -> dict:
    """A snapshot for the panel and the heartbeat."""
    return dict(_STATE)


def _heartbeat(timer) -> None:  # noqa: ANN001
    from ..peripheral_models import stm32f3_usb as usb_mod
    from ..peripheral_models import gpio_matrix as gpio_mod
    from ..peripheral_models import usb_host as host_mod
    log.info("IrqPump: %d beats, guest clock %.3f s (%d Hz), tick alarm %s "
             "(delta=%d elapsed=%d), ticks=%d usb=%d sof=%d",
             _STATE["beats"], timer.seconds(), timer.frequency(),
             "ARMED" if timer.armed else "idle", timer.arm_delta,
             timer.elapsed_since_arm, _STATE["ticks"], _STATE["usb"],
             _STATE["sof"])
    usb = usb_mod.get_usb()
    if usb is not None:
        log.info("IrqPump:   EPnR = %s  BTABLE=0x%04x DADDR=0x%02x",
                 " ".join("%04x" % e for e in usb.epr), usb.btable(),
                 usb.regs.get(0x4C, 0))
    host = host_mod.get_host()
    log.info("IrqPump:   host state=%s descriptors=%s reports=%d console=%r",
             host.state, ",".join(sorted(host.descriptors)),
             host.report_count, host.console_text()[-60:])
    m = gpio_mod.get_matrix()
    if m is not None:
        log.info("IrqPump:   matrix scans=%d row_selects=%d col_reads=%d "
                 "held=%s", m.scans, m.row_selects, m.col_reads, m.held())


class IrqPump(BPHandler):
    """The idle-`wfi` entry point, and the owner of the live backend handle."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.visits = 0

    def register_handler(self, qemu, addr, func_name, **kwargs):  # noqa: ANN001
        global _BACKEND
        _BACKEND = qemu
        return super().register_handler(qemu, addr, func_name, **kwargs)

    @bp_handler(["irq_pump"])
    def pump(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        self.visits += 1
        if not _STATE["announced"]:
            _STATE["announced"] = True
            log.info("IrqPump: armed at ChibiOS' idle `wfi` 0x%08x; also "
                     "beating on GPIO activity every %d input reads%s",
                     bp_addr, MMIO_PER_BEAT,
                     "  [HAL_PLANCK_NO_USB_IRQ=1: the USB line is WITHHELD]"
                     if NO_USB_IRQ else "")
        service(qemu, from_bp=True)
        return False, None
