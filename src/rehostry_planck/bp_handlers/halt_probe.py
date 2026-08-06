# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Name the reason the kernel stopped, instead of letting it be an anonymous hang.

ChibiOS' failure modes are all the same two bytes -- ``b .`` -- and from outside
they are indistinguishable from each other, from the idle thread, and from a
firmware that is merely slow. This image has **seven** such self-loops besides
the idle thread:

* the ARMv7-M port's stack-overflow panic, three inlined copies of
  ``ch.dbg.panic_msg = "stack overflow"; cpsid i; b .``;
* ``_unhandled_exception`` -- the weak stub every unused vector points at, so
  reaching it means an exception was taken that the firmware never wired up;
* ``__default_exit`` -- ``main()`` returned;
* the trap after ``_port_thread_start``'s ``blx r4``, i.e. a thread function
  returned;
* one further halt.

Landing on any of them is a *result*, and a valuable one. This handler logs the
address, the PC that reached it, ``LR``, and -- where the site is a ChibiOS
panic -- reads ``ch.dbg.panic_msg`` straight back out of guest memory and prints
the string (playbook trap 67: a four-line handler turns 168 million iterations
of one address into ``chSysHalt('Unsupported width')``).

It logs **once per address** and then gets out of the way, so a site that is
somehow reached legitimately does not flood the log.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler
from halucinator import hal_log

log = hal_log.getHalLogger()

#: ChibiOS' system structure in this image (`ch`), recovered from `chSysHalt`
#: itself -- the function is six instructions and stores its `reason` argument
#: straight into `ch.dbg.panic_msg`:
#:
#:     08007d74:  cpsid i
#:                ldr   r3, =0x200021A8      ; &ch
#:                str.w r0, [r3, #0x88]      ; ch.dbg.panic_msg = reason
#:                ldr   r3, =0x20002198
#:                movs  r2, #3
#:                strb  r2, [r3, #0]         ; ch.state = HALTED
#:                b     .
CH_SYSTEM = 0x200021A8
CH_PANIC_MSG = CH_SYSTEM + 0x88

#: Flash bounds, so a recovered pointer is sanity-checked before it is chased.
FLASH_LO, FLASH_HI = 0x08000000, 0x0800F140


class HaltProbe(BPHandler):
    """Logs, once per site, why the firmware came to a stop."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.seen: Dict[int, int] = {}
        self.qemu = None

    def register_handler(self, qemu, addr, func_name, **kwargs):  # noqa: ANN001
        self.qemu = qemu
        return super().register_handler(qemu, addr, func_name, **kwargs)

    def _panic_msg(self, qemu) -> Optional[str]:  # noqa: ANN001
        try:
            raw = qemu.read_memory(CH_PANIC_MSG, 4, 1)
            ptr = raw if isinstance(raw, int) else int(raw)
        except Exception:                      # noqa: BLE001 -- diagnostic only
            return None
        if not FLASH_LO <= ptr < FLASH_HI:
            return None
        try:
            data = qemu.read_memory(ptr, 1, 64)
        except Exception:                      # noqa: BLE001
            return None
        if isinstance(data, int):
            return None
        text = bytes(data).split(b"\x00", 1)[0]
        try:
            return text.decode("ascii")
        except UnicodeDecodeError:
            return None

    @bp_handler(["halt_probe"])
    def halt(self, qemu, bp_addr) -> Tuple[bool, Optional[int]]:  # noqa: ANN001
        self.seen[bp_addr] = self.seen.get(bp_addr, 0) + 1
        if self.seen[bp_addr] != 1:
            return False, None
        try:
            lr = qemu.read_register("lr")
        except Exception:                      # noqa: BLE001
            lr = 0
        msg = self._panic_msg(qemu)
        if msg:
            log.error("HaltProbe: the firmware STOPPED at 0x%08x -- ChibiOS "
                      "panic: %r  (lr=0x%08x)", bp_addr, msg, lr)
        else:
            log.error("HaltProbe: the firmware STOPPED at 0x%08x (a ChibiOS "
                      "halt self-loop; no panic message stored)  lr=0x%08x",
                      bp_addr, lr)
        return False, None
