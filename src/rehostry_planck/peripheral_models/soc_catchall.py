# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SoC catch-all that does NOT disable `svc` handling.

Identical behaviour to `halucinator.peripheral_models.auto_model.AutoPeripheral`
-- it is a straight subclass -- but under a **different class name**, and that is
the entire point.

The core sets ``backend.skip_svc = True`` for any peripheral class whose
``__name__`` is exactly ``AutoPeripheral`` (playbook trap 11), which makes an
``svc`` instruction be advanced past instead of vectored to SVCall.

That would be fatal here. **ChibiOS' ARMv7-M port switches context with
`svc 0`**: this image's SVCall vector (index 11) is a real handler at
0x08000959, distinct from the `_unhandled_exception` stub every unused vector
points at. A stock ``AutoPeripheral`` anywhere in the config would make every
context switch fall through silently, and the kernel would look like it simply
never schedules.

DIAGNOSTICS
-----------

``HAL_PLANCK_READ_TRACE=1`` logs every distinct ``(pc, address)`` read pair once.
On a stripped image the PC histogram says *where* the firmware is spinning but
not *what* it is waiting for; this names the register the hot instruction reads.
Deduped, so a loop running millions of times still produces one line.

``HAL_PLANCK_WRITE_TRACE=1`` does the same for writes -- which is how an
unmodelled peripheral's base address gets identified, since a catch-all hides a
wrong base perfectly (playbook trap 137).
"""
from __future__ import annotations

import os
from typing import Any, Set, Tuple

from halucinator.peripheral_models.auto_model import AutoPeripheral
from halucinator import hal_log

log = hal_log.getHalLogger()

_READ_TRACE = os.environ.get("HAL_PLANCK_READ_TRACE") == "1"
_WRITE_TRACE = os.environ.get("HAL_PLANCK_WRITE_TRACE") == "1"
_seen_r: Set[Tuple[int, int]] = set()
_seen_w: Set[Tuple[int, int]] = set()


class SocCatchAll(AutoPeripheral):
    """AutoPeripheral behaviour, without tripping the core's `skip_svc` check."""

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        value = super().hw_read(offset, size, pc=pc, **kwargs)
        if _READ_TRACE:
            key = (pc, self.address + offset)
            if key not in _seen_r:
                _seen_r.add(key)
                log.info("SocCatchAll: READ  pc=0x%08x addr=0x%08x -> 0x%08x",
                         pc, self.address + offset, value)
        return value

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        if _WRITE_TRACE:
            key = (pc, self.address + offset)
            if key not in _seen_w:
                _seen_w.add(key)
                log.info("SocCatchAll: WRITE pc=0x%08x addr=0x%08x <- 0x%08x",
                         pc, self.address + offset, value)
        return super().hw_write(offset, size, value, pc=pc, **kwargs)
