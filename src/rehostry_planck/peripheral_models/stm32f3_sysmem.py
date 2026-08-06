# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The STM32F3 system/OTP page: the die's flash-size register and unique ID.

A MAPPED-BUT-EMPTY REGION IS WORSE THAN AN UNMAPPED ONE (playbook trap 216).
Mapping ``0x1FFFF000`` as plain read-only memory is the careful-looking thing to
do, and it makes the **flash-size register** read **0** -- a lie the firmware
acts on somewhere else entirely.

Measured on the first boot of this device, with the page mapped as memory:

    8004a20:  ldr   r3, =0x1FFFF000
              ldr.w r3, [r3, #0x7CC]        ; FLASH_SIZE, in kilobytes
              and.w r5, r5, r3, lsl #10     ; -> flash size in BYTES  == 0
              ...
    8004a66:  ldr   r0, ="No sector in available flash range"
    8004a68:  bl    chSysHalt

QMK's wear-levelling EEPROM backend sizes its flash region from that register,
concluded the part has zero flash, and halted the kernel -- from a code path
with nothing to do with the register it had read, and with the only visible
symptom being a `b .` at ``0x08007D82``. Answering the part's real capacity
(STM32F303**CC** = 256 KB) is two lines.

THE UNIQUE ID IS SYNTHETIC AND SAYS SO. The 96-bit device id at ``0x1FFFF7AC``
is not in the firmware image and cannot be recovered from one (playbook trap
80). This firmware reads it to build its USB **serial-number** string descriptor
(``0x080075BC``), so the digits a host sees are firmware-computed from a value
*this rehost chose*: they prove the firmware's formatter ran, they do not
identify a real die. The constant below is fixed, documented and obviously
synthetic -- zeroes would read like a failed access rather than a chosen value,
so it is not zeroes. PROVENANCE.md §5.1 states this, and no byte-exact
prediction in this repository depends on it.

Everything else in the page is option bytes and system flash, which read as
erased (``0xFF``) on a part that has never had them programmed.
"""
from __future__ import annotations

import struct
from typing import Any

from halucinator.peripheral_models.generic import GenericPeripheral
from halucinator import hal_log

log = hal_log.getHalLogger()

#: Offsets within the 0x1FFFF000 page (RM0316 §31.1, §33.1).
UID_OFF = 0x7AC          # 96-bit unique device id
FLASH_SIZE_OFF = 0x7CC   # flash size in kB, 16-bit

#: STM32F303**CC**: 256 KB of flash. The suffix is the capacity code, and the
#: Planck rev6 ships the CCT6.
FLASH_SIZE_KB = 256

#: A fixed, documented, OBVIOUSLY SYNTHETIC 96-bit id. "REHOSTRY" in ASCII
#: followed by a marker, so anything derived from it is recognisable on sight
#: as a rehost's value rather than a real die's.
SYNTHETIC_UID = b"REHOSTRY-PLANCK\x00"[:12]


class Stm32f3SysMem(GenericPeripheral):
    """Serves the flash-size register, the unique id, and erased option bytes."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.uid_reads = 0
        self.flash_size_reads = 0
        log.info("Stm32f3SysMem: system/OTP page at 0x%08x -- FLASH_SIZE "
                 "(+0x%03X) answers %d kB; the 96-bit unique id (+0x%03X) is a "
                 "fixed SYNTHETIC value (%r), not a real die's",
                 address, FLASH_SIZE_OFF, FLASH_SIZE_KB, UID_OFF,
                 SYNTHETIC_UID)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        if UID_OFF <= offset < UID_OFF + 12:
            self.uid_reads += 1
            if self.uid_reads == 1:
                log.info("Stm32f3SysMem: the firmware is reading the unique "
                         "device id (pc=0x%08x) -- it builds its USB serial "
                         "string descriptor from it; the value is synthetic",
                         pc)
            raw = (SYNTHETIC_UID + b"\x00" * 4)[offset - UID_OFF:
                                                offset - UID_OFF + 4]
            return struct.unpack("<I", raw)[0] & ((1 << (8 * size)) - 1)
        if FLASH_SIZE_OFF <= offset < FLASH_SIZE_OFF + 2:
            self.flash_size_reads += 1
            if self.flash_size_reads == 1:
                log.info("Stm32f3SysMem: the firmware read FLASH_SIZE "
                         "(pc=0x%08x) -> %d kB. Answering 0 here halts QMK's "
                         "wear-levelling backend with 'No sector in available "
                         "flash range' (playbook trap 216).", pc,
                         FLASH_SIZE_KB)
            value = FLASH_SIZE_KB >> (8 * (offset - FLASH_SIZE_OFF))
            return value & ((1 << (8 * size)) - 1)
        # System flash / option bytes on a part that has never been programmed.
        return (1 << (8 * size)) - 1

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        log.info("Stm32f3SysMem: IGNORING a write of 0x%x to +0x%03X "
                 "(pc=0x%08x) -- this page is read-only on silicon",
                 value, offset, pc)
        return True
