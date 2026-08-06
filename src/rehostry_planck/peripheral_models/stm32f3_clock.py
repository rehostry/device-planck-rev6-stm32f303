# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""STM32F303 RCC + the flash interface -- the read-back polls the boot spins on.

ChibiOS' ``stm32_clock_init`` (0x08002574 in this image) is nine handshakes in a
row, and **every one of them is a write followed by a read-back**, which is the
exact shape the catch-all's busy-wait breaker cannot satisfy (playbook trap 40:
the breaker escalates the value it returns, so a compare against a specific
value can never succeed). Measured before this model existed: **1,376,195**
escalating reads of ``RCC_CFGR`` at one PC, no fault, nothing else in the log.

The sequence, read off the disassembly:

===============================  ==========================================
firmware writes                  then waits for
===============================  ==========================================
``CR |= HSION``                  ``CR & HSIRDY``
``CFGR.SW = 0``                  ``CFGR.SWS == 0``
``CR |= HSEON``                  ``CR & HSERDY``
``CFGR = 0x1D070400``,           (no wait)
``CFGR2 = 0x2110``, ``CFGR3 = 0x30``
``CR |= PLLON``                  ``CR & PLLRDY``
``FLASH_ACR = 0x12``             (no wait; latency 2 + prefetch)
``CFGR.SW = 2``                  ``CFGR.SWS == 2``  (PLL)
===============================  ==========================================

and then ``main()`` does the backup-domain dance, which needs ``BDCR.LSERDY``
and ``CSR.LSIRDY`` to behave the same way.

**Each RDY bit MIRRORS its own ON bit** rather than being pinned ready. Pinning
serves "spin until ready" and makes the opposite direction -- turn a PLL off and
wait for RDY to CLEAR -- unsatisfiable (playbook trap 72). Mirroring is also
simply what the silicon does, so both directions work for free.

**Reset values matter.** A register that reads 0 out of reset when the real one
does not is a lie the firmware acts on somewhere you are not looking (playbook
trap 84): the F3's ``RCC_CR`` resets to ``0x00000083`` (HSION + HSIRDY +
HSITRIM=16), and ``FLASH_OBR``/``WRPR`` report an unprotected part.
"""
from __future__ import annotations

from typing import Any, Dict

from halucinator.peripheral_models.generic import GenericPeripheral
from halucinator import hal_log

log = hal_log.getHalLogger()

# --- RCC (RM0316 §9.4) -----------------------------------------------------
RCC_CR, RCC_CFGR, RCC_CIR = 0x00, 0x04, 0x08
RCC_APB2RSTR, RCC_APB1RSTR = 0x0C, 0x10
RCC_AHBENR, RCC_APB2ENR, RCC_APB1ENR = 0x14, 0x18, 0x1C
RCC_BDCR, RCC_CSR = 0x20, 0x24
RCC_AHBRSTR, RCC_CFGR2, RCC_CFGR3 = 0x28, 0x2C, 0x30

#: (enable bit, ready bit) pairs, per register.
CR_PAIRS = ((0, 1), (16, 17), (24, 25))     # HSI/HSE/PLL ON -> RDY
BDCR_PAIRS = ((0, 1),)                      # LSEON -> LSERDY
CSR_PAIRS = ((0, 1),)                       # LSION -> LSIRDY

#: RCC_CR out of reset: HSION | HSIRDY | HSITRIM=16.
CR_RESET = 0x00000083

BDCR_BDRST = 1 << 16

#: Peripheral clock enables this device narrates, because each one is the
#: firmware's own statement that it is bringing that block up. These are the
#: M2 evidence on a firmware with no console until USB enumerates.
APB1ENR_BITS = {14: "SPI2/I2S2", 18: "USART3", 21: "I2C1", 22: "I2C2",
                23: "USB", 25: "CAN", 28: "PWR", 29: "DAC1"}
APB2ENR_BITS = {0: "SYSCFG", 11: "TIM1", 12: "SPI1", 13: "TIM8",
                14: "USART1", 16: "TIM15", 17: "TIM16", 18: "TIM17"}
AHBENR_BITS = {0: "DMA1", 2: "SRAM", 4: "FLITF", 6: "CRC", 17: "GPIOA",
               18: "GPIOB", 19: "GPIOC", 20: "GPIOD", 21: "GPIOE", 22: "GPIOF",
               24: "TSC", 28: "ADC1/2", 29: "ADC3/4"}
APB1ENR_TIMERS = {0: "TIM2", 1: "TIM3", 2: "TIM4", 4: "TIM6", 5: "TIM7",
                  11: "WWDG"}
_APB1ENR_ALL = dict(APB1ENR_BITS)
_APB1ENR_ALL.update(APB1ENR_TIMERS)


def _mirror(value: int, pairs) -> int:
    out = value
    for on, rdy in pairs:
        if value & (1 << on):
            out |= 1 << rdy
        else:
            out &= ~(1 << rdy)
    return out & 0xFFFFFFFF


class Stm32f3Rcc(GenericPeripheral):
    """RCC with ready bits that follow their own enables."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.regs: Dict[int, int] = {RCC_CR: CR_RESET}
        self.sysclk_switched = False
        self.enabled: Dict[str, int] = {}
        log.info("Stm32f3Rcc: modelling RCC at 0x%08x (each RDY bit follows "
                 "its own ON bit; CR resets to 0x%08x)", address, CR_RESET)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        word = offset & ~0x3
        value = self.regs.get(word, 0)
        if word == RCC_CR:
            value = _mirror(value or CR_RESET, CR_PAIRS)
        elif word == RCC_CFGR:
            # SWS (3:2) mirrors SW (1:0) -- the switch completes immediately.
            value = (value & ~0xC) | ((value & 0x3) << 2)
        elif word == RCC_BDCR:
            value = _mirror(value, BDCR_PAIRS)
        elif word == RCC_CSR:
            value = _mirror(value, CSR_PAIRS)
        return value

    def _narrate(self, word: int, prev: int, value: int) -> None:
        table = {RCC_AHBENR: ("AHBENR", AHBENR_BITS),
                 RCC_APB2ENR: ("APB2ENR", APB2ENR_BITS),
                 RCC_APB1ENR: ("APB1ENR", _APB1ENR_ALL)}.get(word)
        if table is None:
            return
        reg, bits = table
        for bit, who in sorted(bits.items()):
            if (value & (1 << bit)) and not (prev & (1 << bit)):
                self.enabled[who] = 1
                log.info("Stm32f3Rcc: firmware enabled the %s clock "
                         "(%s bit %d)", who, reg, bit)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        word = offset & ~0x3
        value &= 0xFFFFFFFF
        prev = self.regs.get(word, 0)

        if word == RCC_BDCR and (value & BDCR_BDRST):
            # A backup-domain reset clears the whole register; the firmware
            # writes BDRST then clears it, then reprograms RTCSEL/RTCEN.
            self.regs[word] = 0
            return True

        self.regs[word] = value
        self._narrate(word, prev, value)

        if word == RCC_CFGR and (value & 0x3) == 0x2 and not self.sysclk_switched:
            self.sysclk_switched = True
            log.info("Stm32f3Rcc: firmware switched SYSCLK to the PLL "
                     "(CFGR=0x%08x, pc=0x%08x)", value, pc)
        return True


# --- FLASH interface (RM0316 §4.5) -----------------------------------------
FLASH_ACR, FLASH_KEYR, FLASH_OPTKEYR = 0x00, 0x04, 0x08
FLASH_SR, FLASH_CR, FLASH_AR = 0x0C, 0x10, 0x14
FLASH_OBR, FLASH_WRPR = 0x1C, 0x20

FLASH_ACR_PRFTBE = 1 << 4
FLASH_ACR_PRFTBS = 1 << 5
FLASH_SR_BSY = 1 << 0
FLASH_SR_EOP = 1 << 5

KEY1, KEY2 = 0x45670123, 0xCDEF89AB


class Stm32f3Flash(GenericPeripheral):
    """The flash interface: latency reads back, and the controller is never busy.

    ``SR`` must **not** echo writes. Its bits are write-1-to-clear, and a status
    register that stores the clear-mask makes the driver's "wait until idle"
    immortal -- 8.4 million iterations on a sibling device (playbook trap 67).
    """

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        self.regs: Dict[int, int] = {}
        self.unlocked = False
        log.info("Stm32f3Flash: modelling the flash interface at 0x%08x "
                 "(SR.BSY reads clear; SR does not echo writes)", address)

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        word = offset & ~0x3
        if word == FLASH_SR:
            return FLASH_SR_EOP            # never busy, last op complete
        if word == FLASH_OBR:
            return 0x03FFFFFC              # not read-protected
        if word == FLASH_WRPR:
            return 0xFFFFFFFF              # nothing write-protected
        if word == FLASH_ACR:
            acr = self.regs.get(word, 0)
            # PRFTBS (5) reports the prefetch buffer's actual state; it follows
            # PRFTBE (4). LATENCY reads back exactly as written, which is what
            # ChibiOS' `stm32_flash_wait` style checks compare against.
            return (acr | FLASH_ACR_PRFTBS) if acr & FLASH_ACR_PRFTBE else acr
        return self.regs.get(word, 0)

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        word = offset & ~0x3
        if word == FLASH_SR:
            return True                    # write-1-to-clear; nothing latched
        if word == FLASH_KEYR and value in (KEY1, KEY2):
            if value == KEY2 and not self.unlocked:
                self.unlocked = True
                log.info("Stm32f3Flash: firmware unlocked the flash controller")
        self.regs[word] = value & 0xFFFFFFFF
        return True
