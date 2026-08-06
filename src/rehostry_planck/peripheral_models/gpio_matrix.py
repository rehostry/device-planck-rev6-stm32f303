# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GPIOA..GPIOF, and the 6x8 key matrix wired across them.

WHY THIS IS A MODEL AND NOT A CATCH-ALL. The Planck's only physical input is a
switch matrix, and QMK reaches it through nothing but ordinary GPIO registers --
so if this page is served by the catch-all, the busy-wait breaker sees one PC
reading ``GPIOx_IDR`` millions of times, decides it is a stalled poll, and
starts handing back escalating garbage (playbook trap 191, measured on
device-tinysa's bit-banged radio bus). The firmware then "reads" keys that were
never pressed, from a model that looks like it is working.

THE SCAN IS THE FIRMWARE'S, NOT OURS. ``matrix_read_cols_on_row()`` at
``0x08002D7C`` is, in full::

    r1 = row_pins[current_row]            ; ioline_t = (GPIO base | pad)
    if (r1 == NO_PIN) return
    palSetLineMode(r1, PAL_MODE_OUTPUT_PUSHPULL)
    *(u16 *)(port + 0x1A) = 1 << pad      ; BSRR high half == RESET -> row LOW
    matrix_output_select_delay()
    for (i = 0; i < 6; i++) {
        r1 = col_pins[i]
        bit = (*(u32 *)(port + 0x10) >> pad) & 1   ; IDR
        if (bit == 0) row_bits |= (1 << i)         ; ACTIVE LOW
    }
    palSetLineMode(row_pin, PAL_MODE_INPUT_PULLUP) ; unselect
    current_matrix[current_row] = row_bits

so the diode direction (COL2ROW), the active-low sense, the pull-ups and the
per-row select are all decisions the *firmware* makes. This model only has to
be a switch matrix: when the firmware drives row R low and reads column C, the
column reads 0 if and only if key (R, C) is held.

TWO RULES THAT ARE EASY TO GET WRONG
------------------------------------

* **An undriven input pin reads 1, not 0** (playbook trap 149). Every STM32 pin
  here is configured input-with-pull-up and every switch is wired active-low
  against it, so "nothing pressed" is all-ones. A page that reads 0 means *every
  key on the board is held*, which QMK will faithfully report.
* **An output pin must read back on IDR** (playbook trap 72). A push-pull pad
  reflects the level it is driving on the *input* register, and QMK's own
  ``matrix_output_unselect_delay`` path depends on nothing else here -- but the
  rule is free to honour and its absence is nearly invisible.

The pin tables and the matrix geometry are NOT hardcoded: they are recovered
from the image by ``tools/extract_firmware.py`` into ``planck_facts.yaml`` and
loaded here, so a rebuild that re-wires the board re-wires the model.
"""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from halucinator import hal_log

from .soc_catchall import SocCatchAll

log = hal_log.getHalLogger()

# STM32F3 GPIO register offsets (RM0316 §11.4).
MODER, OTYPER, OSPEEDR, PUPDR, IDR, ODR, BSRR, LCKR, AFRL, AFRH, BRR = (
    0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28)

PORT_STRIDE = 0x400
PORT_NAMES = "ABCDEF"

_MATRIX: Optional["GpioMatrix"] = None


def get_matrix() -> Optional["GpioMatrix"]:
    """The live GPIO/matrix model (the panel and attack drive it)."""
    return _MATRIX


class GpioMatrix(SocCatchAll):
    """GPIOA..GPIOF with a switch matrix behind the pins QMK scans."""

    def __init__(self, name: str, address: int, size: int,
                 **kwargs: Any) -> None:
        super().__init__(name, address, size, **kwargs)
        from .. import facts
        f = facts.load()["matrix"]
        self.rows: int = f["rows"]
        self.cols: int = f["cols"]
        self.col_pins: List[int] = list(f["col_pins"])
        self.row_pins: List[int] = list(f["row_pins"])
        self.base = address
        #: per-port register files; ODR starts 0 and MODER at its reset value.
        self.regs: Dict[Tuple[int, int], int] = {}
        #: pins currently driven LOW by the firmware, as (port, pad).
        self.driven_low: Set[Tuple[int, int]] = set()
        #: keys the operator is holding, as (row, col) matrix coordinates.
        self.pressed: Set[Tuple[int, int]] = set()
        self.scans = 0
        self.row_selects = 0
        self.col_reads = 0
        self._lock = threading.RLock()
        self._trace = os.environ.get("HAL_PLANCK_GPIO_TRACE") == "1"
        global _MATRIX
        _MATRIX = self
        log.info("GpioMatrix: GPIOA..GPIOF at 0x%08x; %dx%d switch matrix "
                 "(cols %s / rows %s), inputs read HIGH unless a held key "
                 "pulls them to a selected row",
                 address, self.rows, self.cols,
                 " ".join(self._pin_name(p) for p in self.col_pins),
                 " ".join(self._pin_name(p) for p in self.row_pins))

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _pin_name(line: int) -> str:
        return "%s%d" % (PORT_NAMES[(line >> 10) & 0x7], line & 0xF)

    @staticmethod
    def _split(line: int) -> Tuple[int, int]:
        """An ioline_t is (GPIO base | pad)."""
        return ((line >> 10) & 0x7, line & 0xF)

    def _port_of(self, offset: int) -> Tuple[int, int]:
        return offset // PORT_STRIDE, offset % PORT_STRIDE

    # -- the operator-facing surface ---------------------------------------
    def press(self, row: int, col: int) -> None:
        with self._lock:
            self.pressed.add((row, col))
        log.info("GpioMatrix: key (row %d, col %d) is now HELD -- pin %s will "
                 "read LOW while the firmware selects row %s", row, col,
                 self._pin_name(self.col_pins[col]),
                 self._pin_name(self.row_pins[row]))

    def release(self, row: int, col: int) -> None:
        with self._lock:
            self.pressed.discard((row, col))
        log.info("GpioMatrix: key (row %d, col %d) released", row, col)

    def release_all(self) -> None:
        with self._lock:
            self.pressed.clear()

    def held(self) -> List[Tuple[int, int]]:
        with self._lock:
            return sorted(self.pressed)

    # -- the matrix itself --------------------------------------------------
    def _selected_row(self) -> Optional[int]:
        """Which matrix row the firmware is currently driving LOW, if any."""
        for r, line in enumerate(self.row_pins):
            if self._split(line) in self.driven_low:
                return r
        return None

    def _column_level(self, port: int, pad: int) -> Optional[int]:
        """0/1 for a column pin, or None if this pin is not a column."""
        for c, line in enumerate(self.col_pins):
            if self._split(line) == (port, pad):
                row = self._selected_row()
                if row is None:
                    return 1                      # no row selected: pulled up
                with self._lock:
                    held = (row, c) in self.pressed
                return 0 if held else 1
        return None

    # -- MMIO ---------------------------------------------------------------
    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        port, reg = self._port_of(offset)
        word = reg & ~0x3
        if word != IDR:
            return self.regs.get((port, word), self._reset_value(port, word))
        # THE CLOCK BEATS HERE. QMK's protocol task never blocks, so the idle
        # `wfi` is unreachable once the keyboard is up and an idle-only pump
        # goes deaf exactly when the device starts working (playbook trap 192).
        # A matrix column read is the hottest evidence there is that the guest
        # is executing, so guest time is charged against it (traps 77 / 145).
        from ..bp_handlers import irq_pump
        irq_pump.mmio_beat()
        # IDR: start from "every pin pulled up", then apply what the firmware
        # is driving (playbook trap 72) and finally the matrix.
        value = 0xFFFF
        odr = self.regs.get((port, ODR), 0)
        for pad in range(16):
            if (port, pad) in self.driven_low:
                value &= ~(1 << pad)
            elif odr & (1 << pad):
                value |= 1 << pad
            level = self._column_level(port, pad)
            if level is not None:
                self.col_reads += 1
                if level:
                    value |= 1 << pad
                else:
                    value &= ~(1 << pad)
        if self._trace:
            log.info("GpioMatrix: READ GPIO%s->IDR = 0x%04x (pc=0x%08x, "
                     "row selected=%s)", PORT_NAMES[port], value, pc,
                     self._selected_row())
        return value

    @staticmethod
    def _reset_value(port: int, word: int) -> int:
        # MODER resets to all-analog on the F3 for most ports; nothing in this
        # firmware reads it back and acts on it, so 0 is honest enough. IDR is
        # never served from here.
        return 0

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        port, reg = self._port_of(offset)
        word = reg & ~0x3
        value &= (1 << (8 * size)) - 1

        # BSRR is two halves in one word: [15:0] SET, [31:16] RESET. QMK's row
        # select writes a HALFWORD at +0x1A, i.e. the RESET half only, so the
        # access size and offset both matter here.
        if word == BSRR:
            if reg == BSRR + 2:                 # halfword store to the top half
                self._bsrr(port, reset=value, set_=0)
            else:
                self._bsrr(port, reset=(value >> 16) & 0xFFFF,
                           set_=value & 0xFFFF)
            return True
        if word == BRR:
            self._bsrr(port, reset=value & 0xFFFF, set_=0)
            return True
        if word == ODR:
            self.regs[(port, ODR)] = value
            for pad in range(16):
                if value & (1 << pad):
                    self.driven_low.discard((port, pad))
                else:
                    pass                        # ODR=0 alone does not "drive"
            return True
        if word == MODER:
            # Returning a row pin to input (QMK's unselect) releases it.
            prev = self.regs.get((port, MODER), 0)
            self.regs[(port, MODER)] = value
            for pad in range(16):
                was_out = ((prev >> (2 * pad)) & 3) == 1
                now_out = ((value >> (2 * pad)) & 3) == 1
                if was_out and not now_out:
                    self.driven_low.discard((port, pad))
            return True
        self.regs[(port, word)] = value
        return True

    def _bsrr(self, port: int, reset: int, set_: int) -> None:
        for pad in range(16):
            if reset & (1 << pad):
                if (port, pad) not in self.driven_low:
                    self.driven_low.add((port, pad))
                    if self._is_row(port, pad):
                        self.row_selects += 1
                        if self.row_selects == 1:
                            log.info("GpioMatrix: the firmware selected its "
                                     "first matrix row (%s driven LOW) -- "
                                     "QMK's scan is running",
                                     self._pin_name((port << 10) | pad
                                                    | 0x48000000))
                        if self.row_selects % self.rows == 0:
                            self.scans += 1
            if set_ & (1 << pad):
                self.driven_low.discard((port, pad))

    def _is_row(self, port: int, pad: int) -> bool:
        return (port, pad) in [self._split(p) for p in self.row_pins]
