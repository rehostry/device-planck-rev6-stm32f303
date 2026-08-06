# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""MMIO register models for the STM32F303CCT6, plus the modelled USB host.

  ``soc_catchall``   an AutoPeripheral subclass under a DIFFERENT class name.
                     The core sets ``backend.skip_svc`` for any class literally
                     named ``AutoPeripheral``, and ChibiOS' ARMv7-M port
                     switches context with ``svc 0`` (playbook traps 11 / 172).
  ``stm32f3_clock``  RCC + the flash interface -- the write-then-read-back
                     handshakes ChibiOS' clock init spins on.
  ``stm32f3_st``     TIM2 as ChibiOS' system tick: a free-running counter plus
                     the capture/compare interrupt that actually moves the
                     kernel.
  ``stm32f3_usb``    the USB device peripheral + its packet memory.
  ``gpio_matrix``    GPIOA..GPIOF and the 6x8 switch matrix QMK scans.
  ``usb_host``       the other end of the USB wire, without which a keyboard
                     sits inert for ever -- and the host-side bridge.
"""
