# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Breakpoint handlers -- the three places this device has to touch the guest.

  ``irq_pump``      ChibiOS' idle `wfi`: where guest time advances and where the
                    TIM2 tick and the USB interrupt are delivered. The ONLY
                    deliverer, so no exception is ever stacked on one that has
                    not run an instruction (playbook trap 74).
  ``polled_delay``  `chSysPolledDelayX`, which spins on DWT->CYCCNT inside the
                    private peripheral bus and therefore cannot terminate
                    (playbook trap 174).
  ``halt_probe``    every ChibiOS halt self-loop, so a kernel panic names itself
                    instead of being an anonymous hang (playbook trap 67).
"""
