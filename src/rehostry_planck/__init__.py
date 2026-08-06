# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""rehostry-planck -- an OLKB/Drop Planck rev6 (STM32F303, QMK on ChibiOS) as a
standalone, pip-installable HALucinator device.

The seam is USB: a 40 % ortholinear keyboard has no console, no UART and no
network, so its entire externally-reachable surface is the wire it is plugged
into -- and on that wire it is the passive end. This device therefore ships a
modelled USB **host** as well as the device peripheral, and the evidence it
produces is the firmware's own descriptors, its own HID class replies and its
own console reports.

The device is self-contained: its configs ship as package data and are
referenced by the installed module path, with no ``HALUCINATOR_SRC`` source-tree
injection. HALucinator runs in a *child* process (see :mod:`spawn`), so this
package never imports it.
"""
from . import paths, spawn

__version__ = "0.1.0"

__all__ = ["paths", "spawn", "__version__"]
