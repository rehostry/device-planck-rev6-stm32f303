# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The single source of truth for *how to run this device* under HALucinator.

The CLI, the attack and the panel all build their invocation from here, so there
is exactly one spawn recipe: HALucinator on the **unicorn** backend with this
device's configs.

HALucinator is a *runtime* dependency reached as a separate process; it is not
imported here. It must be importable by the spawned interpreter, which is the
*installed* ``halucinator`` in the running interpreter's environment
(``sys.executable``, overridable via ``HAL_PY``). We deliberately do NOT splice
any source tree onto ``PYTHONPATH``: a polluted ``HALUCINATOR_SRC`` /
``PYTHONPATH`` must never resurrect an out-of-tree core, so both are stripped
from the child environment (see :func:`spawn_env`).
"""
from __future__ import annotations

import os
import secrets
import sys
from typing import Optional

from . import paths

#: The seam: the modelled USB wire. Bytes are not piped raw here -- a keyboard's
#: wire is *transactional*, so the bridge speaks control transfers ("CTRL ...")
#: and reports back exactly what the firmware answered. See
#: peripheral_models/usb_host.py.
BRIDGE_PORT = int(os.environ.get("HAL_PLANCK_BRIDGE_PORT", "22140"))
USB_SEAM = "USB HID (EP0 control + interrupt IN 0x81/0x82/0x83)"

#: ZMQ peripheral-bus ports. HALucinator's peripheral_server.start() BINDS the
#: machine-global ipc endpoints /tmp/IoServer2Halucinator<rx> and
#: /tmp/Halucinator2IoServer<tx>; its own defaults are 5555/5556, so two devices
#: left on the default silently share one bus and inject each other's peripheral
#: messages into the wrong guest. This device owns a distinct default pair.
DEFAULT_RX_PORT = int(os.environ.get("HAL_PLANCK_RX_PORT", "6140"))
DEFAULT_TX_PORT = int(os.environ.get("HAL_PLANCK_TX_PORT", "6141"))


def new_nonce() -> str:
    """A per-spawn secret, handed to the child by environment.

    The bridge greets every client ``HELLO pid=... nonce=...`` with this value,
    and the attack refuses any peer that cannot produce it. A pid can be scraped
    from the process table and replayed in principle; a fresh 128-bit nonce
    cannot (playbook traps 168 / 210).
    """
    return secrets.token_hex(16)


def spawn_argv(python: Optional[str] = None, emulator: str = "unicorn",
               rx_port: Optional[int] = None,
               tx_port: Optional[int] = None) -> list:
    """argv for ``python -m halucinator.main`` with this device's configs."""
    argv = [python or os.environ.get("HAL_PY") or sys.executable,
            "-m", "halucinator.main"]
    for f in paths.CONFIG_FILES:
        argv += ["-c", f]
    argv += ["--emulator", emulator]
    argv += ["--rx_port", str(rx_port if rx_port is not None
                              else DEFAULT_RX_PORT)]
    argv += ["--tx_port", str(tx_port if tx_port is not None
                              else DEFAULT_TX_PORT)]
    return argv


def spawn_cwd() -> str:
    """Run from the packaged configs dir so config basenames, the relative
    ``file: planck.bin`` in the memory config, and the shipped ``logging.cfg``
    all resolve (playbook traps 42 / 111)."""
    return str(paths.configs_dir())


def spawn_env(halucinator_src: Optional[str] = None,
              extra: Optional[dict] = None,
              nonce: Optional[str] = None,
              bridge_port: Optional[int] = None) -> dict:
    """Environment for the spawned HALucinator process."""
    env = dict(os.environ)
    env.pop("HALUCINATOR_SRC", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONUNBUFFERED"] = "1"
    # MANDATORY for this image. unicorn's default M-profile model is a
    # Cortex-M3 with no VFP; this is a Cortex-M4F build whose crt0 writes
    # SCB->CPACR = 0x00F00000 and then executes `vmsr fpscr, r0`. Under the
    # default model that is an undefined instruction at a fixed PC and reads
    # like a decode failure (playbook traps 38 / 120). The YAML `cpu_model:`
    # key does NOT select the CPU on cortex-m -- the backend reads this env var.
    env.setdefault("HAL_CORTEXM_CPU_MODEL", "UC_CPU_ARM_CORTEX_M4")
    # A single breakpoint installs a GLOBAL per-instruction hook; this device
    # has ~9 intercepts (playbook trap 51).
    env.setdefault("HAL_FAST_BP", "1")
    # MANDATORY here. The pump beats from an MMIO callback (QMK's protocol task
    # never idles, so the idle seam alone goes deaf -- playbook trap 192), and
    # from there it must QUEUE onto the backend's `_pending_irqs` rather than
    # call `inject_irq`, whose `emu_stop` would abandon the store it is inside
    # (trap 99). That queue is only drained at an instruction-CHUNK boundary,
    # and `irq_chunk` defaults to **0** on cortex-m -- an unbounded run, so the
    # drain point is never reached and the tick simply never fires, silently
    # (trap 50). Anything non-zero works; this is a compromise between
    # interrupt latency and the per-chunk overhead.
    env.setdefault("HAL_IRQ_CHUNK", "20000")
    env["HAL_PLANCK_BRIDGE_PORT"] = str(bridge_port if bridge_port is not None
                                        else BRIDGE_PORT)
    if nonce:
        env["HAL_PLANCK_NONCE"] = nonce
    if extra:
        env.update({k: str(v) for k, v in extra.items()})
    return env
