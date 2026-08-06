# device-planck-rev6-stm32f303

A rehosted **OLKB / Drop Planck rev6** — a 48-key, 40 % ortholinear keyboard on
an **STM32F303CCT6** ("Proton-C"-class, Cortex-M4F) running **QMK on ChibiOS** —
as a standalone, pip-installable HALucinator device.

The seam is **USB**. A keyboard has no console, no UART and no network: its
entire externally reachable surface is the cable, and on that cable it is the
*passive* end. So this device ships a modelled USB **host** as well as the
STM32's USB device peripheral, and everything it demonstrates is the firmware's
own bytes on that wire.

## What it does

* Boots the real vendor firmware to a full **USB enumeration**: device,
  configuration, string and all three **HID report** descriptors, each matching
  byte-for-byte a prediction committed **before the firmware had ever been
  booted** (`PROVENANCE.md`, and `git log` proves the order).
* Reaches the firmware's own runtime output: QMK prints `USB configured.` on its
  **console HID endpoint** (interface 2, EP 0x83) once enumeration completes.
* Runs QMK's **matrix scan** against a modelled 6×8 switch matrix on
  GPIOA..GPIOF, with the pin lists and geometry recovered from the image.
* Demonstrates an **unauthenticated USB host silently downgrading the keyboard**
  from report protocol (NKRO, a 240-key bitmap) to **boot protocol** (six keys
  maximum), verified by the firmware's own `GET_PROTOCOL` answer.

## Quick start

```bash
# 1. regenerate the flash image (firmware bytes are NOT committed -- QMK is GPLv2)
python3 tools/extract_firmware.py

# 2. install into the venv that has halucinator@dev
"$HAL_VENV/bin/pip" install -e .

# 3. boot it
rehostry-planck run --seconds 120

# 4. run the attack (self-booting; prints exactly one RESULT: line)
rehostry-planck-attack
#   RESULT: {"booted": true, "landed": true}

# 5. the web panel
rehostry-planck-panel          # http://127.0.0.1:8892
```

Negative controls, each of which must **not** land:

```bash
rehostry-planck-attack --control withhold          # never send SET_PROTOCOL
rehostry-planck-attack --control wrong-interface   # send it to interface 1
rehostry-planck-attack --control no-usb-irq        # host alive, guest USB dead
```

## Layout

```
PROVENANCE.md            the pre-boot prediction, and (§6) what the boot actually did
STATUS.md                milestones reached, evidence, and the known limitations
tools/extract_firmware.py  derives planck.bin + the generated configs; HARD-FAILS on drift
src/rehostry_planck/
  spawn.py               the single `python -m halucinator.main` recipe
  attack.py              run_attack(on_stage, log_dir) -> dict; one RESULT: line
  planck_panel.py        polling web panel (never SSE), reaps its child on SIGTERM
  configs/               the HALucinator config + the GENERATED addr map and facts
  peripheral_models/     RCC/flash, TIM3 (the tick), the USB device block + PMA,
                         the system/OTP page, the GPIO switch matrix, the USB host
  bp_handlers/           the idle-`wfi` pump, chSysPolledDelayX, the halt probes
tests/test_structure.py  30 no-emulator tests: config/image agreement, the
                         PROVENANCE literals, and that each control can fail
```

## Licence

AGPL-3.0-or-later. The **firmware** is QMK, GPLv2 — no firmware bytes and no
QMK source are committed here; `tools/extract_firmware.py` regenerates the image
from the vendor artifact.
