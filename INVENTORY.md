<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Interface inventory — registered before any per-interface assertion exists

## Why this file exists at all

`STATUS.md` used to say **"M5 / M8 — undefined here"** and gave one reason for
both: the three HID interfaces are `wIndex` values on one EP0 dispatcher, one
bus, one peer, so they are not *independent* interfaces.

**That reason is correct, and it settles M5 only.** M5 asks whether two
interfaces are INDEPENDENT. M8 asks a different question — of everything the
device *declares*, how much of it does this rehost drive at M4? A device can
have exactly one §1a-independent interface and still be graded for parity
against a larger declared inventory; `device-ardupilot-matekf405` is graded
**8/14** against ArduPilot's own capability bitmask while §1a rules all of
MAVLink to be one interface. Fourteen declared capabilities, one interface,
and those numbers are not supposed to agree.

So **M5 stays undefined here and M8 becomes DEFINED**, because an independently
derived inventory does exist for this device. It is the same source
`device-bdn9-stm32f072` uses, and it was already named in this repository's own
STATUS before any parity work began.

## Provenance: the firmware's own CONFIGURATION descriptor

The inventory is **not** the set of things `attack.py` happens to drive, and it
is not derived from the handlers in `peripheral_models/`. Deriving it that way
would make parity `|I_pass| = |I_impl|` — a predicate maximised by implementing
*less*, which Rule 1 exists to forbid.

It is **parsed at run time, by the harness, out of the CONFIGURATION descriptor
the guest itself returns.** A USB configuration descriptor is precisely a
device's published statement of the interfaces it offers: a host has no other
way to learn them, and a device cannot offer an interface it does not declare
there. Those bytes live in the firmware image, so the count does not shrink when
we implement fewer handlers — drop a handler and the interface is still
declared, still enumerated by this parser, and still fails its assertion.

`GET_DESCRIPTOR(CONFIGURATION)` returns 84 bytes with `bNumInterfaces = 3`:

```
iface 0   class 3 (HID)  subclass 1 (BOOT)  protocol 1 (keyboard)
          report descriptor  68 bytes       endpoint 0x81 IN,  8 bytes
iface 1   class 3 (HID)  subclass 0         protocol 0
          report descriptor 182 bytes       endpoint 0x82 IN, 32 bytes
iface 2   class 3 (HID)  subclass 0         protocol 0
          report descriptor  21 bytes       endpoint 0x83 IN, 32 bytes
```

**|inventory| = 3.**

Two guards stop *our own* model shrinking that denominator:

1. **`bNumInterfaces` is cross-checked against the walk.** The harness asserts
   `len(parsed) == cfg[4]` and `cfg[4] > 0`. A disagreement is a **harness
   fault** and refuses the run; it never silently grades a smaller set.
2. **The whole 84 bytes are gated against a pre-boot prediction.**
   `descriptor_match` compares every descriptor to `planck_facts.yaml`, which
   was extracted from the image and committed in `ad83648`
   (2026-08-06 01:14:04 -0700) — before any emulator log exists in this tree.
   `descriptor_match` is an M3 rung and an input to `landed`, so a truncated or
   substituted CONFIGURATION descriptor **drops the run to M1** rather than
   making parity easier. On `device-bdn9-stm32f072` a truncated descriptor
   really did happen, and it correctly dropped that run instead of shrinking its
   denominator.

## What M5 says, and why it is still undefined

Unchanged, and repeated here so the two verdicts cannot be confused:

This device has **one** link to **one** peer — the USB wire, to the host. Its
three HID interfaces are three descriptor sets multiplexed over that one bus,
addressed by `wIndex` on the same EP0 dispatcher and served by the same ChibiOS
USB driver. Under §1a's positive test an interface needs **its own transport
endpoint and its own application logic**; every graded exchange here is an EP0
control transfer with `wIndex` selecting the descriptor set, so they are one
interface. `usb_hid_control_round_trip`, `descriptor_match`, `live_challenge`,
`reject_wrong_interface`, `reject_bad_report_index` and the interface-2 console
read-back all collapse into that one interface.

**M5 undefined. M8 defined, and graded below.**

## The shared substrate, stated machine-readably

All three interfaces share the USB transport and one enumeration. Breaking the
USB device peripheral breaks all three at once. `INTERFACE_INVENTORY` in
`attack.py` records this as `shared_substrate` so a reader applying a stricter
rule can re-derive their own number rather than take ours.

## Scope notes, stated now rather than after the results

- **Parity is graded on control-transfer round trips, not on endpoint IN
  traffic.** §0 defines M4 as *"a request the device would answer on hardware is
  answered by the firmware's own bytes"* — a request and a response. An
  interrupt IN report is unsolicited device-to-host traffic and is not a round
  trip, so it is not the criterion. This is stated before the results because it
  changes the number: see the registered negative below, and the second,
  stricter fraction the harness reports alongside the graded one.
- **Interface 2 is device-to-host only on its interrupt pipe.** Its round trip
  is therefore made on the **control** pipe addressed to interface 2
  (`wIndex = 2`). `0x83` is separately shown carrying the firmware's own
  `printf`, `"USB configured.\n"`.
- **There is no fourth interface and none is claimed.** `wIndex = 3` and above
  are used as the M7 out-of-range stimuli and must STALL.

## Registered predictions

Per-interface obligations and the registered negative predictions are in
`PREDICTIONS.md`, written in the same change as this file and **before** any
assertion that reads them.
