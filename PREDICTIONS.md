<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Registered predictions — written BEFORE the assertions that read them

Registered against the inventory in `INVENTORY.md`. Each entry says what the
firmware **must** do and where that expectation comes from.

Sources, strongest first:

- **ATTACKER-CHOSEN** — the harness picks the value at run time, so the correct
  answer differs every run and no recorded output can satisfy it.
- **SPEC** — fixed by USB 2.0 or HID 1.11. Known before the guest ever ran.
- **IMAGE-DERIVED** — fixed by a byte in the guest's own descriptor, read from
  the guest this run, so the expectation is *computed from the device's own
  declaration* rather than hard-coded here.

None of these is taken from a previous run's output. Where a probe run informed
this file, it did so only by telling me *which spec clause was worth asserting*;
the obligation itself is always read off HID 1.11 / USB 2.0 and off the
interface's own declared bytes, so it cannot be tuned to make a result pass.

---

## The per-interface obligation table (SPEC + IMAGE-DERIVED)

The harness parses the CONFIGURATION descriptor the guest returned and, **for
each interface it finds**, derives that interface's obligations from that
interface's own declared bytes:

| declared | obligation | source |
|---|---|---|
| `wDescriptorLength = N` in *that* interface's HID descriptor | `GET_DESCRIPTOR(REPORT, wIndex=i, wLength=255)` must return exactly **N** bytes, byte-identical to the pre-boot prediction | HID 1.11 §7.1.1; USB 2.0 §9.3.5 (no over-read) |
| the same `N`, and a length **K chosen at run time** | `GET_DESCRIPTOR(REPORT, wIndex=i, wLength=K)` must return exactly `min(K, N)` bytes, and they must be the first `min(K, N)` bytes of the full descriptor | USB 2.0 §9.3.5 — the device sends the shorter of `wLength` and the descriptor |
| `bInterfaceSubClass == 1` | `GET_PROTOCOL` at that `wIndex` must be **honoured**, returning exactly 1 byte | HID 1.11 §7.2.5 — defined only for the boot subclass |
| `bInterfaceSubClass == 0` | `GET_PROTOCOL` at that `wIndex` must be **REFUSED**, leaking 0 bytes | HID 1.11 §7.2.5 |

Nothing in that table is a constant this package chose. For this image it
resolves to: interface 0 honours protocol requests and returns 68
report-descriptor bytes; interfaces 1 and 2 refuse protocol requests and return
182 and 21 bytes. **Change the image and the table follows it.**

Two properties make this a per-interface test rather than one test run three
times:

1. **The lengths differ** (68 / 182 / 21), so a handler that ignores `wIndex`
   answers two of the three with the wrong descriptor.
2. **The subclass discrimination is a byte the guest itself emitted.** The
   *same* request, differing only in `wIndex`, must be honoured on interface 0
   and refused on interfaces 1 and 2. A device with one global class handler
   answers all three or refuses all three, and fails either way.

**Rule 2.** Every obligation above is asserted over `R >= 3` rounds with a
**fresh run-time-chosen `K` in each round**, the three interfaces visited in a
**random order chosen that round**, and the verdict is `passed == rounds`, never
`>= 1` and never a bare `all(...)`.

## Entry: interface 0 — boot keyboard, subclass 1, EP `0x81`

1. **Report descriptor** (IMAGE-DERIVED): exactly 68 bytes, matching
   `planck_facts.yaml`'s `report_descriptors[0]` byte for byte.
2. **Truncation** (ATTACKER-CHOSEN + SPEC): `min(K, 68)` for a fresh `K` each
   round.
3. **`GET_PROTOCOL(wIndex=0)` honoured** (SPEC + IMAGE-DERIVED), because this
   interface declares subclass 1, returning exactly 1 byte.

## Entry: interface 1 — QMK NKRO / shared, subclass 0, EP `0x82`

1. **Report descriptor** (IMAGE-DERIVED): exactly 182 bytes.
2. **Truncation** (ATTACKER-CHOSEN + SPEC): `min(K, 182)`.
3. **`GET_PROTOCOL(wIndex=1)` must be REFUSED** (SPEC + IMAGE-DERIVED), because
   this interface declares subclass 0. This is the per-interface
   discrimination: the *same* request that interface 0 honours must be refused
   here.

## Entry: interface 2 — QMK console, subclass 0, EP `0x83`

1. **Report descriptor** (IMAGE-DERIVED): exactly 21 bytes, declaring the vendor
   usage page `0xFF31`.
2. **Truncation** (ATTACKER-CHOSEN + SPEC): `min(K, 21)`.
3. **`GET_PROTOCOL(wIndex=2)` must be REFUSED** (SPEC + IMAGE-DERIVED),
   subclass 0.
4. Separately, and not part of the parity criterion: the firmware's own
   `printf`, `"USB configured.\n"`, on endpoint `0x83`.

## The anti-shrink guards (registered, because they decide the denominator)

- `bNumInterfaces` from the guest's own CONFIGURATION descriptor must equal the
  number of INTERFACE descriptors the harness walks out of the same bytes, and
  must be **> 0**. A disagreement, or zero, is a **harness fault**: the run
  refuses rather than grading a smaller set. `all([])` is vacuously true and has
  scored a dead arm as perfect twice on this fleet.
- Parity is **strict**: `len(passed) == inventory_size`. A subset never passes.
- The whole 84-byte CONFIGURATION descriptor is gated against the pre-boot
  prediction in `planck_facts.yaml` (commit `ad83648`, 2026-08-06). That gate is
  the M3 rung and an input to `landed`, so a truncated or substituted descriptor
  drops the run rather than making parity easier.

## Registered NEGATIVE predictions — expected to FAIL, and named before the run

- **No interrupt-IN report is produced by a key press, on any interface.** The
  shipped keymap is 48 × `KC_TRANSPARENT` (`STATUS.md` "Known limitations" 1,
  from `PROVENANCE.md` §3.4, registered before the first boot). A full 4 × 12
  press/release sweep drives the firmware's own scan — `scans` and
  `row_selects` climb — and produces **no** keycode. That is a property of the
  vendor artifact, and **on real hardware this build does not type either**.
  Consequently:
  - **Parity is graded on control-transfer round trips.** §0 defines M4 as *"a
    request the device would answer on hardware is answered by the firmware's
    own bytes"* — a request and a response. An unsolicited interrupt-IN report
    is not a round trip, and grading on one would grade this rehost against
    behaviour the real device does not have either.
  - The harness nevertheless reports a **second, stricter fraction**
    (`interface_parity_endpoint_traffic`) counting only interfaces whose own IN
    endpoint was seen carrying firmware bytes. It is **1 / 3** — interface 2's
    console line — and it is printed next to the graded fraction precisely so
    `3/3` cannot be misread as "the keyboard types".
- **`SET_IDLE` / `GET_IDLE` on interface 1 does not store.** Interface 1 returns
  `0x00` for any value written, while interfaces 0 and 2 store and return their
  own attacker-chosen byte. Recorded here before the run so the result is a
  prediction met rather than an excuse. **Idle is therefore not part of the
  parity criterion**, and interface 1 is graded on what it does do. (The same
  QMK behaviour was independently registered on `device-bdn9-stm32f072`, a
  different QMK/ChibiOS build on a different SoC.)
- **`wIndex >= 3` must STALL.** There is no fourth interface. This is the M7
  out-of-range stimulus, and it is also the check that the descriptor walk is
  not simply answering everything.

## The M8 falsification knob

`--control parity-wrong-index` sends **every** per-interface request to
`wIndex = 0` while leaving its expectation derived from the interface it is
*supposed* to address. Interfaces 1 and 2 then receive interface 0's answers —
68 bytes, and `GET_PROTOCOL` honoured rather than refused — and fail their own
obligations. **Parity must fall to 1/3 and M8 must go false while M7 stays
true**: the knob falsifies exactly the deciding term and nothing else.

Note what this knob is *not*: it does not swap in an easier predicate for the
control arm (playbook w33.1). The predicate is identical on both arms; only the
`wIndex` the request carries changes.
