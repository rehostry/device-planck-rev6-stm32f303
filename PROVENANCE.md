# PROVENANCE — OLKB/Drop Planck rev6 (STM32F303, QMK on ChibiOS)

**This file is committed BEFORE the firmware has ever been booted under
emulation.** Everything below is derived by *reading the shipped bytes* —
`arm-none-eabi-objdump` over the raw image plus `tools/extract_firmware.py` —
and nothing in it was copied out of a run log. Its whole value is that its
commit timestamp precedes every emulator log in this repository, so a later
byte-for-byte match cannot be circular: the host has no code that could have
synthesised the bytes it predicts.

Check it yourself:

```
git log --format='%H %ad %s' --date=iso        # this commit precedes any run
stat -f '%SB' .git                             # repo birth precedes any log
```

---

## 1. The artifact

| | |
|---|---|
| device | OLKB / Drop **Planck rev6** — 40 % ortholinear keyboard, 48 keys |
| MCU | STMicroelectronics **STM32F303CCT6** ("Proton-C"-class), Cortex-**M4F** |
| firmware | QMK on **ChibiOS**, built from `github.com/qmk/qmk_firmware` `keyboards/planck/rev6` via api.qmk.fm (job `0c559fc4-26dc-445c-9adb-348d36cf0480`) |
| licence | firmware GPLv2 (QMK). **Not vendored here** — no QMK source and no firmware bytes are committed; `tools/extract_firmware.py` regenerates the image. |
| vendor file | `planck_rev6_default.bin`, 61 776 B |
| sha256 (vendor file) | `dd753dab8717c6c95c3cad83d04cddf4a895558f95df3e710843a4e85101f178` |

### 1.1 The vendor `.bin` is **not** a flash image — it carries a DFU suffix

The last **16 bytes** are a DFU suffix appended by `dfu-suffix` (playbook trap
180), not code:

```
ff ff  11 df  83 04  01 00   "UFD"  10   25 89 a3 8d
 |      |      |      |        |     |     `- dwCRC
 |      |      |      |        |     `------- bLength = 16
 |      |      |      `--------|------------- bcdDFU  = 0x0100
 |      |      `---------------|------------- idVendor  = 0x0483 (STMicro)
 |      `----------------------|------------- idProduct = 0xDF11 (STM32 DFU)
 `---------------------------- |------------- bcdDevice = 0xFFFF
```

**Prediction (checkable offline, no emulator):** the DFU suffix's own CRC-32
— the *running* CRC-32 with no final complement, over every byte up to but
excluding `dwCRC` — is exactly `0x8DA38925`, and stripping the suffix leaves a
**61 760-byte (0xF140)** flash image at base `0x08000000` with sha256
`cac8ac4dcb632e1c43c2a9b2fbbb2677a8d87e186d5f8af2030db694be86b92b`.

That length is then *proven a second, independent way* from the firmware's own
reset stub (playbook trap 129 — "the reset handler is the board's datasheet").
crt0's literal pool at `0x08000280` gives:

| literal | value | meaning |
|---|---|---|
| `0x08000280` | `0x20000400` | MSP top — and vector[0] |
| `0x08000284` | `0x20000C00` | PSP top (crt0 sets `CONTROL = 2`) |
| `0x08000288` | `0x08000000` | written to `SCB->VTOR` |
| `0x08000298` | `0x0800E9E8` | `.data` **load** address |
| `0x0800029C` | `0x20000C00` | `.data` start |
| `0x080002A0` | `0x20001358` | `.data` end |
| `0x080002A4` | `0x20001358` | `.bss` start |
| `0x080002A8` | `0x20002534` | `.bss` end |

`0x0800E9E8 + (0x20001358 − 0x20000C00) = 0x0800F140` — **exactly** the end of
the stripped payload. The image ends on the last byte of `.data`, so the load
base and the suffix strip are arithmetically forced, not guessed.
`tools/extract_firmware.py` HARD-FAILS on any of these.

### 1.2 Vector table (asserted by the extractor)

* `vector[0] = 0x20000400`, `vector[1] = 0x080002BD` (Thumb).
* `_unhandled_exception` (ChibiOS' weak stub) = `0x080002BF`.
* `SysTick` (vector 15) **is the stub** ⇒ the RTOS tick is a hardware timer,
  not SysTick (playbook trap 41).
* **IRQ 28 → `0x0800A5F1`** — TIM2, ChibiOS' system tick on this build.
* **IRQ 75 → `0x0800A671`** — the **remapped** USB low-priority line.
* Control: **IRQ 19 and IRQ 20** — the *non*-remapped `USB_HP_CAN_TX` /
  `USB_LP_CAN_RX0` lines a datasheet would send you to — are the weak stub, and
  so is IRQ 33. A vector guard that cannot fail is not a guard (playbook traps
  118 / 151 / 161); this one refutes "inject IRQ 20, that is USB on an F3".

### 1.3 Cortex-M4F is mandatory

crt0 writes `SCB->CPACR (0xE000ED88) = 0x00F00000` and then executes
`vmsr fpscr, r0` **before** anything else. Under unicorn's default M-profile
model (a Cortex-M3, no VFP) that is an undefined instruction at a fixed PC and
reads like a decode failure (playbook traps 38 / 120). The device therefore sets
`HAL_CORTEXM_CPU_MODEL=UC_CPU_ARM_CORTEX_M4` in `spawn.py`; the YAML
`cpu_model:` key does **not** select the CPU on cortex-m.

---

## 2. THE PREDICTION — the bytes the firmware must put on the wire

The seam is **USB**. The STM32F303's USB block is the classic ST "USB device FS"
peripheral (RM0316 §30) — the same block as an STM32F103, *not* a Synopsys OTG
core — with a 512-byte packet memory seen by the CPU as halfwords in 32-bit
slots. A USB device does nothing until something plugs it in (playbook trap 80),
so this device implements the **host**: bus reset, `GET_DESCRIPTOR`,
`SET_ADDRESS`, `SET_CONFIGURATION`, then HID class traffic.

Every byte below was read out of the firmware image before the first boot. The
firmware's own descriptor dispatcher (`usb_get_descriptor_cb`, `0x0800761C`)
selects them:

```
0800761c:  lsrs r2, r0, #8            ; r2 = wValue >> 8 = descriptor type
           cmp  r2, #3   -> STRING
           cmp  r2, #1   -> ldr r2,=0x0800E585 ; movs r0,#18    (DEVICE)
           cmp  r2, #2   -> ldr r2,=0x0800E531 ; movs r0,#84    (CONFIGURATION)
           cmp  r2, #0x21-> table @0x0800E4F4  ; movs r0,#9     (HID)
           cmp  r2, #0x22-> ptr table @0x0800E4E8, len table @0x0800E4E4 (REPORT)
```

### 2.1 Device descriptor — 18 bytes, `GET_DESCRIPTOR(DEVICE)`

```
12 01 00 02 00 00 00 40 A8 03 F9 A4 06 00 01 02 03 01
```

i.e. bcdUSB 2.00, class/subclass/protocol 0/0/0, `bMaxPacketSize0 = 64`,
**idVendor 0x03A8 ("OLKB")**, **idProduct 0xA4F9 ("Planck")**,
bcdDevice 0x0006, iManufacturer 1, iProduct 2, iSerialNumber 3,
bNumConfigurations 1.

Cross-check that requires no USB at all: the firmware prints the same three
numbers in its own `- Version -` console text, which is a *different* copy of
the data in a different section —
`VID: 0x03A8("OLKB") PID: 0xA4F9("Planck") VER: 0x0006` at `0x0800DC6F`.

### 2.2 Configuration descriptor — 84 bytes (`wTotalLength = 0x0054`)

```
09 02 54 00 03 01 00 A0 FA                        configuration, 3 interfaces,
                                                  bus-powered + remote wakeup,
                                                  bMaxPower 0xFA (500 mA)
09 04 00 00 01 03 01 01 00                        iface 0: HID, BOOT, KEYBOARD
09 21 11 01 00 01 22 44 00                        HID 1.11, report desc 68 B
07 05 81 03 08 00 01                              EP 0x81 IN, interrupt, 8, 1 ms
09 04 01 00 01 03 00 00 00                        iface 1: HID (shared)
09 21 11 01 00 01 22 B6 00                        report desc 182 B
07 05 82 03 20 00 01                              EP 0x82 IN, interrupt, 32, 1 ms
09 04 02 00 01 03 00 00 00                        iface 2: HID (console)
09 21 11 01 00 01 22 15 00                        report desc 21 B
07 05 83 03 20 00 01                              EP 0x83 IN, interrupt, 32, 1 ms
```

### 2.3 String descriptors

| index | bytes | text |
|---|---|---|
| 0 (LANGID) | `04 03 09 04` | 0x0409 = en-US |
| 1 (Manufacturer) | `0A 03 4F 00 4C 00 4B 00 42 00` | `OLKB` |
| 2 (Product) | `0E 03 50 00 6C 00 61 00 6E 00 63 00 6B 00` | `Planck` |
| 3 (Serial) | *computed at run time* | see §5.1 — **not** predicted byte-exact |

### 2.4 HID **report** descriptors — `GET_DESCRIPTOR(REPORT, iface)`

**Interface 0 — boot keyboard, 68 bytes:**

```
05 01 09 06 A1 01 05 07 19 E0 29 E7 15 00 25 01 95 08 75 01 81 02
95 01 75 08 81 01 05 07 19 00 29 FF 15 00 26 FF 00 95 06 75 08 81 00
05 08 19 01 29 05 15 00 25 01 95 05 75 01 91 02 95 01 75 03 91 01 C0
```

(8 modifier bits, 1 reserved byte, **6** keycode bytes, 5 LED output bits +
3 bits padding — the textbook 6-key-rollover boot report.)

**Interface 1 — shared mouse / system / consumer / NKRO, 182 bytes:**

```
05 01 09 02 A1 01 85 02 09 01 A1 00 05 09 19 01 29 08 15 00 25 01 95 08
75 01 81 02 05 01 09 30 09 31 15 81 25 7F 95 02 75 08 81 06 09 38 15 81
25 7F 95 01 75 08 81 06 05 0C 0A 38 02 15 81 25 7F 95 01 75 08 81 06 C0
C0 05 01 09 80 A1 01 85 03 19 01 2A B7 00 15 01 26 B7 00 95 01 75 10 81
00 C0 05 0C 09 01 A1 01 85 04 19 01 2A A0 02 15 01 26 A0 02 95 01 75 10
81 00 C0 05 01 09 06 A1 01 85 06 05 07 19 E0 29 E7 15 00 25 01 95 08 75
01 81 02 05 07 19 00 29 EF 15 00 25 01 95 F0 75 01 81 02 05 08 19 01 29
05 95 05 75 01 91 02 95 01 75 03 91 01 C0
```

(report ID **2** = mouse, **3** = system control, **4** = consumer,
**6** = NKRO — 8 modifier bits plus a **240-bit** keycode bitmap.)

**Interface 2 — QMK console, 21 bytes:**

```
06 31 FF 09 74 A1 01 09 75 15 00 26 FF 00 95 20 75 08 81 02 C0
```

(vendor usage page 0xFF31, usage 0x74 — QMK's `hid_listen` channel, 32 bytes
per report.)

### 2.5 What the firmware must *say*, not just what it stores

Descriptors are static flash bytes; a sceptic can fairly say they only prove the
control endpoint works. Two further predictions do not have that property.

**(a) The console line.** QMK's ChibiOS protocol layer waits for
`USB_DRIVER.state == USB_ACTIVE` and then prints `USB configured.` — the string
is at `0x0800DFDA`. It is emitted **after** enumeration completes, by the
firmware's main thread, on **interface 2's** interrupt IN endpoint (0x83),
32 bytes per report. Predicted arriving bytes:
`55 53 42 20 63 6F 6E 66 69 67 75 72 65 64 2E 0A` (`"USB configured.\n"`),
padded to the 32-byte report.

**(b) QMK's HID host state, and its power-on values.** `get_keyboard_protocol()`
at `0x08006D84` is three instructions —
`ldr r3,[pc,#4] ; ldrb r0,[r3,#2] ; bx lr` — so the block's base falls out of
the literal: **`0x20000EE5`**, with

| address | variable | set by | power-on value |
|---|---|---|---|
| `0x20000EE5` | `keyboard_idle` | `SET_IDLE` (`0x08006DBC`) | **0x00** |
| `0x20000EE6` | `keyboard_led_state` | `SET_REPORT` (`0x08006D90`) | **0x00** |
| `0x20000EE7` | `keyboard_protocol` | `SET_PROTOCOL` (`0x08006D60`) | **0x01** |

Those power-on values are *not* guesses: `0x20000EE5` lies in `.data`
(`0x20000C00 … 0x20001358`), so its initialiser is at flash
`0x0800E9E8 + 0x2E5 = 0x0800ECCD`, where the image holds `00 00 01`
(playbook trap 163 — derive an initial-value prediction from the boot path, not
from a header). The extractor asserts this.

**Predicted control round-trip, byte-exact:**

| request | firmware must answer |
|---|---|
| `A1 03 00 00 00 00 01 00` — `GET_PROTOCOL`, iface 0 | `01` |
| `A1 02 00 00 00 00 01 00` — `GET_IDLE`, iface 0 | `00` |
| `21 0B 00 00 00 00 00 00` — `SET_PROTOCOL(0)`, iface 0 | zero-length status |
| `A1 03 00 00 00 00 01 00` — `GET_PROTOCOL` again | **`00`** |

---

## 3. The attack, predicted before it is run

### 3.1 The attacker-reachable surface, enumerated from the image

QMK's `usb_request_hook_cb` is at **`0x080070F8`** and its dispatch is exactly:

```
080070f8:  ldrb r2,[r0,#116]        ; setup[0] = bmRequestType
           and  r3,r2,#0x7F
           cmp  r3,#0x21            ; class request, recipient = interface
           tst  r2,#0x80            ; direction
   device->host (0xA1):  bRequest 1 -> GET_REPORT    (0x080079E4)
                         bRequest 2 -> GET_IDLE      (0x08007C30)
                         bRequest 3 -> GET_PROTOCOL  (wIndex must be 0)
   host->device (0x21):  bRequest 9 -> SET_REPORT    (wIndex <= 1, 2-byte OUT)
                         bRequest 10-> SET_IDLE      (wValue >> 8)
                         bRequest 11-> SET_PROTOCOL  (wIndex must be 0)
   ...else standard 0x81/GET_DESCRIPTOR -> usb_get_descriptor_cb
```

Every one of those is **unauthenticated**: they are ordinary HID class requests
on endpoint 0, available to *whatever the keyboard is plugged into* — a hostile
laptop, a malicious hub, a charging port. There is no pairing, no challenge, no
user confirmation and no indication to the user that any of them happened.

### 3.2 The attack

**`SET_PROTOCOL(0)` silently downgrades the keyboard from Report protocol to
Boot protocol.** The firmware stores the attacker's byte in its own
`keyboard_protocol` and — as its own report descriptors show (§2.4) — that
switches the device from the interface-1 **NKRO** report (240-key bitmap) to the
interface-0 **boot** report, which can carry at most **six** simultaneous
keycodes. Everything the user typed above six keys is dropped, invisibly and
persistently, by a host they may not control.

`SET_REPORT` (also unauthenticated, wIndex ≤ 1) writes the LED/indicator state
the same way.

**The oracle is the firmware's own answer, not host bookkeeping.** The attack
reads `GET_PROTOCOL` before and after; the byte comes off endpoint 0, composed
by the firmware from a variable the firmware itself stored. A write followed by
a read-back is immune to being wrong about the initial state (playbook trap 163),
and the *pre*-value is independently predicted above as `0x01`.

### 3.3 The negative control — the firmware must REFUSE something

An attack that only shows "the write worked" proves very little (playbook trap
22). Two rejections are predicted from the disassembly and both are required
before `landed` is reported true:

1. **`SET_PROTOCOL` with `wIndex = 1`.** `0x08007176` reads `wIndex` and
   branches to the not-handled path unless it is **zero**, so interface 1 must
   be rejected — and, crucially, `keyboard_protocol` must be **unchanged**
   afterwards. A device that accepted anything would fail this.
2. **`GET_DESCRIPTOR(REPORT, index 3)`.** `0x08007678` does `cmp r1,#2 ; bhi`
   — there are only three HID interfaces, so index 3 must not produce a
   descriptor.

### 3.4 What this device does **not** claim

* **No remote code execution, and none is claimed.** This is a capability /
  input-integrity downgrade by an unauthenticated host, nothing more.
* **The shipped keymap is empty.** `keymap_key_to_keycode_raw` (`0x080010C0`)
  bounds-checks one layer of 8 × 6 and indexes `keymaps[]` at **`0x0800D3C4`**;
  all 48 entries in the image are `0x0001` (`KC_TRANSPARENT`). This build came
  out of the QMK Configurator with no keymap loaded, so **pressing a key cannot
  produce a keycode** — the matrix scan, the debounce and the report path all
  run, but the resolved keycode is transparent on the base layer and no HID
  keycode is ever emitted. The device therefore does **not** claim a
  "keypress → keystroke" round trip, and its matrix model is used to demonstrate
  the *scan*, not a keystroke. This is a property of the vendor artifact, and it
  is stated here before the first boot rather than discovered later.
* **`bootloader_jump()` is present** at `0x08007090` and loads MSP/PC from
  **`0x1FFFD800`**, the STM32F303 system-memory DFU bootloader — matching the
  `0483:DF11` DFU suffix on the vendor file. It is *reached* from QMK's
  `BOOTMAGIC`/`COMMAND` paths, both of which need matrix input that this
  keymap-less build cannot produce, so this device **does not** demonstrate a
  bootloader jump. The address is recorded because it is the real
  firmware-replacement primitive on this hardware and belongs in any threat
  model of it.

---

## 4. What has to be modelled to get there (predicted walls)

Stated in advance so that a wall is a prediction rather than an excuse.

1. **`chSysPolledDelayX` at `0x08007DC0`** spins on `DWT->CYCCNT`
   (`0xE0001000 + 4`), which lives in the private peripheral bus and never
   advances under unicorn: `ldr r1,[r2,#4] ; L: ldr r3,[r2,#4] ; subs r3,r3,r1 ;
   cmp r0,r3 ; bhi L`. It is reached from `usb_lld`, the matrix scan's
   `matrix_io_delay()` and clock bring-up — early and often. Modelling the PPB
   to make CYCCNT count would mean owning all 1 MB of it, and the core maintains
   `ICSR.RETTOBASE` there — which ChibiOS' ISR epilogue gates its entire
   reschedule on (playbook traps 56 / 174 / 217). It is answered at its own call
   boundary instead.
2. **RCC and the flash interface** (`0x40021000`, `0x40022000`) are
   write-then-read-back handshakes, the one shape the catch-all's busy-wait
   breaker can never satisfy (playbook trap 40). Each `xxxRDY` must mirror its
   own `xxxON` so both directions work (trap 72).
3. **TIM2 must have a capture/compare interrupt, not just a counter**
   (playbook trap 89). ChibiOS is tickless here; a free-running `CNT` alone
   makes every `chThdSleep` wait for ever.
4. **The Cortex-M bit-band alias** at `0x42000000` has no backend support
   (traps 45 / 58) and must be mapped or a single aliased bit-set dies as an
   unmapped write.
5. **The PPB must NOT be declared** as a peripheral region (traps 56 / 217).
6. **`AutoPeripheral` must not be used by that name**: ChibiOS' ARMv7-M port
   ends every reschedule with `svc 0` (`0x080002F2`), and the core sets
   `skip_svc` for any class *named* `AutoPeripheral` (traps 11 / 172).

---

## 5. Honest limits on what the numbers mean

### 5.1 Values this rehost *chooses*, and therefore cannot prove

* **The STM32 96-bit unique ID** (`0x1FFFF7AC`) is not in the firmware image and
  cannot be recovered from it (playbook trap 80). The firmware formats it into
  its USB **serial-number** string descriptor (`0x080075BC` → the hex table at
  `0x0800E500`). The serial string is therefore *firmware-computed from a host-
  chosen input*: the digits prove the firmware's formatter ran, they do not
  identify a real die. It is served as a fixed, documented, obviously-synthetic
  value and is **not** part of any byte-exact prediction.
* **Guest time is monotonic but not calibrated to wall-clock.** TIM2 is advanced
  from the guest's own idle `wfi` and from peripheral activity, so it only moves
  when the guest executes — but one emulated second is not one real second.
* **The matrix is a model.** Which keys are "held" is chosen by this device; the
  firmware's own scan, debounce and reporting are what run on top of it.

### 5.2 Things a reader should be able to falsify

* Every descriptor byte in §2 is in the shipped image at the address given —
  `tools/extract_firmware.py` prints them, and `tests/test_structure.py`
  re-derives them from the image and compares against the literals in this file
  with no emulator running.
* The `.data` arithmetic in §1.1 closes exactly, or extraction fails.
* The vector-table guard in §1.2 is required to *fail* on IRQ 19/20/33.
