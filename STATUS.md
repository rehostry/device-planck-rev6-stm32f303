<!-- rehostry-census: milestone=M7 landed=true verdict=M4-OK verified=2026-09-01 method=live-run ladder=derived path=rehostry-planck-ladder note=M7-single-interface -->
# STATUS — device-planck-rev6-stm32f303

**Milestone reached: M7** — a real protocol round-trip over the firmware's own
USB seam (M4), the *same* request answered differently from two attacker-chosen
states (M6), and malformed EP0 traffic refused by the firmware's own STALL with
known-good traffic still byte-identical afterwards (M7).

**Nothing new was modelled to get here.** M4 was already measured; the M6 and
M7 evidence was already being *computed* on every run and was dropped by a
fixed four-key `RESULT:` tuple while `milestone` was assigned the string
literal `"M4"`. The rung is now **derived** from a `LADDER` table
(`attack.py`), so no header can disagree with the run it cites.

Run it: `rehostry-planck ladder [--control ...]` — or the plain
`rehostry-planck-attack`, which emits the same derived rung. The ladder is not
an opt-in mode.

| | |
|---|---|
| device | OLKB / Drop **Planck rev6**, 48-key 40 % ortholinear keyboard |
| SoC | STM32F303CCT6, Cortex-**M4F** (`HAL_CORTEXM_CPU_MODEL=UC_CPU_ARM_CORTEX_M4`) |
| firmware | QMK on ChibiOS, raw `.bin`, **no symbols** |
| core | the installed `halucinator@dev` in the shared `.venv-dev`; **no core changes** |
| seam | USB HID — EP0 control + interrupt IN 0x81 / 0x82 / 0x83 |
| tests | 31 structural tests, no emulator needed, all passing |

---

## Milestones, with the evidence

### M1 — boots without faulting

No `UC_ERR`, no `Traceback`, no `FETCH-DERAIL` in any run. Verified with
`LC_ALL=C grep -ac`: BSD `grep` prints nothing and exits 1 on a *binary* file,
which is indistinguishable from "no match" (playbook trap 155), and these logs
carry raw peripheral bytes.

### M2 — drivers initialise, in the firmware's own words

```
Stm32f3Rcc: firmware enabled the GPIOA..GPIOF clocks
Stm32f3Rcc: firmware switched SYSCLK to the PLL (CFGR=0x001d2402, pc=0x08009704)
Stm32f3SystemTimer: firmware started the tick timer (CR1=0x00000001, PSC=7199,
                    ARR=0x0000ffff)
Stm32f3SysMem: the firmware read FLASH_SIZE (pc=0x08004a24) -> 256 kB
Stm32f3Rcc: firmware enabled the USB clock (APB1ENR bit 23)
Usb: firmware brought the USB device out of reset -- it is ready to enumerate
Usb: firmware enabled the USB function (DADDR.EF)
GpioMatrix: the firmware selected its first matrix row (A10 driven LOW)
```

`PSC = 7199` is the firmware's own choice: 72 MHz / 7200 = **10 kHz**, i.e.
ChibiOS' `CH_CFG_ST_FREQUENCY` for this build, read back rather than assumed.

### M3 — the scheduler runs

```
inject_irq(29): exc 45 @ 0x800a191            <- the tick vector, DERIVED
exc_return 0xffffffec: popped from PSP, resuming at 0x80002ef
inject_irq(-5): exc 11 @ 0x8008575            <- ChibiOS' `svc 0` reschedule
IrqPump: delivered 100 tick(s) on IRQ 29; guest clock 0.103 s
```

Threads switch through ChibiOS' ARMv7-M `svc 0` epilogue and the tick advances
monotonically.

### M4 — a real protocol round-trip

Driven by the modelled USB host, the firmware transmitted **nine** descriptors
on endpoint 0 and then its own console line on interface 2:

```
UsbHost: device descriptor FROM THE FIRMWARE -- VID:PID = 03A8:A4F9, 18 bytes:
  12 01 00 02 00 00 00 40 a8 03 f9 a4 06 00 01 02 03 01
UsbHost: configuration descriptor FROM THE FIRMWARE, 84 bytes: 09 02 54 00 03 ...
UsbHost: string descriptor 1 FROM THE FIRMWARE: 0a 03 4f 00 4c 00 4b 00 42 00 'OLKB'
UsbHost: string descriptor 2 FROM THE FIRMWARE: 0e 03 50 00 ... 'Planck'
UsbHost: HID REPORT descriptor for interface 0 FROM THE FIRMWARE, 68 bytes: ...
UsbHost: HID REPORT descriptor for interface 1 FROM THE FIRMWARE, 182 bytes: ...
UsbHost: HID REPORT descriptor for interface 2 FROM THE FIRMWARE, 21 bytes: ...
UsbHost: the device is CONFIGURED -- interrupt IN endpoints open:
         ep1 (iface 0, 8 B), ep2 (iface 1, 32 B), ep3 (iface 2, 32 B)
UsbHost: 32-byte report FROM THE FIRMWARE on ep3 (interface 2):
  55 53 42 20 63 6f 6e 66 69 67 75 72 65 64 2e 0a 00 00 ...   "USB configured.\n"
```

**Every one of those descriptor bytes was predicted in `PROVENANCE.md` before
the firmware had ever been booted, and every one matched exactly.** The commit
order is checkable: the prediction commit is `ad83648`, authored
`2026-08-06 01:14:04 -0700`, and the repository itself was created at
`01:08:13` — both before any emulator log in this tree.

`USB configured.` is the stronger half: the descriptors are flash bytes read out
over EP0, but that line is composed by the firmware's *main thread* after
enumeration completes and pushed out on a *different* interface.

### M6 — the same request, three states, three different right answers

`GET_IDLE` (`bmRequestType 0xA1, bRequest 0x02, wValue 0, wIndex 0, wLength 1`)
is issued **byte-identically** in every round. Between rounds the firmware is
put into a different state by `SET_IDLE` with a byte drawn at run time
(`secrets.randbelow`, **without replacement**, so a chance collision cannot
quietly merge two states). QMK's own `set_keyboard_idle` (`0x08007194`) stores
it at `0x20000EE5`; `GET_IDLE` reads that same variable back.

The verdict asserts `distinct_replies == distinct_states >= 2` **and**
`passed == rounds` with `rounds >= 3` — never `>= 1`, and never a bare
`all(...)`.

A second, independent state differential runs in the same seam: `GET_PROTOCOL`
answers `0x01` before the attack's `SET_PROTOCOL(0)` and `0x00` after
(`protocol_downgraded`). **Both are required for M6**, so each has its own
knob — see Controls.

Live run, 2026-09-01:

```
[live-challenge] 3 of 3 run-time-chosen bytes were stored and read back through
                 QMK's own SET_IDLE/GET_IDLE handlers; the byte-identical
                 GET_IDLE answered 3 distinct values from 3 distinct states
                 ok=True rounds=3 distinct_states=3 distinct_replies=3
```

### M7 — malformed EP0 traffic refused, known-good traffic unharmed

Nine malformed control transfers in three kinds, three distinct out-of-range
values each:

| kind | values | what the firmware did |
|---|---|---|
| `GET_DESCRIPTOR(HID REPORT, wIndex)` past the last interface | 3, 4, 5 | STALL |
| `GET_DESCRIPTOR(STRING, index)` past the string table | 0x40, 0x41, 0x42 | STALL |
| an unassigned HID class `bRequest` | 0x0C, 0x0D, 0x0E | STALL |

Every refusal is the **firmware's own register write**, not a harness verdict —
the model logs a STALL only when the guest sets `EP0`'s `STAT_TX`/`STAT_RX` to
`STAT_STALL`:

```
UsbHost: the firmware STALLed 81 06 00 22 03 00 40 00 -- request REFUSED
UsbHost: the firmware STALLed 81 06 40 03 09 04 40 00 -- request REFUSED
UsbHost: the firmware STALLed a1 0c 00 00 00 00 01 00 -- request REFUSED
   (9 in total, one per case)
```

Then the half most of this fleet's M7-shaped probes are missing: **known-good
traffic is re-checked afterwards**, three rounds, each comparing all three HID
report descriptors byte-for-byte against the bytes predicted from the image
before the first boot, re-reading `GET_PROTOCOL`, and pushing a fresh random
idle byte through `SET_IDLE`/`GET_IDLE`. `3/3`.

A bridge-level timeout is explicitly **not** counted as a refusal: a guest that
has gone deaf must not read as a guest that refuses.

### M5 / M8 — undefined here, and that is a claim

This device has **one** link to **one** peer: the USB wire, to the host. Its
three HID *interfaces* (boot keyboard / NKRO / QMK console) are three
descriptor sets multiplexed over that one bus, addressed by `wIndex` on the
same EP0 dispatcher and served by the same ChibiOS USB driver. Two commands
over one seam are one interface.

**Keys that collapse into that one interface:**
`usb_hid_control_round_trip`, `descriptor_match`, `live_challenge`,
`reject_wrong_interface`, `reject_bad_report_index` and the interface-2 console
read-back. None of them is a second link. The inventory comes from the
firmware's **own configuration descriptor** read off the wire
(`bNumInterfaces`, the three HID report descriptors it hands out) — implementing
less here would not change what that descriptor says.

---

## The attack

**An unauthenticated USB host silently downgrades the keyboard from n-key
rollover to six-key boot protocol.**

`SET_PROTOCOL` is an ordinary HID class request on endpoint 0. Any host the
keyboard is plugged into may send it — a hostile laptop, a malicious hub, a
public charging port — with no pairing, no challenge, no user confirmation and
no indication to the user. QMK stores the byte in its own `keyboard_protocol`
(`0x20000EE7`), and the firmware's *own* report descriptors say what that means:
interface 1 declares a **240-bit** keycode bitmap (`95 F0 75 01` —
REPORT_COUNT 240, REPORT_SIZE 1) while interface 0 declares **six** bytes
(`95 06 75 08`). After the downgrade everything typed beyond six simultaneous
keys is dropped, invisibly and persistently.

Live run:

```
[preflight ] tcp/22140 is free on both 0.0.0.0 and 127.0.0.1 (bind probe, no SO_REUSEADDR)
[connected ] HELLO pid=81063 device=planck-rev6-stm32f303 nonce=428ddb9d42184a3f...
[identity  ] the bridge greeted with this run's child pid AND this run's per-spawn nonce
[bind-marker] the child logged HOST-BRIDGE-BOUND tcp/22140 pid=81063 and no bind failure
[provenance-static] all 7 descriptors match the bytes predicted before the first boot
[live-challenge   ] three run-time-chosen bytes stored and read back through QMK's
                    own SET_IDLE/GET_IDLE handlers
[baseline  ] the firmware reports protocol 0x01   (PROVENANCE.md predicted 0x01)
[attack    ] SET_PROTOCOL(0) -> interface 0        result=ok
[verify    ] the firmware now reports protocol 0x00
[negative-control-1] SET_PROTOCOL(1) to interface 1: protocol UNCHANGED
[negative-control-2] GET_DESCRIPTOR(REPORT, interface 3): STALL
[console   ] USB configured.
[verdict   ] landed=True before=1 after=0
RESULT: {"booted": true, "landed": true}
```

The oracle is the firmware's own `GET_PROTOCOL` answer, composed from a variable
the firmware itself stored. `landed` is gated on **all** of: the identity
challenge, the descriptor match, the live challenge, the baseline being `0x01`,
the post value being `0x00`, and both rejections.

**Scope, stated plainly.** This is a capability / input-integrity downgrade by an
unauthenticated host. It is **not** code execution, and none is claimed.

One prediction was **wrong about the mechanism** and is corrected in
`PROVENANCE.md` §6.3 rather than quietly re-worded: `SET_PROTOCOL` to interface
1 is *accepted and silently ignored*, not STALLed. The load-bearing half — that
`keyboard_protocol` is unchanged — held exactly, and that is what the control
asserts.

---

## Controls — run, not asserted

| control | what it changes | result |
|---|---|---|
| `--control withhold` | identical run, `SET_PROTOCOL` never sent | protocol stays `0x01`, `landed: false` |
| `--control wrong-interface` | `SET_PROTOCOL` sent only to interface 1 | protocol stays `0x01`, `landed: false` |
| `--control no-usb-irq` | the **guest's** USB line withheld; the whole host stack stays alive | 163,737 host beats, **zero** descriptors, `landed: false` |
| decoy on `127.0.0.1` (no emulator, no firmware) | replays a recorded transcript | refused at pre-flight |
| decoy on `0.0.0.0` (no emulator, no firmware) | replays a recorded transcript | refused at pre-flight |
| decoy + `HAL_PLANCK_AUDIT_SKIP=preflight,bindmarker` | the port guards deliberately disabled | refused at the **identity challenge** |
| `--control nopayload` (a typo) | — | `exit 2`; the real attack is **not** run |

### Ladder controls — one knob per deciding term, both arms run 2026-09-01

Each of these falsifies **exactly one** rung's deciding term and leaves the
others standing. A knob that drives some other term while the verdict stays
true is not a control.

| arm | what it changes | rung emitted | why |
|---|---|---|---|
| `--control none` | — | **M7** | `idle 3/3, 3 distinct states -> 3 distinct replies; protocol 0x01->0x00; adversarial 9/9 refused; known-good after fuzz 3/3` |
| `--control idle-constant` | `SET_IDLE` driven with the **same** byte every round | **M4** | `idle_distinct_states: 1`, `idle_stateful: false` — but `idle_passed: 3/3` and `usb_hid_control_round_trip: true`, so M4 and M7 survive. The M6 term and only the M6 term moved. |
| `--control withhold` | `SET_PROTOCOL` never sent | **M4** | `protocol_downgraded: false` — the *other* M6 term. `idle_stateful` stays true, M7 stays true. |
| `--control fuzz-benign` | every malformed index swapped for a **valid** one | **M6** | `adversarial_refused: 0/9`. The firmware answers valid indices, so the "no descriptor was produced" oracle goes false — which is what proves that oracle discriminates rather than being satisfied by anything. M4 and M6 untouched. |
| `HAL_PLANCK_LADDER_ROUNDS=0` | the adversarial stage runs **zero** cases | **M6** | `adversarial_cases: 0, adversarial_tolerated: false`. `all([])` is vacuously `True`; the floor (`cases >= 3 * 3`) is what stops `0 of 0` scoring a perfect M7. Demonstrated live, not asserted. |
| `--control no-usb-irq` | the **guest's** USB interrupt withheld | **M1** | host stack fully alive — bridge bound, greeted, connected, 225,486 SOF beats — and the guest produced **no descriptor at all**: `refused: "the firmware never produced a full descriptor set"`, `rungs_met M3..M7 all false`. Every rung above M1 is guest-derived. |

The decoy is ~70 lines with no emulator and no firmware behind it; it answers the
whole bridge protocol from a recording of this device's real descriptors and
still cannot be graded. The hardest case, with both port-level guards switched
off so only the identity challenge remains:

```
[mode] WARNING: HAL_PLANCK_AUDIT_SKIP=bindmarker,preflight -- identity guards
       are DELIBERATELY WEAKENED for an audit
[connected] greeting=HELLO pid=999999 device=planck-rev6-stm32f303 nonce=deadnonce
[refused  ] the peer is pid 999999, but the emulator this run spawned is pid 81908
RESULT: {"booted": false, "landed": false}
```

**Guest-derivation.** `SIGSTOP` on the emulator would freeze the peripheral
models and the bridge too — they are threads in the same process — so it proves
only "replies exist while that process runs" (playbook traps 183 / 187). The
`no-usb-irq` control is the sharper one: it withholds a single *guest* interrupt
line while the entire host side keeps running (the bridge binds, the client
connects, the identity check passes, the host state machine beats 163,737 times)
and the device produces **nothing**.

---

## Known limitations

1. **The shipped keymap is empty, so no keystroke can be produced.** This build
   came out of the QMK Configurator with no keymap loaded:
   `keymap_key_to_keycode_raw` (`0x080010C0`) bounds-checks **one** layer of
   8 × 6 and indexes `keymaps[]` at `0x0800D3C4`, where all 48 entries are
   `0x0001` (`KC_TRANSPARENT`). The matrix scan, the debounce and the report
   path all run — the panel's key buttons drive the real GPIO matrix and the
   firmware's own scan counters climb — but the resolved keycode is transparent
   on the base layer, so **no HID keycode is ever emitted**. This device
   therefore does **not** claim a "keypress → keystroke" round trip. It is a
   property of the vendor artifact, and it was written into `PROVENANCE.md` §3.4
   *before* the first boot rather than discovered afterwards.
2. **Guest time is monotonic but not calibrated.** TIM3 is advanced from the
   guest's own activity (its idle `wfi`, and its matrix-scan GPIO reads), so it
   only moves when the guest executes — but one emulated second is not one real
   second.
3. **The 96-bit unique device ID is synthetic.** It is not in the firmware image
   and cannot be recovered from one. The firmware formats it into its USB
   serial-number string descriptor, so those digits prove the firmware's own
   formatter ran; they identify no real die. Nothing predicted byte-exact in
   this repository depends on it.
4. **The bootloader jump is present but not demonstrated.** `bootloader_jump()`
   at `0x08007090` loads MSP/PC from `0x1FFFD800`, the STM32F303 system-memory
   DFU bootloader — matching the `0483:DF11` DFU suffix on the vendor file. It
   is reached from QMK's `BOOTMAGIC` / `COMMAND` paths, both of which need matrix
   input this keymap-less build cannot produce, so it is recorded as attack
   surface and **not** claimed as a result.
5. **No mouse, extrakey or NKRO report was observed**, for the same reason as
   (1): nothing generates one. The report *descriptors* for all three are
   transmitted and matched.
6. **SOF is modelled but the firmware never asks for it** (`CNTR.SOFM` stays
   clear in this build), so the frame clock latches `ISTR.SOF` and never raises
   the line; the console flush happens anyway. The SOF path is kept because it
   is what a real host does and because a sibling QMK build may enable it.
7. **`chSysPolledDelayX` is answered, not emulated.** It spins on `DWT->CYCCNT`
   inside the private peripheral bus, which never advances under unicorn, so it
   cannot terminate. It is a `void` busy-wait with no side effects and is
   completed at its own call boundary; ~2,160 guest cycles are skipped per call
   and the running total is logged.
8. **The emulator's own per-exception trace is off by default.** The shipped
   `logging.cfg` pins `halucinator.backends.unicorn_backend` to WARNING (a
   tickless ChibiOS guest takes one exception per armed deadline, and INFO there
   costs gigabytes and throughput — playbook trap 196). `cp logging-verbose.cfg
   logging.cfg` in the configs directory turns it, and `HAL_PC_SAMPLE`'s
   histogram, back on.

## Core changes

**None.** This is a Bucket-A device: `cortex-m3` is already in the backend's
`_ARCH_MAP` and the shared `.venv-dev` core ran it unmodified.

## Reproducing

```bash
python3 tools/extract_firmware.py     # hard-fails if anything has drifted
python3 -m pytest tests/ -q           # 30 tests, no emulator
python3 -m rehostry_planck.attack     # self-booting; one RESULT: line
```
