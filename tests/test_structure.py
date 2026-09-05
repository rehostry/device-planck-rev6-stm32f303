# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structural tests. NO EMULATOR is started by any of them.

They exist to make three classes of silent drift loud:

* the **config and the image must agree** -- if a rebuild moves the tick timer,
  the USB line, a descriptor or the matrix wiring, something here fails rather
  than the device booting and quietly doing the wrong thing;
* the **PROVENANCE.md prediction must still be the image's bytes** -- the
  document is only evidence if its literals can be re-derived from the firmware
  at any time by anyone;
* every **check must be able to fail** (playbook traps 118 / 151 / 161): a
  structural assertion that is true for any input is not a check, so several of
  these assert that the plausible *wrong* answer disagrees.
"""
from __future__ import annotations

import os
import re
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rehostry_planck import facts, paths, spawn          # noqa: E402
from rehostry_planck import attack as attack_mod          # noqa: E402

FLASH_BASE = 0x08000000


def _image() -> bytes:
    p = paths.firmware_bin()
    if not p.is_file():
        pytest.skip("firmware not extracted; run tools/extract_firmware.py")
    return p.read_bytes()


def _provenance() -> str:
    return (ROOT / "PROVENANCE.md").read_text()


# ---------------------------------------------------------------------------
# 1. the spawn contract
# ---------------------------------------------------------------------------
def test_spawn_argv_runs_the_installed_core():
    argv = spawn.spawn_argv(python="/usr/bin/python3")
    assert argv[:4] == ["/usr/bin/python3", "-m", "halucinator.main", "-c"]
    assert "--emulator" in argv and argv[argv.index("--emulator") + 1] == "unicorn"


def test_spawn_env_strips_source_tree_injection():
    os.environ["HALUCINATOR_SRC"] = "/nonexistent/x"
    os.environ["PYTHONPATH"] = "/nonexistent/x"
    try:
        env = spawn.spawn_env()
    finally:
        os.environ.pop("HALUCINATOR_SRC", None)
        os.environ.pop("PYTHONPATH", None)
    assert "HALUCINATOR_SRC" not in env
    assert "PYTHONPATH" not in env


def test_spawn_env_sets_the_two_mandatory_knobs():
    env = spawn.spawn_env()
    # The YAML `cpu_model:` key does NOT select the CPU on cortex-m; this image
    # needs an M4F or it dies on crt0's `vmsr fpscr` (playbook traps 38 / 120).
    assert env["HAL_CORTEXM_CPU_MODEL"] == "UC_CPU_ARM_CORTEX_M4"
    # The pump queues from an MMIO callback, and that queue only drains at an
    # instruction-chunk boundary -- `irq_chunk` is 0 on cortex-m by default,
    # so without this the tick never fires, silently (playbook trap 50).
    assert int(env["HAL_IRQ_CHUNK"], 0) > 0


def test_spawn_nonce_is_fresh_and_long():
    a, b = spawn.new_nonce(), spawn.new_nonce()
    assert a != b and len(a) == 32


# ---------------------------------------------------------------------------
# 2. the config and the image agree
# ---------------------------------------------------------------------------
def test_config_entry_and_stack_match_the_vector_table():
    """The YAML's entry point and initial SP must BE the vector table's."""
    import yaml
    img = _image()
    cfg = yaml.safe_load((paths.configs_dir() / "planck_config.yaml").read_text())
    sp, reset = struct.unpack_from("<II", img, 0)
    assert cfg["machine"]["init_sp"] == sp
    assert cfg["machine"]["entry_addr"] == reset       # Thumb bit already set
    assert cfg["machine"]["vector_base"] == FLASH_BASE
    assert reset & 1, "the reset vector must carry the Thumb bit"


def test_payload_length_is_proven_by_crt0():
    """crt0's own .data copy bounds must close exactly on the end of the image.

    This is the check that makes the DFU-suffix strip a proof rather than a
    guess (PROVENANCE.md §1.1).
    """
    img = _image()
    data_load, data_start, data_end = struct.unpack_from("<III", img, 0x298)
    assert data_load + (data_end - data_start) == FLASH_BASE + len(img)
    # and it can fail: the *unstripped* vendor length would not close.
    assert data_load + (data_end - data_start) != FLASH_BASE + len(img) + 16


def test_system_tick_is_derived_and_is_not_the_siblings():
    """The tick must be the one this image wires, not TIM2/IRQ 28.

    device-nanovna-h4 is the same SoC, the same RTOS and the same USB block and
    ticks on TIM2 / IRQ 28. This image ticks on TIM3 / IRQ 29 -- and IRQ 28 is
    *live here too*, so "is the vector the weak stub?" cannot tell them apart
    (playbook trap 141). That mistake was made on this device's first boot.
    """
    img = _image()
    st = facts.load()["system_timer"]
    stub = struct.unpack_from("<I", img, 8)[0]
    assert st["irq"] == 29 and st["base"] == 0x40000400 and st["bits"] == 16
    assert struct.unpack_from("<I", img, (16 + st["irq"]) * 4)[0] != stub
    # the control that gives the assertion teeth:
    assert struct.unpack_from("<I", img, (16 + 28) * 4)[0] != stub, \
        "IRQ 28 is the stub here, so 'not the stub' would not discriminate"


def test_usb_line_is_the_remapped_one_and_the_classic_ones_are_stubs():
    img = _image()
    from rehostry_planck.bp_handlers import irq_pump
    stub = struct.unpack_from("<I", img, 8)[0]
    assert irq_pump.USB_LP_IRQ == 75
    assert struct.unpack_from("<I", img, (16 + 75) * 4)[0] != stub
    for classic in (19, 20):        # USB_HP_CAN_TX / USB_LP_CAN_RX0
        assert struct.unpack_from("<I", img, (16 + classic) * 4)[0] == stub


def test_intercept_addresses_hold_the_instructions_they_claim():
    """A bare breakpoint hit is not evidence (playbook trap 156).

    Each generated intercept must sit on the opcode its handler was written
    for, so a rebuild that moves the code fails here instead of firing a
    handler on unrelated bytes.
    """
    img = _image()
    text = (paths.configs_dir() / "planck_addrs.yaml").read_text()
    entries = re.findall(r"class: rehostry_planck\.bp_handlers\.(\w+)\.\w+\s+"
                         r"function: \w+\s+addr: (0x[0-9A-Fa-f]+)", text)
    assert entries, "no intercepts were generated"
    seen = set()
    for module, addr in entries:
        a = int(addr, 16) - FLASH_BASE
        half = struct.unpack_from("<H", img, a)[0]
        if module == "irq_pump":
            assert half == 0xBF30, "the idle seam must be a `wfi`"
        elif module == "halt_probe":
            assert half == 0xE7FE, "a halt seam must be a `b .`"
        elif module == "polled_delay":
            # `ldr r2,[pc,#12]` at the entry of chSysPolledDelayX
            assert half == 0x4A03
        seen.add(addr)
    assert len(seen) == len(entries), "two intercepts share an address"


def test_no_config_region_names_the_stock_autoperipheral():
    """ChibiOS' ARMv7-M port ends EVERY reschedule with `svc 0`, and the core
    sets `skip_svc` for any class literally named `AutoPeripheral` -- so the
    stock class anywhere here makes the kernel tick once and then park on the
    `b .` after that svc, for ever, with no fault (playbook traps 11 / 172)."""
    text = (paths.configs_dir() / "planck_config.yaml").read_text()
    assert "emulate: halucinator.peripheral_models.auto_model" not in text
    assert not re.search(r"emulate:.*\.AutoPeripheral\s*$", text, re.M)


def test_the_svc_the_kernel_reschedules_through_is_real():
    img = _image()
    stub = struct.unpack_from("<I", img, 8)[0]
    svcall = struct.unpack_from("<I", img, 11 * 4)[0]
    assert svcall != stub, "SVCall is the weak stub -- this is not ChibiOS v7-M"


def test_ppb_is_not_declared_as_a_peripheral():
    """Owning 0xE0000000 means owning SCB->ICSR, which the core maintains by
    writing that memory -- and ChibiOS skips its whole reschedule when
    RETTOBASE is clear (playbook traps 56 / 217)."""
    text = (paths.configs_dir() / "planck_config.yaml").read_text()
    assert "0xE0000000" not in text.upper().replace("0XE000ED08", "")


# ---------------------------------------------------------------------------
# 3. PROVENANCE.md's literals are still the image's bytes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,length", [("device", 18), ("config", 84),
                                         ("report0", 68), ("report1", 182),
                                         ("report2", 21)])
def test_descriptor_lengths(name, length):
    assert len(facts.descriptor(name)) == length


def test_device_descriptor_is_in_the_image_and_matches_provenance():
    img, doc = _image(), _provenance()
    dev = facts.descriptor("device")
    assert img.count(dev) == 1, "the device descriptor is not uniquely in flash"
    vid, pid = struct.unpack_from("<HH", dev, 8)
    assert (vid, pid) == (0x03A8, 0xA4F9)
    spaced = " ".join("%02X" % b for b in dev)
    assert spaced in doc, "PROVENANCE.md no longer quotes the image's bytes"


def test_report_descriptors_are_in_the_image_and_in_provenance():
    img, doc = _image(), _provenance()
    flat = re.sub(r"[^0-9A-Fa-f]", "", doc).upper()
    for i in range(3):
        body = facts.descriptor("report%d" % i)
        assert body in img
        assert body[-1] == 0xC0, "a report descriptor must END_COLLECTION"
        assert body.hex().upper() in flat, \
            "report descriptor %d is no longer quoted in PROVENANCE.md" % i


def test_the_nkro_descriptor_really_declares_240_key_bits():
    """The attack's whole claim -- that boot protocol is a downgrade -- rests
    on the shared descriptor declaring a bitmap much larger than six keys."""
    body = facts.descriptor("report1")
    # REPORT_COUNT (0x95) 0xF0 followed by REPORT_SIZE (0x75) 0x01
    assert bytes.fromhex("95f07501") in body
    boot = facts.descriptor("report0")
    # the boot report is REPORT_COUNT 6, REPORT_SIZE 8
    assert bytes.fromhex("95067508") in boot


def test_strings_are_the_firmwares_own():
    for name, want in (("string1", "OLKB"), ("string2", "Planck")):
        body = facts.descriptor(name)
        assert body[1] == 0x03 and body[0] == len(body)
        assert body[2:].decode("utf-16-le") == want


def test_host_state_addresses_and_power_on_values():
    """`keyboard_protocol` must start at 1, or the attack's baseline is stale."""
    h = facts.load()["host_state"]
    assert h["keyboard_protocol"] == h["keyboard_idle"] + 2
    assert list(h["power_on"]) == [0x00, 0x00, 0x01]
    assert "0x20000EE7" in _provenance()


def test_keymap_is_empty_and_provenance_says_so():
    """This build shipped one all-transparent layer, so a keypress cannot
    produce a keycode. That is a property of the vendor artifact and it is
    stated in PROVENANCE.md *before* the first boot -- this test stops the
    claim drifting if a future artifact is different."""
    m = facts.load()["matrix"]
    assert m["keymap_layers"] == 1
    assert m["keymap_all_transparent"] is True
    assert "KC_TRANSPARENT" in _provenance()


def test_matrix_pins_are_distinct_and_plausible():
    m = facts.load()["matrix"]
    pins = list(m["col_pins"]) + list(m["row_pins"])
    assert len(pins) == m["rows"] + m["cols"] == 14
    assert len(set(pins)) == len(pins), "a pin is used twice"
    for p in pins:
        assert 0x48000000 <= p < 0x48001800, "not a GPIOA..GPIOF ioline_t"


# ---------------------------------------------------------------------------
# 4. the attack's contract, and that its controls can fail
# ---------------------------------------------------------------------------
def test_attack_exposes_the_fleet_interface():
    import inspect
    sig = inspect.signature(attack_mod.run_attack)
    assert "on_stage" in sig.parameters and "log_dir" in sig.parameters


def test_unknown_control_mode_is_rejected_not_ignored():
    """An unrecognised control value must NEVER fall through to the real
    attack (playbook trap 200): a reviewer who mistypes it would otherwise get
    a landing and reasonably conclude the control does not discriminate."""
    with pytest.raises(ValueError):
        attack_mod.run_attack(control="nopayload")
    assert attack_mod.main(["--control", "nopayload"]) == 2


def test_live_challenge_refuses_a_replayed_transcript():
    """Layer 3 has to reject an impostor that answers from a recording.

    The static descriptor match is replayable by construction -- that is
    exactly why the *computed* half exists (playbook trap 210). Here a fake
    bridge accepts every SET_IDLE and always answers GET_IDLE with the value a
    recording would carry; the challenge must fail.
    """
    class Replay:
        def cmd(self, text, deadline):
            if text.startswith("CTRL 0x21 0x0A"):
                return "CTRL-OK "
            if text.startswith("CTRL 0xA1 0x02"):
                return "CTRL-OK 00"        # the recorded power-on value
            return "CTRL-OK "

    calls = []
    assert attack_mod._live_challenge(
        Replay(), 1e18, lambda *a, **k: calls.append(a))["ok"] is False
    # ...and it must PASS against a peer that really stores what it is told,
    # or the test above would pass for a broken challenge.

    class Honest:
        value = 0

        def cmd(self, text, deadline):
            if text.startswith("CTRL 0x21 0x0A"):
                Honest.value = (int(text.split()[3], 0) >> 8) & 0xFF
                return "CTRL-OK "
            if text.startswith("CTRL 0xA1 0x02"):
                return "CTRL-OK %02x" % Honest.value
            return "CTRL-OK "

    ok = attack_mod._live_challenge(Honest(), 1e18, lambda *a, **k: None)
    assert ok["ok"] is True
    # ...and the M6 term specifically: N of N with a floor, and N DIFFERENT
    # states producing N DIFFERENT correct replies.
    assert ok["rounds"] >= attack_mod.MIN_LADDER_ROUNDS
    assert ok["passed"] == ok["rounds"]
    assert ok["distinct_states"] >= 2
    assert ok["distinct_replies"] == ok["distinct_states"]
    assert ok["stateful"] is True


def test_m6_term_is_falsified_by_the_constant_knob():
    """`--control idle-constant` must kill the M6 term and ONLY the M6 term.

    Same honest peer, same code path, same round count: only the *input* stops
    varying. The round trip must still pass and the differential must not --
    a knob that also breaks the round trip would prove nothing about M6.
    """
    class Honest:
        value = 0

        def cmd(self, text, deadline):
            if text.startswith("CTRL 0x21 0x0A"):
                Honest.value = (int(text.split()[3], 0) >> 8) & 0xFF
                return "CTRL-OK "
            if text.startswith("CTRL 0xA1 0x02"):
                return "CTRL-OK %02x" % Honest.value
            return "CTRL-OK "

    out = attack_mod._live_challenge(Honest(), 1e18, lambda *a, **k: None,
                                     constant=True)
    assert out["ok"] is True                 # the round trip survives
    assert out["distinct_states"] == 1
    assert out["stateful"] is False          # ...and only M6 falls


def test_zero_rounds_does_not_score_vacuously():
    """`all([])` is True. Nothing here may inherit that.

    Every counted verdict in this module asserts `passed == rounds` AND a
    floor. With zero rounds the first half is satisfied by `0 == 0`, so the
    floor is the whole guard -- and it is exercised here rather than assumed.
    """
    class Honest:
        value = 0

        def cmd(self, text, deadline):
            if text.startswith("CTRL 0x21 0x0A"):
                Honest.value = (int(text.split()[3], 0) >> 8) & 0xFF
                return "CTRL-OK "
            if text.startswith("CTRL 0xA1 0x02"):
                return "CTRL-OK %02x" % Honest.value
            return "CTRL-OK "

    out = attack_mod._live_challenge(Honest(), 1e18, lambda *a, **k: None,
                                     rounds=0)
    assert out["rounds"] == 0 and out["passed"] == 0
    assert out["ok"] is False and out["stateful"] is False


def test_milestone_is_derived_and_never_a_literal():
    """The rung must come off the LADDER, and a term going false must drop it.

    The defect this device carried was `res["milestone"] = "M4"` -- a literal
    that no amount of evidence could raise, three lines below four computed
    M6/M7-shaped keys that reached no RESULT key at all.
    """
    full = {"booted": True, "descriptor_match": True,
            "usb_hid_control_round_trip": True, "stateful_readback": True,
            "adversarial_tolerated": True}
    assert attack_mod.grade(full)[0] == "M7"
    assert attack_mod.grade({**full, "adversarial_tolerated": False})[0] == "M6"
    assert attack_mod.grade({**full, "stateful_readback": False})[0] == "M4"
    assert attack_mod.grade({**full, "descriptor_match": False})[0] == "M1"
    assert attack_mod.grade({})[0] == "M0"
    import inspect
    # ------------------------------------------------------------------
    # W1 (2026-09-02): THIS USED TO BE A SUBSTRING SCAN AND IT CONSTRAINED
    # NOTHING. It searched `inspect.getsource()` for two literal spellings; an
    # audit enumerated EIGHT working equivalents that assign a milestone
    # literal anyway -- no spaces, mixed quote styles, `.update()`, assignment
    # via a module constant, a different variable name, a computed key,
    # `setattr`, `|=` -- and the scan caught **0 of 8**. The property was true
    # of this file but was in no way guaranteed.
    #
    # It is now an AST walk (`tests/_milestone_ast.py`): every write of a
    # `milestone` key or attribute must be one of exactly two shapes -- the M0
    # initialiser, or the `x["milestone"], x["rungs_met"] = grade(...)` tuple
    # unpack. Spelling is irrelevant to it. The evasion suite that proves it
    # is not decoration is the test immediately below.
    from _milestone_ast import milestone_writes, unexpected_milestone_writes
    src = inspect.getsource(attack_mod)
    writes = milestone_writes(src)
    assert unexpected_milestone_writes(src) == [], writes
    # ...and both allowed shapes are actually PRESENT. Without this an empty
    # result -- the classic vacuous pass -- would satisfy the assert above.
    kinds = {k for _, k, _ in writes}
    assert "ALLOWED:initialiser" in kinds and "ALLOWED:grade" in kinds, writes


def test_the_milestone_guard_catches_what_the_old_substring_scan_missed():
    """The guard must FAIL on evasions -- RULES 2.1: if you cannot make your
    own test fail, it is not a test.

    These are the auditor's own eight equivalents. The substring scan this
    replaced passed all eight; the AST check must reject all eight, or it is
    the same decoration in a new shape.
    """
    from _milestone_ast import unexpected_milestone_writes
    evasions = [
        'res["milestone"]="M7"',                    # no spaces
        "res['milestone'] = \"M7\"",                # mixed quote styles
        'res.update({"milestone": "M7"})',          # dict update
        'res["milestone"] = _RUNG',                 # via a module constant
        'out["milestone"] = "M7"',                  # a different variable name
        'res[KEY_MS] = "M7"',                       # computed key
        'setattr(ns, "milestone", "M7")',           # attribute form
        'res |= {"milestone": "M7"}',               # 3.9+ merge operator
    ]
    for bad in evasions:
        assert unexpected_milestone_writes(bad), "evasion NOT caught: " + bad
    # ...and the two legitimate shapes are not rejected.
    for good in ('result = {"booted": False, "milestone": "M0"}',
                 'res["milestone"], res["rungs_met"] = grade(res)'):
        assert unexpected_milestone_writes(good) == [], good


def test_result_line_is_a_deny_list_not_a_fixed_tuple():
    """A fixed key tuple is how this device's M6/M7 evidence went unread."""
    for key in ("protocol_downgraded", "reject_wrong_interface",
                "reject_bad_report_index", "adversarial_tolerated",
                "stateful_readback", "milestone", "rungs_met"):
        assert key not in attack_mod.RESULT_BULK

    # ------------------------------------------------------------------
    # W2 (2026-09-02): THE INVARIANT IS NOW DERIVED, NOT HAND-WRITTEN.
    # This test used to assert a hand-maintained key list was absent from
    # RESULT_BULK. That checks today's rungs and nothing else: add a rung to
    # LADDER tomorrow and its key could be dropped into RESULT_BULK and vanish
    # from the RESULT: line with every test still green -- which is exactly the
    # failure ("a fixed key tuple") these tests exist to prevent, one level up.
    # Deriving it from LADDER makes a new rung self-protecting.
    for _rung, _key in attack_mod.LADDER:
        assert _key not in attack_mod.RESULT_BULK, (
            "rung %s grades on %r, which RESULT_BULK would hide" % (_rung, _key))
    # the grade() output itself must reach the line too
    for _key in ("milestone", "rungs_met"):
        assert _key not in attack_mod.RESULT_BULK


def test_preflight_refuses_a_held_port():
    import socket as s
    srv = s.socket(s.AF_INET, s.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    try:
        with pytest.raises(attack_mod.Refused):
            attack_mod.preflight(port)
    finally:
        srv.close()
    # and it must ACCEPT a free port, or the guard is vacuous
    attack_mod.preflight(port)


def test_identity_check_rejects_a_stranger():
    b = attack_mod.Bridge(1)
    b.greeting = "HELLO pid=999999 device=planck-rev6-stm32f303 nonce=aa"
    with pytest.raises(attack_mod.Refused):
        b.check_identity(1234, "aa")
    b.greeting = "HELLO pid=1234 device=planck-rev6-stm32f303 nonce=bb"
    with pytest.raises(attack_mod.Refused):
        b.check_identity(1234, "aa")
    b.greeting = "HELLO pid=1234 device=somethingelse nonce=aa"
    with pytest.raises(attack_mod.Refused):
        b.check_identity(1234, "aa")
    # the positive case must pass, or the three above prove nothing
    b.greeting = "HELLO pid=1234 device=planck-rev6-stm32f303 nonce=aa"
    b.check_identity(1234, "aa")


# ---------------------------------------------------------------------------
# 5. the matrix model is a switch matrix, not a store
# ---------------------------------------------------------------------------
def test_matrix_model_reads_high_until_a_held_key_is_scanned():
    from rehostry_planck.peripheral_models.gpio_matrix import GpioMatrix, IDR
    m = GpioMatrix("gpio", 0x48000000, 0x2000)
    col_port, col_pad = m._split(m.col_pins[0])
    row_port, row_pad = m._split(m.row_pins[0])

    def read_col():
        return (m.hw_read(col_port * 0x400 + IDR, 4) >> col_pad) & 1

    # nothing selected, nothing held: pull-ups win (playbook trap 149)
    assert read_col() == 1
    # select row 0 by driving it LOW through BSRR's reset half
    m.hw_write(row_port * 0x400 + 0x1A, 2, 1 << row_pad)
    assert read_col() == 1, "no key held, so the column must still read high"
    m.press(0, 0)
    assert read_col() == 0, "a held key must pull the scanned column low"
    # a key on a DIFFERENT row must not appear while row 0 is selected
    m.release(0, 0)
    m.press(1, 0)
    assert read_col() == 1


# ---------------------------------------------------------------------------
# M8 -- parity over the inventory the guest declares (added 2026-09-05)
# ---------------------------------------------------------------------------
class _DeadBridge:
    """No guest at all: every request refuses."""

    def cmd(self, text, deadline):
        raise attack_mod.Refused("no guest")


def _stage(name, **kw):
    pass


def _parity_verdict(par):
    """The exact expression `run_attack` uses for `interface_parity_full`."""
    return bool(not par["fault"]
                and (par["declared"] or 0) > 0
                and par["rounds"] >= attack_mod.MIN_PARITY_ROUNDS
                and len(par["passed"]) == (par["declared"] or 0))


def test_parity_cannot_pass_on_an_empty_or_inconsistent_inventory():
    """`all([])` is vacuously True and has scored a dead arm as perfect twice
    on this fleet.  The degenerate inputs must FAULT, not score 0/0 as parity.

    The fourth case is the one that matters most: a CONFIGURATION descriptor
    truncated after interface 0 while still declaring three.  Grading that as
    1/1 would let our own model shrink the denominator, which is precisely what
    Rule 1 forbids.  It really happened on `device-bdn9-stm32f072`.
    """
    hdr3 = bytes.fromhex("09025400030100a0fa")      # bNumInterfaces = 3
    iface0 = bytes.fromhex("090400000103010100")
    cases = {
        "empty": b"",
        "header only, bNumInterfaces=0": bytes.fromhex("090200000000a0fa"),
        "declares 3, no INTERFACE records": hdr3,
        "declares 0, one INTERFACE record":
            bytes.fromhex("09021200000100a0fa") + iface0,
        "TRUNCATED after iface 0 while declaring 3": hdr3 + iface0,
    }
    for label, cfg in cases.items():
        par = attack_mod._parity(_DeadBridge(), 0.0, _stage, cfg, 3)
        assert par["fault"], "%s did not fault" % label
        assert par["inventory"] == [], label
        assert par["parity"] == "unmeasured", label
        assert _parity_verdict(par) is False, "%s scored M8" % label


def test_parity_is_strict_and_never_passes_on_a_subset():
    for declared, passed in ((3, [0]), (3, [0, 1]), (3, []), (2, [0]),
                             (0, []), (1, [])):
        par = {"fault": None, "declared": declared, "rounds": 3,
               "passed": passed}
        assert _parity_verdict(par) is (declared > 0
                                        and len(passed) == declared)


def test_parity_needs_n_of_n_rounds_not_one():
    """Rule 2: an oracle satisfied by a single exchange cannot tell a working
    interface from one that answers once and goes deaf."""
    for rounds in range(0, attack_mod.MIN_PARITY_ROUNDS):
        par = {"fault": None, "declared": 3, "rounds": rounds,
               "passed": [0, 1, 2]}
        assert _parity_verdict(par) is False, rounds
    assert _parity_verdict({"fault": None, "declared": 3,
                            "rounds": attack_mod.MIN_PARITY_ROUNDS,
                            "passed": [0, 1, 2]}) is True


def test_m8_is_on_the_ladder_and_m5_is_not():
    """RULES.md §1b: independence governs M5, coverage governs M8.  M5 stays
    undefined here (one bus, one peer) and must never be emitted; M8 is defined
    against `bNumInterfaces` and must be gradeable."""
    rungs = [r for r, _ in attack_mod.LADDER]
    assert "M5" not in rungs
    assert rungs[-1] == "M8"
    full = {"booted": True, "descriptor_match": True,
            "usb_hid_control_round_trip": True, "stateful_readback": True,
            "adversarial_tolerated": True, "interface_parity_full": True}
    assert attack_mod.grade(full)[0] == "M8"
    assert attack_mod.grade({**full, "interface_parity_full": False})[0] == "M7"
    assert attack_mod.INTERFACE_INVENTORY["m5_defined"] is False
    assert attack_mod.INTERFACE_INVENTORY["m8_defined"] is True
    # The declared count is filled in from the guest every run; a hard-coded
    # one here would be exactly the denominator Rule 1 forbids.
    assert attack_mod.INTERFACE_INVENTORY["m8_declared"] is None


def test_parity_obligations_come_from_the_guests_own_bytes():
    """The per-interface obligations must be read off the descriptor, so that
    changing the image changes the table.  A hand-written {0: 68, 1: 182}
    would be the artifact-derived predicate Rule 1 forbids."""
    import yaml
    from rehostry_planck import paths as _paths
    with open(_paths.configs_dir() / "planck_facts.yaml") as fh:
        cfg = bytes.fromhex(yaml.safe_load(fh)["usb"]["config_descriptor"])
    parsed = attack_mod._parse_interfaces(cfg)
    assert cfg[4] == len(parsed) == 3
    assert [f["report_len"] for f in parsed] == [68, 182, 21]
    assert [f["sub"] for f in parsed] == [1, 0, 0]
    # ... and a DIFFERENT image gives a different table, with no code change.
    grown = (bytes.fromhex("09025400040100a0fa")
             + bytes.fromhex("090400000103010100")
             + bytes.fromhex("092111010001220A00")
             + bytes.fromhex("090401000103000000")
             + bytes.fromhex("09211101000122FF01"))
    g = attack_mod._parse_interfaces(grown)
    assert grown[4] == 4 and len(g) == 2      # declares 4, ships 2 -> a fault
    assert [f["report_len"] for f in g] == [10, 511]
    assert [f["sub"] for f in g] == [1, 0]
