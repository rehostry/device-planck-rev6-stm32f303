# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The attack: an unauthenticated USB host silently downgrades the keyboard.

WHAT IT DOES. `SET_PROTOCOL(0)` is an ordinary HID class request on endpoint 0.
It is available to **whatever the keyboard is plugged into** -- a hostile
laptop, a malicious hub, a charging port in an airport -- with no pairing, no
challenge, no user confirmation and no indication to the user that it happened.
QMK stores the attacker's byte in its own ``keyboard_protocol`` and, as the
firmware's *own* report descriptors say, that switches the device from its
interface-1 **NKRO** report (a 240-key bitmap) to the interface-0 **boot**
report, which can carry at most **six** simultaneous keycodes. Everything the
user types beyond six keys is dropped, invisibly and persistently.

THE ORACLE IS THE FIRMWARE'S OWN ANSWER. The verdict is `GET_PROTOCOL`, read
back off endpoint 0 and composed by the firmware from a variable the firmware
itself stored (`0x20000EE7`, recovered from `get_keyboard_protocol()`'s literal
pool -- PROVENANCE.md §2.5). Nothing host-side computes it. A write followed by
a read-back is also immune to being wrong about the initial state (playbook
trap 163), and the *pre*-value was predicted statically as `0x01` from the
`.data` initialiser image before the firmware had ever been booted.

TWO REJECTIONS ARE REQUIRED (playbook trap 22). "The write worked" proves very
little on its own -- a device that accepted everything would look identical. So
`landed` also requires that the firmware **refuses**:

  * `SET_PROTOCOL` addressed to **interface 1** (`0x08007176` branches to the
    not-handled path unless `wIndex == 0`), *and* that `keyboard_protocol` is
    unchanged afterwards;
  * `GET_DESCRIPTOR(REPORT, index 3)` (`0x08007678` does `cmp r1,#2 ; bhi`).

WHOSE GUEST IS THIS? Every layer below is necessary and none is sufficient
alone (playbook traps 168 / 182 / 210):

  0. pre-flight by **binding** the bridge port -- on **both** the wildcard and
     loopback, and deliberately **without** ``SO_REUSEADDR``, because with it a
     probe *succeeds* against a wildcard squatter, which is the exact hole that
     let a 60-line decoy score a byte-identical landing on a sibling device;
  1. abort unless our own child's log carries ``HOST-BRIDGE-BOUND tcp/<port>
     pid=<child>`` -- and never a ``HOST-BRIDGE-BIND-FAILED``;
  2. after connecting, require the greeting to carry **our child's pid** *and*
     the **per-spawn nonce** we generated and passed by environment. A pid can
     be scraped and replayed in principle; a fresh 128-bit nonce cannot;
  3. a **live** challenge the guest must compute: three bytes chosen at run
     time, pushed through QMK's own `SET_IDLE` handler and read back through
     `GET_IDLE`. A recorded transcript cannot satisfy a fresh challenge, which
     is exactly why the static descriptor match (replayable by construction) is
     not enough on its own.

`landed` is gated on every one of those. A control that cannot fail the verdict
is not a control (playbook trap 4 of the attack box).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

from . import facts, paths, spawn

#: Negative-control modes. An UNRECOGNISED value must never fall through to the
#: real attack (playbook trap 200), so this set is the authority and anything
#: else is a hard error.
CONTROLS = {
    "none": "the real attack",
    "withhold": "connect, enumerate and verify, but NEVER send SET_PROTOCOL",
    "wrong-interface": "send SET_PROTOCOL only to interface 1, which the "
                       "firmware must refuse",
    "no-usb-irq": "spawn with the guest's USB interrupt WITHHELD: the host "
                  "stack stays fully alive while the guest's USB path is dead",
    # -- LADDER KNOBS. Each one falsifies exactly ONE deciding term. A knob
    # that drives some other term while leaving the verdict true is not a
    # control (this fleet found that exact defect on a sibling device today).
    "idle-constant": "drive SET_IDLE with the SAME byte in every round: the "
                     "round trip still passes, but the firmware is never put "
                     "into two different states, so the M6 term -- and ONLY "
                     "the M6 term -- must go false",
    "fuzz-benign": "replace every malformed request in the adversarial stage "
                   "with its WELL-FORMED twin (report index 0, string index "
                   "1, an implemented bRequest). The firmware answers them, "
                   "so the 'no descriptor was produced' oracle must go false "
                   "-- proving that oracle discriminates rather than being "
                   "satisfied by anything. M4 and M6 must survive.",
}

#: Rule 2 -- no one-shot oracles. Every differential and every refusal below is
#: repeated this many times with a **fresh, run-time-chosen** input, and the
#: verdicts below assert ``passed == rounds`` with ``rounds >= MIN``, never
#: ``>= 1`` and never a bare ``all(...)``: ``all([])`` is vacuously True and has
#: already scored a dead arm as perfect on this fleet. Set to 0 to demonstrate
#: the empty-list guard -- it must produce M4, not M7.
LADDER_ROUNDS = int(os.environ.get("HAL_PLANCK_LADDER_ROUNDS", "3"))
MIN_LADDER_ROUNDS = 3

#: AUDIT-ONLY lever, and it only ever WEAKENS the guards. An auditor testing
#: "is layer 2 load-bearing, or is the run only saved by the port checks?" needs
#: to be able to switch layers 0 and 1 off and see the identity challenge refuse
#: on its own. Never set in a normal run; every stage it disables is announced.
AUDIT_SKIP = {s.strip() for s in
              os.environ.get("HAL_PLANCK_AUDIT_SKIP", "").split(",") if s.strip()}
_ALLOWED_SKIPS = {"preflight", "bindmarker"}
if AUDIT_SKIP - _ALLOWED_SKIPS:
    raise SystemExit("HAL_PLANCK_AUDIT_SKIP: unknown item(s) %s; valid are %s"
                     % (sorted(AUDIT_SKIP - _ALLOWED_SKIPS),
                        sorted(_ALLOWED_SKIPS)))

BOOT_TIMEOUT = float(os.environ.get("HAL_PLANCK_BOOT_TIMEOUT", "240"))
ENUM_TIMEOUT = float(os.environ.get("HAL_PLANCK_ENUM_TIMEOUT", "180"))


class Refused(RuntimeError):
    """The run cannot be graded -- abort, do not downgrade to a boolean."""


# ---------------------------------------------------------------------------
# layer 0: pre-flight
# ---------------------------------------------------------------------------
def preflight(port: int) -> None:
    """Refuse to run if anything holds the bridge port.

    Probe by **bind**, never by connect: a connect probe consumes a slot in the
    listener's accept backlog (so two probes in a row disagree) and, worse, it
    *succeeds* against a foreign listener -- which is precisely the condition
    that must abort.

    Probe **both** addresses and use **no** ``SO_REUSEADDR``. On BSD/macOS a
    wildcard `0.0.0.0` bind and a specific `127.0.0.1` bind coexist, and a
    connection to loopback goes to the more specific one; with
    ``SO_REUSEADDR`` set, a loopback probe binds happily *alongside* a wildcard
    squatter and reports the port free.
    """
    for host in ("0.0.0.0", "127.0.0.1"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, port))
        except OSError as exc:
            raise Refused(
                "pre-flight: tcp/%d is already held on %s (%s). Refusing to "
                "run -- a stale or foreign listener would be graded as this "
                "device's firmware." % (port, host, exc))
        finally:
            s.close()


# ---------------------------------------------------------------------------
# the bridge client
# ---------------------------------------------------------------------------
class Bridge:
    """A line client for the USB host bridge, with the identity checks."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.buf = b""
        self.greeting = ""

    def connect(self, deadline: float) -> None:
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection(("127.0.0.1", self.port),
                                                     timeout=5.0)
                self.sock.settimeout(60.0)
                self.greeting = self.readline(deadline)
                return
            except OSError:
                time.sleep(0.5)
        raise Refused("never connected to the bridge on tcp/%d" % self.port)

    def readline(self, deadline: float) -> str:
        while b"\n" not in self.buf:
            if time.time() > deadline:
                raise Refused("timed out reading from the bridge")
            chunk = self.sock.recv(65536)
            if not chunk:
                raise Refused("the bridge closed the connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("ascii", "replace").strip()

    def cmd(self, text: str, deadline: float) -> str:
        self.sock.sendall((text + "\n").encode())
        return self.readline(deadline)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # -- layer 2 -----------------------------------------------------------
    def check_identity(self, child_pid: int, nonce: str) -> None:
        m = re.match(r"HELLO pid=(\d+) device=(\S+) nonce=(\S*)",
                     self.greeting)
        if not m:
            raise Refused("the peer on tcp/%d did not greet as this device's "
                          "bridge (got %r)" % (self.port, self.greeting))
        pid, dev, got = int(m.group(1)), m.group(2), m.group(3)
        if dev != "planck-rev6-stm32f303":
            raise Refused("the peer says it is %r, not this device" % dev)
        if pid != child_pid:
            raise Refused("the peer is pid %d, but the emulator this run "
                          "spawned is pid %d -- we are talking to somebody "
                          "else's guest" % (pid, child_pid))
        if got != nonce:
            raise Refused("the peer did not produce this run's nonce (a "
                          "replayed or recorded greeting)")


# ---------------------------------------------------------------------------
# control transfers, expressed the way the firmware's dispatcher reads them
# ---------------------------------------------------------------------------
def ctrl(bridge: Bridge, bm: int, req: int, value: int, index: int,
         length: int, deadline: float, out: bytes = b"") -> Tuple[str, bytes]:
    reply = bridge.cmd("CTRL 0x%02X 0x%02X 0x%04X 0x%04X %d%s"
                       % (bm, req, value, index, length,
                          (" " + out.hex()) if out else ""), deadline)
    if reply.startswith("CTRL-OK"):
        parts = reply.split()
        return "ok", bytes.fromhex(parts[1]) if len(parts) > 1 else b""
    if reply.startswith("CTRL-STALL"):
        return "stall", b""
    return "error", reply.encode()


GET_PROTOCOL = (0xA1, 0x03)
SET_PROTOCOL = (0x21, 0x0B)
GET_IDLE = (0xA1, 0x02)
SET_IDLE = (0x21, 0x0A)
GET_DESCRIPTOR = (0x81, 0x06)
DESC_REPORT, DESC_STRING = 0x22, 0x03


# ---------------------------------------------------------------------------
# the ladder
# ---------------------------------------------------------------------------
#: The rung is DERIVED, never written down. Each entry is (rung, evidence key);
#: the milestone is the last rung whose key is true with every earlier key true,
#: so a term that goes false drops the rung and is visible in ``rungs_met``.
#:
#: **M5 and M8 are deliberately absent and that is a claim, not an omission.**
#: This device has exactly ONE link to exactly one peer: the USB wire, to the
#: host. Its three HID *interfaces* (boot keyboard / NKRO / QMK console) are
#: three descriptor sets multiplexed over that one bus, addressed by wIndex on
#: the same EP0 dispatcher and served by the same ChibiOS USB driver -- "two
#: commands over one seam are one interface". So `usb_hid_control_round_trip`,
#: `descriptor_match`, `live_challenge` and the console read-back all collapse
#: into ONE interface, and M5/M8 are undefined here rather than unmet.
LADDER: Tuple[Tuple[str, str], ...] = (
    ("M1", "booted"),
    ("M3", "descriptor_match"),
    ("M4", "usb_hid_control_round_trip"),
    ("M6", "stateful_readback"),
    ("M7", "adversarial_tolerated"),
)

#: One link, one peer -- see the LADDER note. Written down so a census can read
#: it rather than infer it from the number of `*_round_trip` keys, which has
#: over-counted on four devices in this fleet.
INTERFACE_INVENTORY = {
    # Source: the FIRMWARE'S OWN configuration descriptor, read off the wire
    # during enumeration -- bNumInterfaces and the three HID report
    # descriptors it hands out. Not "what we implemented": if we implemented
    # less the descriptor would still say the same thing.
    "links": ["USB full-speed device (EP0 control + IN 0x81/0x82/0x83)"],
    "count": 1,
    "m5_defined": False,
    "why": "one bus, one peer; interfaces 0/1/2 are wIndex values on the same "
           "EP0 dispatcher, not separate links",
}


def grade(res: Dict) -> Tuple[str, Dict[str, bool]]:
    """Walk the ladder and return (milestone, per-rung truth)."""
    met = {rung: bool(res.get(key)) for rung, key in LADDER}
    milestone = "M0"
    for rung, key in LADDER:
        if not res.get(key):
            break
        milestone = rung
    return milestone, met


#: Keys too bulky (or too noisy) for a one-line RESULT:. Everything else is
#: emitted -- see the note in ``main``.
RESULT_BULK = {"descriptors", "stages", "console", "log",
               "adversarial_detail", "control_description"}


def ladder_report(res: Dict) -> str:
    """A human-readable rung table for the ``ladder`` subcommand."""
    lines = ["", "LADDER (rung derived from evidence, never written down)"]
    met = res.get("rungs_met") or {}
    for rung, key in LADDER:
        lines.append("  %-3s %-30s %s" % (rung, key,
                                          "PASS" if met.get(rung) else "--"))
    inv = res.get("interfaces") or INTERFACE_INVENTORY
    lines.append("  M5/M8 undefined: %d interface -- %s"
                 % (inv["count"], inv["why"]))
    lines.append("  evidence: idle %s/%s rounds, %s distinct states -> %s "
                 "distinct replies; protocol 0x%02X->0x%02X; adversarial "
                 "%s/%s refused; known-good after fuzz %s"
                 % (res.get("idle_passed"), res.get("idle_rounds"),
                    res.get("idle_distinct_states"),
                    res.get("idle_distinct_replies"),
                    res.get("protocol_before", 0), res.get("protocol_after", 0),
                    res.get("adversarial_refused"),
                    res.get("adversarial_cases"),
                    res.get("known_good_after_fuzz")))
    lines.append("  MILESTONE: %s" % res.get("milestone"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None,
               control: str = "none") -> Dict:
    """Boot the device, run the attack, verify from firmware-side evidence."""
    if control not in CONTROLS:
        raise ValueError("unknown control mode %r; valid modes are %s"
                         % (control, ", ".join(sorted(CONTROLS))))

    def stage(name: str, **data) -> None:
        if on_stage:
            on_stage(name, **data)

    res: Dict = {"booted": False, "landed": False, "control": control,
                 "usb_hid_control_round_trip": False, "milestone": "M0",
                 "control_description": CONTROLS[control], "stages": []}
    stage("mode", control=control, description=CONTROLS[control])

    port = spawn.BRIDGE_PORT
    nonce = spawn.new_nonce()
    log_dir = log_dir or os.environ.get("HAL_PLANCK_LOG_DIR") or "."
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "planck-attack.log")

    extra = {"HAL_PLANCK_NO_USB_IRQ": "1"} if control == "no-usb-irq" else None
    env = spawn.spawn_env(extra=extra, nonce=nonce, bridge_port=port)
    argv = spawn.spawn_argv()
    proc = None
    bridge = Bridge(port)
    installed: List = []

    def _bail(signum, frame):        # noqa: ANN001 - signal handler
        raise KeyboardInterrupt

    try:
        # Inside the try, so a refusal still produces exactly one RESULT line
        # rather than a traceback (the fleet contract is a parseable verdict,
        # including when the verdict is "I will not grade this run").
        if "preflight" in AUDIT_SKIP:
            stage("preflight", skipped=True,
                  detail="LAYER 0 DELIBERATELY DISABLED by "
                         "HAL_PLANCK_AUDIT_SKIP -- this is the audit "
                         "configuration, never a normal run")
        else:
            preflight(port)
            stage("preflight", port=port,
                  detail="tcp/%d is free on both 0.0.0.0 and 127.0.0.1 (bind "
                         "probe, no SO_REUSEADDR)" % port)

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                installed.append((sig, signal.getsignal(sig)))
                signal.signal(sig, _bail)
            except (ValueError, OSError):
                pass

        with open(log_path, "w") as fh:
            proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                                    stdout=fh, stderr=subprocess.STDOUT)
        stage("spawn", pid=proc.pid, log=log_path,
              argv=" ".join(os.path.basename(a) if i == 0 else a
                            for i, a in enumerate(argv)))

        deadline = time.time() + BOOT_TIMEOUT
        bridge.connect(deadline)
        stage("connected", greeting=bridge.greeting)

        # layer 2: whose guest is this?
        bridge.check_identity(proc.pid, nonce)
        stage("identity", pid=proc.pid,
              detail="the bridge greeted with this run's child pid AND this "
                     "run's per-spawn nonce")

        # layer 1: our own child's bind marker
        if "bindmarker" in AUDIT_SKIP:
            stage("bind-marker", skipped=True,
                  detail="LAYER 1 DELIBERATELY DISABLED by "
                         "HAL_PLANCK_AUDIT_SKIP")
        else:
            _check_bind_marker(log_path, proc.pid, port)
            stage("bind-marker",
                  detail="the child logged HOST-BRIDGE-BOUND tcp/%d pid=%d "
                         "and no bind failure" % (port, proc.pid))

        res["booted"] = True

        # -- enumeration ---------------------------------------------------
        wanted = ["device", "config", "report0", "report1", "report2",
                  "string1", "string2"]
        enum_deadline = time.time() + ENUM_TIMEOUT
        have: Dict[str, bytes] = {}
        while time.time() < enum_deadline:
            state = bridge.cmd("STATE", enum_deadline)
            names = state.split("descriptors=")[-1].split(",")
            if all(w in names for w in wanted):
                break
            time.sleep(1.0)
        else:
            raise Refused("the firmware never produced a full descriptor set "
                          "(last STATE: %s)" % state)
        for name in wanted:
            reply = bridge.cmd("DESC %s" % name, enum_deadline)
            if not reply.startswith("DESC "):
                raise Refused("the firmware did not return %s (%s)"
                              % (name, reply))
            have[name] = bytes.fromhex(reply.split()[2])
        stage("enumerated", descriptors=len(have))

        # -- provenance: the STATIC half -----------------------------------
        mismatches = []
        for name, body in sorted(have.items()):
            predicted = facts.descriptor(name)
            if body != predicted:
                mismatches.append((name, predicted.hex(), body.hex()))
        res["descriptor_match"] = not mismatches
        res["descriptors"] = {k: v.hex() for k, v in sorted(have.items())}
        if mismatches:
            stage("provenance-static", ok=False, mismatches=mismatches)
        else:
            stage("provenance-static", ok=True,
                  detail="all %d descriptors match the bytes predicted in "
                         "PROVENANCE.md before the first boot -- device "
                         "%s, config %d B, report descriptors %s"
                         % (len(have), have["device"].hex(),
                            len(have["config"]),
                            "/".join(str(len(have["report%d" % i]))
                                     for i in range(3))))

        # -- provenance: the LIVE half, and the M6 differential -------------
        # The identity guard floors at MIN_LADDER_ROUNDS whatever the knob
        # says: LADDER_ROUNDS=0 is the empty-list demonstration for the
        # ADVERSARIAL counters, not a licence to skip layer 3.
        idle = _live_challenge(bridge, enum_deadline, stage,
                               rounds=max(LADDER_ROUNDS, MIN_LADDER_ROUNDS),
                               constant=(control == "idle-constant"))
        live_ok = idle["ok"]
        res["live_challenge"] = live_ok
        res["idle_rounds"] = idle["rounds"]
        res["idle_passed"] = idle["passed"]
        res["idle_distinct_states"] = idle["distinct_states"]
        res["idle_distinct_replies"] = idle["distinct_replies"]
        res["idle_stateful"] = idle["stateful"]
        if not live_ok:
            raise Refused("the peer failed the live SET_IDLE/GET_IDLE "
                          "challenge -- it is not running this firmware")

        # -- baseline ------------------------------------------------------
        deadline = time.time() + 120
        kind, data = ctrl(bridge, *GET_PROTOCOL, 0x0000, 0x0000, 1, deadline)
        if kind != "ok" or len(data) != 1:
            raise Refused("GET_PROTOCOL did not answer (%s %r)" % (kind, data))
        before = data[0]
        res["protocol_before"] = before
        stage("baseline", protocol=before,
              detail="the firmware reports protocol 0x%02X (PROVENANCE.md "
                     "predicted 0x01 from the .data initialiser image)"
                     % before)

        # -- the attack ----------------------------------------------------
        if control == "withhold":
            stage("attack-withheld",
                  detail="SET_PROTOCOL deliberately NOT sent")
        elif control == "wrong-interface":
            kind, _ = ctrl(bridge, *SET_PROTOCOL, 0x0000, 0x0001, 0, deadline)
            stage("attack-wrong-interface", result=kind,
                  detail="SET_PROTOCOL sent to interface 1 only; the firmware "
                         "requires wIndex == 0")
        else:
            kind, _ = ctrl(bridge, *SET_PROTOCOL, 0x0000, 0x0000, 0, deadline)
            res["set_protocol_result"] = kind
            stage("attack", result=kind,
                  detail="SET_PROTOCOL(0) -> interface 0: an unauthenticated "
                         "HID class request, no confirmation, no indication")

        kind, data = ctrl(bridge, *GET_PROTOCOL, 0x0000, 0x0000, 1, deadline)
        if kind != "ok" or len(data) != 1:
            raise Refused("GET_PROTOCOL did not answer after the attack")
        after = data[0]
        res["protocol_after"] = after
        stage("verify", protocol=after,
              detail="the firmware now reports protocol 0x%02X" % after)

        # -- negative controls ---------------------------------------------
        # NEGATIVE CONTROL 1 -- and note what the firmware ACTUALLY does.
        # PROVENANCE.md predicted this would be *refused*. It is not: the
        # dispatcher at 0x08007176 branches to the zero-length-reply path,
        # not to the not-handled path, so the request is ACCEPTED at the
        # protocol level and simply never reaches `set_keyboard_protocol`.
        # The load-bearing half of the prediction -- that the protocol byte
        # is UNCHANGED -- holds exactly. See PROVENANCE.md §6.
        rej1_kind, _ = ctrl(bridge, *SET_PROTOCOL, 0x0001, 0x0001, 0, deadline)
        kind, data = ctrl(bridge, *GET_PROTOCOL, 0x0000, 0x0000, 1, deadline)
        unchanged = (kind == "ok" and len(data) == 1 and data[0] == after)
        res["wrong_interface_reply"] = rej1_kind
        res["reject_wrong_interface"] = unchanged
        stage("negative-control-1", result=rej1_kind, unchanged=unchanged,
              detail="SET_PROTOCOL(1) addressed to interface 1 must NOT change "
                     "the protocol byte (the firmware accepts the request and "
                     "silently ignores it -- it does not STALL; see "
                     "PROVENANCE.md §6)")

        rej2_kind, rej2 = ctrl(bridge, 0x81, 0x06, 0x2200, 0x0003, 0x40,
                               deadline)
        res["reject_bad_report_index"] = (rej2_kind != "ok" or not rej2)
        stage("negative-control-2", result=rej2_kind, length=len(rej2),
              detail="GET_DESCRIPTOR(REPORT, interface 3) must not produce a "
                     "descriptor -- there are only three HID interfaces")

        # -- the console, as a second firmware-side witness -----------------
        reply = bridge.cmd("CONSOLE", deadline)
        console = bytes.fromhex(reply.split(maxsplit=1)[1]) if " " in reply \
            else b""
        res["console"] = console.decode("ascii", "replace")
        if console:
            stage("console", text=res["console"],
                  detail="bytes the firmware transmitted on its QMK console "
                         "endpoint (interface 2, EP 0x83)")

        # -- the verdict ---------------------------------------------------
        expected_after = before if control in ("withhold", "wrong-interface") \
            else 0x00
        changed = (after == expected_after)
        landed = bool(
            res["booted"]
            and res["descriptor_match"]
            and res["live_challenge"]
            and before == 0x01
            and res["reject_wrong_interface"]
            and res["reject_bad_report_index"]
            and control == "none"
            and after == 0x00)
        # THE SEAM: USB control transfers. SET_IDLE with a byte chosen at run
        # time came back out of GET_IDLE through the firmware's own handler,
        # GET_PROTOCOL answered, and the report descriptors were transmitted by
        # the firmware. No recorded transcript can satisfy the live challenge.
        res["usb_hid_control_round_trip"] = bool(
            res["live_challenge"] and res["descriptor_match"]
            and before in (0x00, 0x01))
        res["landed"] = landed and res["usb_hid_control_round_trip"]
        res["protocol_downgraded"] = (before == 0x01 and after == 0x00)

        # -- M7: adversarial input, then known-good traffic again -----------
        adv = _adversarial(bridge, deadline, stage, LADDER_ROUNDS, after,
                           benign=(control == "fuzz-benign"))
        res["adversarial_cases"] = adv["cases"]
        res["adversarial_refused"] = adv["refused"]
        res["adversarial_detail"] = adv["kinds"]
        res["known_good_after_fuzz"] = "%d/%d" % (adv["recheck_passed"],
                                                  adv["recheck_rounds"])
        res["adversarial_tolerated"] = adv["ok"]

        # -- M6: the same request, two states, two different right answers --
        # TWO independent differentials on the one seam, and BOTH are
        # required, so each has its own knob: `idle-constant` kills the first
        # and `withhold` kills the second, and neither touches M4.
        res["stateful_readback"] = bool(res["idle_stateful"]
                                        and res["protocol_downgraded"])

        # -- the rung, DERIVED ----------------------------------------------
        res["milestone"], res["rungs_met"] = grade(res)
        res["interfaces"] = INTERFACE_INVENTORY
        stage("verdict", landed=landed, before=before, after=after,
              as_expected=changed, milestone=res["milestone"],
              detail="rung derived from the ladder, not written down: " +
                     " ".join("%s=%s" % (r, res["rungs_met"][r])
                              for r, _ in LADDER))
        return res
    except Refused as exc:
        res["refused"] = str(exc)
        res["landed"] = False
        res["milestone"], res["rungs_met"] = grade(res)
        stage("refused", reason=str(exc), milestone=res["milestone"])
        return res
    except KeyboardInterrupt:
        res["refused"] = "interrupted"
        res["landed"] = False
        res["milestone"], res["rungs_met"] = grade(res)
        return res
    finally:
        bridge.close()
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(10)
            except Exception:          # noqa: BLE001
                proc.kill()
        for sig, prev in installed:
            try:
                signal.signal(sig, prev)
            except (ValueError, OSError):
                pass
        res["log"] = log_path


def _check_bind_marker(log_path: str, pid: int, port: int) -> None:
    """Layer 1: our own child must have got the socket, and said so.

    Necessary but NOT sufficient: against a wildcard-bound impostor the real
    bridge still binds and still logs this line, so this guard passes while the
    client talks to somebody else. Layer 2 is what closes that.
    """
    want = "HOST-BRIDGE-BOUND tcp/%d pid=%d" % (port, pid)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with open(log_path, "rb") as fh:
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            text = ""
        if "HOST-BRIDGE-BIND-FAILED" in text:
            raise Refused("our own emulator could NOT bind tcp/%d -- anything "
                          "answering on it is not this run's guest" % port)
        if want in text:
            return
        time.sleep(0.5)
    raise Refused("our own emulator never logged %r" % want)


def _live_challenge(bridge: Bridge, deadline: float, stage,
                    rounds: int = 3, constant: bool = False) -> Dict:
    """Layer 3 *and* the M6 evidence: the same request, N different states.

    QMK's `SET_IDLE` handler (`0x08007194` -> `set_keyboard_idle`, storing at
    `0x20000EE5`) takes the duration from **wValue's high byte**, and
    `GET_IDLE` reads the same variable back. So a byte picked at run time,
    pushed through the firmware's own handler and read back, is a challenge no
    recorded transcript can satisfy -- unlike the descriptor match, which is
    replayable by construction.

    That is also, exactly, M6: **one byte-identical request** (`GET_IDLE`,
    wValue/wIndex/wLength all zero) asked at N different firmware states,
    answering N different correct values that only the firmware's own store
    can produce. The values are drawn WITHOUT replacement so a chance
    collision cannot silently collapse two states into one, and the count of
    distinct replies is asserted against the count of distinct states.

    ``constant=True`` is the M6 falsification knob: identical input every
    round. The round trip still passes; the differential must not.
    """
    out: Dict = {"rounds": 0, "passed": 0, "ok": False, "sent": [], "got": [],
                 "distinct_states": 0, "distinct_replies": 0,
                 "stateful": False, "constant_knob": constant}
    fixed = secrets.randbelow(255) + 1
    used: set = set()
    for _ in range(max(0, rounds)):
        if constant:
            want = fixed
        else:
            while True:
                want = secrets.randbelow(255) + 1
                if want not in used:
                    break
            used.add(want)
        out["rounds"] += 1
        kind, _ = ctrl(bridge, *SET_IDLE, want << 8, 0x0000, 0, deadline)
        if kind != "ok":
            stage("live-challenge", ok=False,
                  detail="SET_IDLE was not accepted (%s)" % kind)
            out["sent"].append(want)
            out["got"].append(None)
            break
        kind, data = ctrl(bridge, *GET_IDLE, 0x0000, 0x0000, 1, deadline)
        got = data[0] if (kind == "ok" and len(data) == 1) else None
        out["sent"].append(want)
        out["got"].append(got)
        if got != want:
            stage("live-challenge", ok=False, sent=want, got=got)
            break
        out["passed"] += 1

    # N of N, with a floor. `passed == rounds` alone is satisfied by 0 == 0.
    out["ok"] = (out["rounds"] >= MIN_LADDER_ROUNDS
                 and out["passed"] == out["rounds"])
    out["distinct_states"] = len(set(out["sent"]))
    out["distinct_replies"] = len({g for g in out["got"] if g is not None})
    # M6: two DIFFERENT states must give two DIFFERENT correct answers.
    out["stateful"] = bool(out["ok"]
                           and out["distinct_states"] >= 2
                           and out["distinct_replies"] == out["distinct_states"])
    if out["ok"]:
        ctrl(bridge, *SET_IDLE, 0x0000, 0x0000, 0, deadline)
        stage("live-challenge", ok=True, rounds=out["rounds"],
              distinct_states=out["distinct_states"],
              distinct_replies=out["distinct_replies"],
              detail="%d of %d run-time-chosen bytes were stored and read "
                     "back through QMK's own SET_IDLE/GET_IDLE handlers; the "
                     "byte-identical GET_IDLE answered %d distinct values "
                     "from %d distinct states"
                     % (out["passed"], out["rounds"],
                        out["distinct_replies"], out["distinct_states"]))
    else:
        stage("live-challenge", ok=False, rounds=out["rounds"],
              passed=out["passed"],
              detail="the N-of-N idle challenge did not pass (floor is %d "
                     "rounds)" % MIN_LADDER_ROUNDS)
    return out


def _adversarial(bridge: Bridge, deadline: float, stage, rounds: int,
                 protocol_after: int, benign: bool = False) -> Dict:
    """M7: malformed EP0 traffic refused, then known-good traffic re-checked.

    Three *kinds* of malformed request, each issued ``rounds`` times with a
    different out-of-range index, so no single lucky refusal can carry the
    rung:

    * ``GET_DESCRIPTOR(HID REPORT, wIndex = 3, 4, 5 ...)`` -- there are three
      HID interfaces; `0x08007678` does ``cmp r1,#2 ; bhi`` and takes the
      not-handled path.
    * ``GET_DESCRIPTOR(STRING, index 0x40+)`` -- past the firmware's string
      table.
    * an **unassigned HID class request** (``bRequest`` 0x0C, 0x0D ...): not in
      QMK's dispatcher at all.

    The oracle is "the firmware produced no payload". A bridge-level *error*
    (`CTRL-TIMEOUT`) is NOT a refusal and is counted as a failure, because a
    guest that has gone deaf would otherwise read as a guest that refuses.

    Afterwards -- and this is the half that is missing from most of the fleet's
    M7-shaped probes -- the known-good requests are re-issued and matched
    **byte for byte** against what the same firmware answered before the
    malformed traffic.

    ``benign=True`` is the M7 falsification knob: same code path, same counts,
    but every index is swapped for a VALID one the firmware does answer. The
    refusal oracle must then go false, which is what shows it discriminates.
    """
    out: Dict = {"cases": 0, "refused": 0, "kinds": [], "benign_knob": benign,
                 "recheck_rounds": 0, "recheck_passed": 0,
                 "refusals_ok": False, "known_good_ok": False, "ok": False,
                 "baseline_matches_image": False}
    n = max(0, rounds)

    # The known-good baseline, taken through the SAME `ctrl` path the recheck
    # will use, and independently anchored to the bytes predicted from the
    # image before the first boot -- so "still works afterwards" is not merely
    # "still self-consistent afterwards".
    known_good: Dict[str, bytes] = {}
    anchored = True
    for name, idx in (("report0", 0), ("report1", 1), ("report2", 2)):
        kind, data = ctrl(bridge, *GET_DESCRIPTOR, DESC_REPORT << 8, idx,
                          0x0100, deadline)
        known_good[name] = data if kind == "ok" else b""
        if not data or data != facts.descriptor(name):
            anchored = False
    out["baseline_matches_image"] = anchored
    for i in range(n):
        cases = [
            ("report-index-%d" % (3 + i),
             (GET_DESCRIPTOR[0], GET_DESCRIPTOR[1],
              (DESC_REPORT << 8), 0 if benign else (3 + i), 0x40)),
            ("string-index-%d" % (0x40 + i),
             (GET_DESCRIPTOR[0], GET_DESCRIPTOR[1],
              (DESC_STRING << 8) | (1 if benign else (0x40 + i)), 0x0409, 0x40)),
            ("class-request-0x%02X" % (0x02 if benign else 0x0C + i),
             (0xA1, 0x02 if benign else 0x0C + i, 0x0000, 0x0000, 1)),
        ]
        for name, (bm, req, val, idx, length) in cases:
            kind, data = ctrl(bridge, bm, req, val, idx, length, deadline)
            refused = (kind == "stall") or (kind == "ok" and not data)
            out["cases"] += 1
            out["refused"] += 1 if refused else 0
            out["kinds"].append({"case": name, "reply": kind,
                                 "bytes": len(data), "refused": refused})

    # N of N with a floor -- and the floor is what stops `0 of 0` scoring.
    out["refusals_ok"] = (out["cases"] >= 3 * MIN_LADDER_ROUNDS
                          and out["refused"] == out["cases"])

    # ... and known-good traffic still works, byte for byte.
    for i in range(max(MIN_LADDER_ROUNDS, n)):
        out["recheck_rounds"] += 1
        ok = True
        for name, idx in (("report0", 0), ("report1", 1), ("report2", 2)):
            kind, data = ctrl(bridge, *GET_DESCRIPTOR, DESC_REPORT << 8, idx,
                              0x0100, deadline)
            if kind != "ok" or not data or data != known_good.get(name):
                ok = False
        kind, data = ctrl(bridge, *GET_PROTOCOL, 0x0000, 0x0000, 1, deadline)
        if kind != "ok" or len(data) != 1 or data[0] != protocol_after:
            ok = False
        want = secrets.randbelow(255) + 1
        kind, _ = ctrl(bridge, *SET_IDLE, want << 8, 0x0000, 0, deadline)
        if kind != "ok":
            ok = False
        kind, data = ctrl(bridge, *GET_IDLE, 0x0000, 0x0000, 1, deadline)
        if kind != "ok" or len(data) != 1 or data[0] != want:
            ok = False
        out["recheck_passed"] += 1 if ok else 0
    ctrl(bridge, *SET_IDLE, 0x0000, 0x0000, 0, deadline)

    out["known_good_ok"] = (out["recheck_rounds"] >= MIN_LADDER_ROUNDS
                            and out["recheck_passed"] == out["recheck_rounds"]
                            and out["baseline_matches_image"])
    out["ok"] = bool(out["refusals_ok"] and out["known_good_ok"])
    stage("adversarial", ok=out["ok"], cases=out["cases"],
          refused=out["refused"], recheck="%d/%d" % (out["recheck_passed"],
                                                     out["recheck_rounds"]),
          detail="%d malformed EP0 requests in three kinds, then %d rounds of "
                 "byte-identical known-good traffic%s"
                 % (out["cases"], out["recheck_rounds"],
                    "  [BENIGN KNOB: the indices are VALID, so the refusal "
                    "oracle must fail]" if benign else ""))
    return out


# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Boot the rehosted Planck rev6 and run the SET_PROTOCOL "
                    "downgrade against it.")
    ap.add_argument("--control", default="none",
                    help="negative-control mode: " +
                         "; ".join("%s = %s" % kv
                                   for kv in sorted(CONTROLS.items())))
    ap.add_argument("--log-dir", default=None)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--ladder", action="store_true",
                    help="also print the derived rung table (the RESULT line "
                         "carries the rung either way)")
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        # argparse already reported it; keep the contract "non-zero on a
        # mis-invocation" rather than silently running the real attack.
        return 2
    if args.control not in CONTROLS:
        print("ERROR: unknown --control %r; valid modes are: %s"
              % (args.control, ", ".join(sorted(CONTROLS))), file=sys.stderr)
        return 2

    def show(name: str, **data) -> None:
        if args.quiet:
            return
        detail = data.pop("detail", "")
        extras = " ".join("%s=%s" % kv for kv in data.items())
        print("[%-20s] %s%s" % (name, detail, ("  " + extras) if extras else ""))

    print("[mode] %s -- %s" % (args.control, CONTROLS[args.control]))
    if AUDIT_SKIP:
        print("[mode] WARNING: HAL_PLANCK_AUDIT_SKIP=%s -- identity guards "
              "are DELIBERATELY WEAKENED for an audit"
              % ",".join(sorted(AUDIT_SKIP)))
    res = run_attack(on_stage=show, log_dir=args.log_dir,
                     control=args.control)
    if args.ladder:
        print(ladder_report(res))
    # EMIT EVERYTHING that is not bulk. A fixed key tuple is exactly how this
    # device's M6/M7 evidence went unread for a month: `protocol_downgraded`,
    # `reject_wrong_interface` and `reject_bad_report_index` were all computed
    # and all dropped here. A deny-list of bulky keys cannot do that again.
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k not in RESULT_BULK}, sort_keys=True))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    sys.exit(main())
