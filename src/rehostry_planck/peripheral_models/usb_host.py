# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A minimal USB **host**, because a USB device does nothing until plugged in.

THIS IS THE SEAM. A keyboard has no console, no UART and no network; its entire
externally-reachable surface is the USB wire, and on that wire it is the
*passive* end. Nothing happens until a host drives a bus reset and enumerates it
(playbook trap 80), so reaching anything interesting in this firmware means
implementing the other end: bus reset, ``GET_DESCRIPTOR``, ``SET_ADDRESS``,
``SET_CONFIGURATION``, and then HID class traffic on endpoint 0 plus the three
interrupt IN endpoints the firmware declares.

HOW A PACKET MOVES on the STM32 USB device peripheral (RM0316 §30):

  * ``BTABLE`` points into packet memory at four halfwords per endpoint:
    ``ADDR_TX``, ``COUNT_TX``, ``ADDR_RX``, ``COUNT_RX``.
  * To give the device a packet: write the bytes into PMA at ``ADDR_RX``, put
    the length in the low 10 bits of ``COUNT_RX`` (**preserving** the
    buffer-size bits 15:10, which the firmware programmed and still needs), set
    ``CTR_RX`` (plus ``SETUP`` for a setup packet) and raise the USB interrupt.
  * To take a packet from the device: it has set ``STAT_TX = VALID``; read
    ``COUNT_TX`` bytes from PMA at ``ADDR_TX``, then set ``CTR_TX``.

THE ENDPOINTS ARE READ OUT OF THE FIRMWARE'S OWN CONFIGURATION DESCRIPTOR, never
assumed: the host fetches the descriptor during enumeration and parses its
endpoint descriptors, so a firmware that moves an interface fails loudly instead
of silently writing into the wrong buffer.

THE STATE MACHINE RUNS FROM A SAFE CONTEXT. :meth:`step` is called by the
interrupt pump at ChibiOS' idle ``wfi``, never from an MMIO callback -- injecting
an exception from inside a store abandons the un-retired instruction (playbook
traps 48 / 95).

START-OF-FRAME IS LOAD-BEARING. QMK's ChibiOS transport buffers console output
in a queue and hands it to the endpoint from ``qmkusbSOFHookI()``, i.e. from the
host's 1 ms frame clock. Model enumeration perfectly and forget SOF and the
firmware composes ``USB configured.`` and then sits on it for ever -- which
reads exactly like a device that has decided not to talk (playbook traps 70 /
141 / 162).

WHOSE GUEST IS THIS?
--------------------

The bridge below is an *oracle*, so it has to be able to say **whose** firmware
answered. Two independent halves, because either alone is weak (playbook traps
168 / 182 / 210):

* **which process** -- the parent generates a per-spawn nonce, passes it to the
  child by environment, and the bridge greets every client
  ``HELLO pid=<pid> device=planck-rev6-stm32f303 nonce=<hex>``. A scraped pid is
  replayable in principle; a per-spawn nonce is not.
* **is it actually running the firmware** -- served by the ``CTRL`` command: the
  client picks a byte it has never used before, has the *guest* store it through
  QMK's own ``SET_IDLE`` handler and read it back through ``GET_IDLE``, and
  checks the answer. A recorded transcript cannot satisfy a fresh challenge.

The bridge binds **127.0.0.1** (never the wildcard) with **no** ``SO_REUSEADDR``
and logs its own pid on success, so a stale or foreign listener is visible
rather than silently graded.
"""
from __future__ import annotations

import os
import queue
import socket
import struct
import threading
from typing import Any, Dict, List, Optional, Tuple

from halucinator import hal_log

log = hal_log.getHalLogger()

STAT_DISABLED, STAT_STALL, STAT_NAK, STAT_VALID = 0, 1, 2, 3

# Standard requests.
GET_DESCRIPTOR = 6
SET_ADDRESS = 5
SET_CONFIGURATION = 9

DESC_DEVICE, DESC_CONFIG, DESC_STRING = 1, 2, 3
DESC_HID, DESC_REPORT = 0x21, 0x22

#: HID class requests (RM: HID 1.11 §7.2).
HID_GET_REPORT, HID_GET_IDLE, HID_GET_PROTOCOL = 0x01, 0x02, 0x03
HID_SET_REPORT, HID_SET_IDLE, HID_SET_PROTOCOL = 0x09, 0x0A, 0x0B

#: The address this host assigns.
DEVICE_ADDRESS = 4

_HOST: Optional["UsbHost"] = None


def get_host() -> "UsbHost":
    """The single host driving this device (created on first use)."""
    global _HOST
    if _HOST is None:
        _HOST = UsbHost()
        port = os.environ.get("HAL_PLANCK_BRIDGE_PORT")
        if port:
            _HOST.start_bridge(int(port))
    return _HOST


class ControlRequest:
    """One queued control transfer, and the answer the firmware gave."""

    def __init__(self, setup: bytes, out_data: bytes = b"") -> None:
        self.setup = setup
        self.out_data = out_data
        self.want = struct.unpack_from("<H", setup, 6)[0]
        self.dir_in = bool(setup[0] & 0x80)
        self.data = bytearray()
        self.stalled = False
        self.done = threading.Event()

    def __repr__(self) -> str:     # pragma: no cover - diagnostics
        return "ControlRequest(%s)" % self.setup.hex(" ")


class UsbHost:
    """Bus reset, enumeration, HID class traffic, and the host-side bridge."""

    def __init__(self) -> None:
        self.state = "reset"
        self.pending_irq = False
        #: True once `start_bridge` has actually got the socket and called
        #: `listen`. PUBLISH-ONLY: nothing grades it. `bp_handlers/irq_pump`
        #: reads it so the `HAL_PLANCK_STALL_AFTER_BIND` control can park the
        #: guest at a point where the harness is fully alive -- which is the
        #: only arm that can tell a rung apart from a liveness check.
        self.bound = False
        self.configured = False
        self.enumerated = False
        self.vid_pid: Optional[Tuple[int, int]] = None
        #: Every descriptor the firmware transmitted, keyed by a short name.
        self.descriptors: Dict[str, bytes] = {}
        #: Interrupt IN endpoints, learned from the configuration descriptor.
        self.in_endpoints: List[Tuple[int, int, int]] = []   # (iface, ep, mps)
        #: Reports the firmware transmitted, per endpoint.
        self.reports: Dict[int, List[bytes]] = {}
        self.console = bytearray()
        self.report_count = 0
        self.sofs = 0
        self.pid = os.getpid()
        self.nonce = os.environ.get("HAL_PLANCK_NONCE", "")
        self._pending: List[ControlRequest] = []
        self._current: Optional[ControlRequest] = None
        self._queue: "queue.Queue[ControlRequest]" = queue.Queue()
        self._lock = threading.RLock()
        self._clients: list = []
        self._trace = os.environ.get("HAL_PLANCK_USB_TRACE") == "1"
        self._steps = 0

    # -- helpers over the device's packet memory ---------------------------
    @staticmethod
    def _btable_entry(usb, pma, ep: int):
        base = usb.btable()
        raw = pma.read_flat(base + ep * 8, 8)
        return struct.unpack("<HHHH", raw)   # addr_tx, cnt_tx, addr_rx, cnt_rx

    @staticmethod
    def _set_count_rx(pma, base: int, ep: int, length: int) -> None:
        off = base + ep * 8 + 6
        cur = struct.unpack("<H", pma.read_flat(off, 2))[0]
        # Preserve BL_SIZE/NUM_BLOCK (15:10); only the byte count is ours.
        pma.write_flat(off, struct.pack("<H", (cur & 0xFC00) | (length & 0x3FF)))

    def _give(self, usb, pma, ep: int, data: bytes, setup: bool = False) -> None:
        base = usb.btable()
        _, _, addr_rx, _ = self._btable_entry(usb, pma, ep)
        pma.write_flat(addr_rx, data)
        self._set_count_rx(pma, base, ep, len(data))
        usb.raise_ctr_rx(ep, setup=setup)
        self.pending_irq = True

    def _take(self, usb, pma, ep: int) -> bytes:
        addr_tx, count_tx, _, _ = self._btable_entry(usb, pma, ep)
        data = pma.read_flat(addr_tx, count_tx & 0x3FF)
        usb.raise_ctr_tx(ep)
        self.pending_irq = True
        return data

    # -- the state machine --------------------------------------------------
    def _enumeration(self) -> List[ControlRequest]:
        """The transfers a real host performs, in the order it performs them."""
        return [
            ControlRequest(b"\x80\x06\x00\x01\x00\x00\x12\x00"),   # DEVICE
            ControlRequest(bytes((0x00, SET_ADDRESS, DEVICE_ADDRESS,
                                  0, 0, 0, 0, 0))),
            ControlRequest(b"\x80\x06\x00\x02\x00\x00\x09\x00"),   # CONFIG hdr
        ]

    def step(self, usb, pma) -> bool:
        """Advance one transaction. Returns True if the USB IRQ should fire."""
        self._steps += 1
        self.pending_irq = False

        if self.state == "reset":
            usb.raise_reset()
            self.pending_irq = True
            self.state = "wait_ep0"
            log.info("UsbHost: driving a bus reset (the keyboard has been "
                     "'plugged in')")
            return True

        if self.state == "wait_ep0":
            # Wait until the firmware has CONFIGURED EP0 and enabled the USB
            # function -- NOT until STAT_RX reads VALID. A control endpoint
            # cannot NAK a SETUP: the hardware always accepts it and forces
            # STAT_RX to NAK afterwards, which is exactly the state correct
            # firmware leaves EP0 in after a reset. Waiting for VALID here
            # deadlocks against a device that is behaving properly.
            if usb.epr[0] != 0 and usb.daddr_enabled():
                log.info("UsbHost: the firmware opened EP0 -- enumerating")
                self._pending = self._enumeration()
                return self._next_transfer(usb, pma)
            return False

        if self.state == "data_in":
            if usb.ep_stat_tx(0) == STAT_VALID:
                pkt = self._take(usb, pma, 0)
                cur = self._current
                cur.data += pkt
                if len(pkt) < 64 or len(cur.data) >= cur.want:
                    self._decode(cur)
                    self.state = "status_out"
                return True
            if usb.ep_stat_tx(0) == STAT_STALL:
                return self._stalled(usb, pma)
            return False

        if self.state == "data_out":
            if usb.ep_stat_rx(0) == STAT_VALID:
                self._give(usb, pma, 0, self._current.out_data)
                self.state = "status_in"
                return True
            if usb.ep_stat_rx(0) == STAT_STALL:
                return self._stalled(usb, pma)
            return False

        if self.state == "status_out":
            if usb.ep_stat_rx(0) == STAT_VALID:
                self._give(usb, pma, 0, b"")        # zero-length OUT status
                self.state = "advance"
                return True
            return False

        if self.state == "status_in":
            if usb.ep_stat_tx(0) == STAT_VALID:
                self._take(usb, pma, 0)             # zero-length IN status
                self.state = "advance"
                return True
            if usb.ep_stat_tx(0) == STAT_STALL:
                return self._stalled(usb, pma)
            return False

        if self.state == "advance":
            cur, self._current = self._current, None
            if cur is not None:
                cur.done.set()
            # ONE transaction per step. Completing a stage and starting the
            # next transfer in the same step never lets the firmware run in
            # between -- SET_ADDRESS only writes DADDR *after* its status
            # stage -- and the second notification overwrites the first in
            # ISTR.
            return self._next_transfer(usb, pma)

        if self.state == "configured":
            if self._drain_in(usb, pma):
                return True
            return self._next_transfer(usb, pma)

        return False

    def _stalled(self, usb, pma) -> bool:
        """The firmware REFUSED the request. That is a result, not a failure.

        A device that answers everything is not discriminating, so the attack's
        negative controls depend on being able to see a STALL as a STALL.
        """
        cur = self._current
        if cur is not None:
            cur.stalled = True
            log.info("UsbHost: the firmware STALLed %s -- request REFUSED",
                     cur.setup.hex(" "))
        self.state = "advance"
        return True

    def sof(self, usb) -> bool:
        """Emit a Start-Of-Frame. Returns True if the firmware wants the IRQ."""
        self.sofs += 1
        want = usb.raise_sof()
        self.pending_irq = want
        return want

    # -- control transfers --------------------------------------------------
    def _next_transfer(self, usb, pma) -> bool:
        if not self._pending:
            try:
                while True:
                    self._pending.append(self._queue.get_nowait())
            except queue.Empty:
                pass
        if not self._pending:
            if not self.configured:
                self.configured = True
                self.enumerated = all(
                    n in self.descriptors
                    for n in ("device", "config", "report0", "report1",
                              "report2", "string1", "string2"))
                log.info("UsbHost: the device is CONFIGURED -- %d descriptors "
                         "collected, interrupt IN endpoints open: %s",
                         len(self.descriptors),
                         ", ".join("ep%d (iface %d, %d B)" % (e, i, m)
                                   for i, e, m in self.in_endpoints))
            self.state = "configured"
            return False
        cur = self._pending.pop(0)
        self._current = cur
        cur.data = bytearray()
        self._give(usb, pma, 0, cur.setup, setup=True)
        if cur.want and cur.dir_in:
            self.state = "data_in"
        elif cur.want:
            self.state = "data_out"
        else:
            self.state = "status_in"
        if self._trace or not self.configured:
            log.info("UsbHost: SETUP %s (%s)", cur.setup.hex(" "),
                     "expects %d data byte(s)" % cur.want if cur.want
                     else "no data stage")
        return True

    def submit(self, setup: bytes, out_data: bytes = b"",
               timeout: float = 20.0) -> ControlRequest:
        """Queue a control transfer and block until the firmware answers."""
        req = ControlRequest(setup, out_data)
        self._queue.put(req)
        req.done.wait(timeout)
        return req

    # -- decoding what the firmware sent ------------------------------------
    def _decode(self, cur: ControlRequest) -> None:
        setup, data = cur.setup, bytes(cur.data)
        if setup[1] != GET_DESCRIPTOR or (setup[0] & 0x60):
            return
        dtype, dindex = setup[3], setup[2]
        if dtype == DESC_DEVICE and len(data) >= 12:
            self.descriptors["device"] = data
            vid, pid = struct.unpack_from("<HH", data, 8)
            self.vid_pid = (vid, pid)
            log.info("UsbHost: device descriptor FROM THE FIRMWARE -- "
                     "VID:PID = %04X:%04X, %d bytes: %s",
                     vid, pid, len(data), data.hex(" "))
            return
        if dtype == DESC_CONFIG:
            if len(data) == 9:
                total = struct.unpack_from("<H", data, 2)[0]
                log.info("UsbHost: configuration descriptor is %d bytes; "
                         "fetching all of it", total)
                self._pending.insert(0, ControlRequest(
                    bytes((0x80, GET_DESCRIPTOR, 0, DESC_CONFIG, 0, 0,
                           total & 0xFF, total >> 8))))
                return
            self.descriptors["config"] = data
            log.info("UsbHost: configuration descriptor FROM THE FIRMWARE, "
                     "%d bytes: %s", len(data), data.hex(" "))
            self._parse_config(data)
            # Strings, then every HID report descriptor the config declares,
            # then SET_CONFIGURATION.
            follow = [ControlRequest(bytes((0x80, GET_DESCRIPTOR, 0,
                                            DESC_STRING, 0, 0, 0xFF, 0)))]
            for idx in (1, 2, 3):
                follow.append(ControlRequest(
                    bytes((0x80, GET_DESCRIPTOR, idx, DESC_STRING,
                           0x09, 0x04, 0xFF, 0))))
            for iface, length in self._report_lengths:
                follow.append(ControlRequest(
                    bytes((0x81, GET_DESCRIPTOR, 0, DESC_REPORT,
                           iface, 0, length & 0xFF, length >> 8))))
            follow.append(ControlRequest(bytes((0x00, SET_CONFIGURATION, 1,
                                                0, 0, 0, 0, 0))))
            self._pending[0:0] = follow
            return
        if dtype == DESC_STRING:
            self.descriptors["string%d" % dindex] = data
            text = ""
            try:
                text = data[2:].decode("utf-16-le")
            except UnicodeDecodeError:
                pass
            log.info("UsbHost: string descriptor %d FROM THE FIRMWARE: %s %s",
                     dindex, data.hex(" "), repr(text) if text else "")
            return
        if dtype == DESC_REPORT:
            iface = setup[4]
            self.descriptors["report%d" % iface] = data
            log.info("UsbHost: HID REPORT descriptor for interface %d FROM "
                     "THE FIRMWARE, %d bytes: %s", iface, len(data),
                     data.hex(" "))

    def _parse_config(self, desc: bytes) -> None:
        """Recover the interfaces, their report-descriptor lengths and their
        interrupt IN endpoints from the firmware's own configuration."""
        self._report_lengths: List[Tuple[int, int]] = []
        self.in_endpoints = []
        i, iface = 0, -1
        while i + 1 < len(desc):
            length, dtype = desc[i], desc[i + 1]
            if length == 0:
                break
            if dtype == 0x04:                                   # INTERFACE
                iface = desc[i + 2]
                log.info("UsbHost: interface %d: class 0x%02X subclass 0x%02X "
                         "protocol 0x%02X", iface, desc[i + 5], desc[i + 6],
                         desc[i + 7])
            elif dtype == DESC_HID and i + 9 <= len(desc):       # HID
                if desc[i + 6] == DESC_REPORT:
                    n = struct.unpack_from("<H", desc, i + 7)[0]
                    self._report_lengths.append((iface, n))
            elif dtype == 0x05 and i + 7 <= len(desc):          # ENDPOINT
                addr, attrs = desc[i + 2], desc[i + 3]
                mps = struct.unpack_from("<H", desc, i + 4)[0]
                if (attrs & 0x03) == 0x03 and (addr & 0x80):    # interrupt IN
                    self.in_endpoints.append((iface, addr & 0x0F, mps))
                log.info("UsbHost: endpoint 0x%02X attrs 0x%02X mps %d",
                         addr, attrs, mps)
            i += length
        if not self.in_endpoints:
            log.error("UsbHost: the configuration declares no interrupt IN "
                      "endpoint -- this firmware is not the HID device this "
                      "host was written for")

    # -- interrupt IN traffic ----------------------------------------------
    def _drain_in(self, usb, pma) -> bool:
        for iface, ep, _mps in self.in_endpoints:
            if usb.ep_stat_tx(ep) == STAT_VALID:
                data = self._take(usb, pma, ep)
                if not data:
                    return True
                self.report_count += 1
                with self._lock:
                    self.reports.setdefault(ep, []).append(bytes(data))
                    if iface == self._console_iface():
                        self.console += bytes(data).rstrip(b"\x00")
                log.info("UsbHost: %d-byte report FROM THE FIRMWARE on ep%d "
                         "(interface %d): %s", len(data), ep, iface,
                         bytes(data).hex(" "))
                return True
        return False

    def _console_iface(self) -> int:
        """QMK's console is the LAST HID interface; it is identified by its
        report descriptor's vendor usage page 0xFF31, not by its number."""
        for name, body in self.descriptors.items():
            if name.startswith("report") and body[:3] == b"\x06\x31\xff":
                return int(name[len("report"):])
        return -1

    def console_text(self) -> str:
        with self._lock:
            return bytes(self.console).decode("ascii", "replace")

    # -- host-side bridge ---------------------------------------------------
    def start_bridge(self, port: int) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Deliberately NO SO_REUSEADDR: a bind that "succeeds" over a stale or
        # foreign listener is how an attack ends up grading somebody else's
        # guest (playbook traps 12 / 154 / 168).
        try:
            srv.bind(("127.0.0.1", port))
        except OSError as exc:
            log.error("UsbHost: HOST-BRIDGE-BIND-FAILED tcp/%d (%s) -- nothing "
                      "will be injectable into this run", port, exc)
            return
        srv.listen(4)
        self.bound = True
        log.info("UsbHost: HOST-BRIDGE-BOUND tcp/%d pid=%d", port, self.pid)

        def accept_loop():
            while True:
                try:
                    conn, peer = srv.accept()
                except OSError:
                    return
                log.info("UsbHost: bridge client connected from %s", peer)
                threading.Thread(target=self._serve, args=(conn, peer),
                                 daemon=True).start()

        threading.Thread(target=accept_loop, daemon=True).start()

    def _serve(self, conn, peer) -> None:
        with self._lock:
            self._clients.append(conn)
        try:
            conn.sendall(("HELLO pid=%d device=planck-rev6-stm32f303 nonce=%s\n"
                          % (self.pid, self.nonce)).encode())
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    reply = self._command(line.decode("ascii", "replace").strip())
                    if reply is not None:
                        conn.sendall((reply + "\n").encode())
        except OSError:
            pass
        finally:
            with self._lock:
                if conn in self._clients:
                    self._clients.remove(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _command(self, line: str) -> Optional[str]:
        """The wire protocol. Everything it returns is the firmware's bytes."""
        if not line:
            return None
        parts = line.split()
        cmd = parts[0].upper()
        try:
            if cmd == "PING":
                return "PONG pid=%d nonce=%s" % (self.pid, self.nonce)
            if cmd == "STATE":
                return ("STATE enumerated=%d configured=%d reports=%d sofs=%d "
                        "descriptors=%s"
                        % (int(self.enumerated), int(self.configured),
                           self.report_count, self.sofs,
                           ",".join(sorted(self.descriptors))))
            if cmd == "DESC":
                if len(parts) < 2:
                    return "ERR usage: DESC <name>"
                body = self.descriptors.get(parts[1])
                if body is None:
                    return "NODESC %s" % parts[1]
                return "DESC %s %s" % (parts[1], body.hex())
            if cmd == "CONSOLE":
                with self._lock:
                    return "CONSOLE %s" % bytes(self.console).hex()
            if cmd == "REPORTS":
                with self._lock:
                    out = []
                    for ep, lst in sorted(self.reports.items()):
                        for r in lst:
                            out.append("%d:%s" % (ep, r.hex()))
                return "REPORTS %s" % " ".join(out)
            if cmd == "CTRL":
                # CTRL <bmRequestType> <bRequest> <wValue> <wIndex> <wLength>
                #      [out-data-hex]
                if len(parts) < 6:
                    return "ERR usage: CTRL bmType bReq wValue wIndex wLen [hex]"
                bm, br = int(parts[1], 0), int(parts[2], 0)
                wv, wi, wl = (int(parts[3], 0), int(parts[4], 0),
                              int(parts[5], 0))
                out = bytes.fromhex(parts[6]) if len(parts) > 6 else b""
                setup = struct.pack("<BBHHH", bm, br, wv, wi, wl)
                req = self.submit(setup, out)
                if not req.done.is_set():
                    return "CTRL-TIMEOUT"
                if req.stalled:
                    return "CTRL-STALL"
                return "CTRL-OK %s" % bytes(req.data).hex()
            if cmd in ("PRESS", "RELEASE"):
                from . import gpio_matrix
                m = gpio_matrix.get_matrix()
                if m is None:
                    return "ERR no matrix model"
                row, col = int(parts[1]), int(parts[2])
                (m.press if cmd == "PRESS" else m.release)(row, col)
                return "%s-OK %d %d" % (cmd, row, col)
            if cmd == "MATRIX":
                from . import gpio_matrix
                m = gpio_matrix.get_matrix()
                if m is None:
                    return "ERR no matrix model"
                return ("MATRIX scans=%d row_selects=%d col_reads=%d held=%s"
                        % (m.scans, m.row_selects, m.col_reads,
                           ";".join("%d,%d" % rc for rc in m.held())))
        except Exception as exc:                    # noqa: BLE001 - protocol
            return "ERR %s" % exc
        return "ERR unknown command %r" % cmd

