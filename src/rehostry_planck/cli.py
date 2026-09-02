# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`rehostry-planck` CLI: boot the rehost, open the panel, or run the attack.

``run`` boots the firmware under HALucinator (unicorn) and streams its log to
stdout for ``--seconds``, then reaps only the process it started. ``panel``
and ``attack`` are thin wrappers over the two modules of the same name, so
there is one spawn recipe (:mod:`spawn`) behind all three.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

from . import paths, spawn


def _descendants(pid: int) -> list:
    out: list = []
    try:
        kids = subprocess.run(["pgrep", "-P", str(pid)],
                              capture_output=True, text=True).stdout.split()
    except (OSError, ValueError):
        kids = []
    for k in kids:
        out.extend(_descendants(int(k)))
        out.append(int(k))
    return out


def _kill_tree(proc: subprocess.Popen) -> None:
    # Kill ONLY the PIDs we started, via the Popen handle. NEVER `pkill -f
    # halucinator`: a global pattern kill takes out other sessions' emulators,
    # and the victim sees rc=-15 with no fault in its log -- indistinguishable
    # from a clean timeout, so it gets misread as a firmware result (playbook
    # trap 10).
    for sig in (signal.SIGTERM, signal.SIGKILL):
        # Signal the whole SESSION we created (the spawn passes setsid /
        # start_new_session, so the child IS the group leader and the group id
        # is proc.pid). The halucinator emulator is a GRANDCHILD: killing only
        # the direct child leaves it alive, reparented to init, still holding
        # the guest's port and burning a core.
        #
        # proc.pid is used directly rather than os.getpgid(proc.pid): getpgid
        # raises ProcessLookupError as soon as the direct child is reaped, and
        # that is exactly the case where the grandchild is still running and
        # most needs the signal. The descendant walk below races the same
        # reparenting -- once the grandchild's parent is gone, `pgrep -P` no
        # longer lists it under our pid -- so it is kept only as a fallback for
        # a child that never got its own session.
        # Still only PIDs WE started. NEVER a pattern kill.
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        pids = _descendants(proc.pid) + [proc.pid]
        for p in pids:
            try:
                os.kill(p, sig)
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue


def cmd_run(args: argparse.Namespace) -> int:
    if not paths.firmware_present():
        print("firmware not found at %s" % paths.firmware_bin(),
              file=sys.stderr)
        print("  regenerate it with tools/extract_firmware.py -- the image is "
              "NOT committed (QMK is GPLv2; see PROVENANCE.md)",
              file=sys.stderr)
        return 1

    argv = spawn.spawn_argv(emulator=args.emulator)
    env = spawn.spawn_env(nonce=spawn.new_nonce(), bridge_port=args.port)

    print("[rehostry-planck] booting: %s" % " ".join(argv))
    print("[rehostry-planck] cwd=%s (configs from the installed package)"
          % spawn.spawn_cwd())
    print("[rehostry-planck] USB bridge on tcp/%d -- seam: %s"
          % (args.port, spawn.USB_SEAM))

    proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    deadline = time.monotonic() + args.seconds
    try:
        assert proc.stdout is not None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                for line in proc.stdout:
                    sys.stdout.write(line)
                print("[rehostry-planck] HALucinator exited early.",
                      file=sys.stderr)
                return proc.returncode or 1
            line = proc.stdout.readline()
            if line:
                sys.stdout.write(line)
            else:
                time.sleep(0.05)
        print("[rehostry-planck] ran for %.0fs; tearing down." % args.seconds)
        return 0
    finally:
        _kill_tree(proc)


def cmd_attack(args: argparse.Namespace) -> int:
    from . import attack
    return attack.main(["--control", args.control] +
                       (["--log-dir", args.log_dir] if args.log_dir else []))


def cmd_ladder(args: argparse.Namespace) -> int:
    """Run the graded ladder and print the rung it derives.

    Same run as ``attack``; the difference is that the rung table is printed
    as well. The rung itself is on the ``RESULT:`` line in both cases -- the
    ladder is not an opt-in mode, because a device whose default RESULT says
    ``M4`` while an opt-in flag says ``M7`` is exactly the ceiling this was
    added to remove.
    """
    from . import attack
    return attack.main(["--control", args.control, "--ladder"] +
                       (["--log-dir", args.log_dir] if args.log_dir else []))


def cmd_panel(args: argparse.Namespace) -> int:
    from . import planck_panel
    return planck_panel.main(["--http-port", str(args.http_port)])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="rehostry-planck",
        description="Standalone rehosted OLKB/Drop Planck rev6 "
                    "(STM32F303 / QMK on ChibiOS) for HALucinator.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="boot the firmware and stream its log")
    r.add_argument("--seconds", type=float, default=60.0)
    r.add_argument("--emulator", default="unicorn")
    r.add_argument("--port", type=int, default=spawn.BRIDGE_PORT,
                   help="USB bridge TCP port (default %d)" % spawn.BRIDGE_PORT)
    r.set_defaults(func=cmd_run)

    a = sub.add_parser("attack", help="run the SET_PROTOCOL downgrade")
    a.add_argument("--control", default="none")
    a.add_argument("--log-dir", default=None)
    a.set_defaults(func=cmd_attack)

    from . import attack as _attack
    lad = sub.add_parser(
        "ladder",
        help="run the graded ladder and print the rung it derives",
        description="Derives the milestone from the evidence. Controls: " +
                    "; ".join("%s = %s" % kv
                              for kv in sorted(_attack.CONTROLS.items())))
    lad.add_argument("--control", default="none")
    lad.add_argument("--log-dir", default=None)
    lad.set_defaults(func=cmd_ladder)

    w = sub.add_parser("panel", help="serve the web panel")
    w.add_argument("--http-port", type=int, default=8892)
    w.set_defaults(func=cmd_panel)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
