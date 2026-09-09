# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The boot rung must be a GUEST-EXECUTION rung, not a harness-liveness one.

Before 2026-09-08 `res["booted"] = True` sat behind four preconditions that all
RAISE -- a bind probe, a TCP connect, a greeting carrying our child's pid and
our per-run nonce, and a marker in our child's log. Every one of them is
enforced perfectly and every one of them is satisfied by OUR OWN side of the
wire. Live, with `HAL_PLANCK_STALL_AFTER_BIND=20`, that rung recorded
`booted: true, milestone: M1` for a CPU parked on a `b .`.

These tests pin the four properties the repair rests on, rather than restating
the repair (playbook w112.2: put the dependency in a test, not in a comment).
"""
from __future__ import annotations

import ast
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from rehostry_planck import attack                              # noqa: E402
from rehostry_planck.bp_handlers import irq_pump                # noqa: E402
from rehostry_planck.peripheral_models import gpio_matrix       # noqa: E402


def _source(path: str) -> str:
    with open(path, "r") as handle:
        return handle.read()


def _function(module, name: str) -> ast.FunctionDef:
    tree = ast.parse(_source(module.__file__))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError("no function %r in %s" % (name, module.__file__))


def _names_used(node: ast.FunctionDef) -> set:
    """Every identifier the function BODY mentions, docstring excluded.

    ⚠ Dropping the docstring is not tidiness. The first version of this test
    read the raw source and failed, because the helper's own docstring names
    `read_memory` and `read_register` in order to say that it does not use
    them -- a structural test refuted by its own prose (playbook w120.5). The
    same would happen to a comment, which `ast` also drops.
    """
    body = list(node.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    used = set()
    for stmt in body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name):
                used.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                used.add(sub.attr)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                used.add(sub.value)
    return used


BANNED = ("read_memory", "write_memory", "read_register", "write_register",
          "mem_read", "mem_write", "emu_start", "emu_stop", "_uc", "qemu",
          "backend")


def test_the_rung_helper_touches_no_emulator_handle():
    used = _names_used(_function(attack, "guest_is_executing"))
    assert not (used & set(BANNED)), sorted(used & set(BANNED))


def test_the_rung_helper_reads_only_the_bridges_MATRIX_command():
    used = _names_used(_function(attack, "guest_is_executing"))
    assert "MATRIX" in used
    assert "cmd" in used


def test_the_witness_has_exactly_one_writer_and_it_is_a_dispatch_thread_hook():
    """`col_reads` must be assigned in exactly one place, inside `hw_read`."""
    tree = ast.parse(_source(gpio_matrix.__file__))
    writers = []
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.AugAssign):
            targets = [node.target]
        elif isinstance(node, ast.Assign):
            targets = node.targets
        for tgt in targets:
            if isinstance(tgt, ast.Attribute) and tgt.attr == "col_reads":
                writers.append(node.lineno)
    inits = [ln for ln in writers if ln < _function(
        gpio_matrix, "hw_read").lineno]
    # one initialiser in __init__, one increment in hw_read, and nothing else
    assert len(writers) == 2, writers
    assert len(inits) == 1, writers
    enclosing = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for sub in ast.walk(node):
                if (isinstance(sub, ast.AugAssign)
                        and isinstance(sub.target, ast.Attribute)
                        and sub.target.attr == "col_reads"):
                    enclosing = node.name
    assert enclosing == "hw_read", enclosing


def test_no_thread_is_started_in_the_model_that_owns_the_witness():
    """The module may take a LOCK; it must not start a thread of its own.

    ⚠ The first version of this asserted `"threading" not in src` and failed,
    because the module imports `threading` for one `RLock`. An over-strict
    structural test is a false alarm about the code under it, which is the
    same failure mode as an over-loose one -- it just costs you an hour
    instead of a result.
    """
    tree = ast.parse(_source(gpio_matrix.__file__))
    started = [n for n in ast.walk(tree)
               if isinstance(n, ast.Call)
               and getattr(n.func, "attr", getattr(n.func, "id", None))
               == "Thread"]
    assert not started, [n.lineno for n in started]


def test_the_rung_requires_growth_not_merely_a_non_zero_count():
    """`n1 > 0` alone passes `HAL_PLANCK_STALL_AFTER_BIND=300` (`[218]`)."""
    src = ast.dump(_function(attack, "guest_is_executing"))
    assert "samples" in src
    # the deciding comparison must be strict growth between the two samples
    fn = _function(attack, "guest_is_executing")
    strict = [n for n in ast.walk(fn)
              if isinstance(n, ast.Compare)
              and any(isinstance(o, ast.Gt) for o in n.ops)]
    assert len(strict) >= 2, "expected both `n > 0` and `n > samples[0]`"


def test_fewer_than_two_samples_is_a_denial():
    fn = _function(attack, "guest_is_executing")
    eqs = [n for n in ast.walk(fn)
           if isinstance(n, ast.Compare)
           and any(isinstance(o, ast.Eq) for o in n.ops)
           and isinstance(n.left, ast.Call)
           and getattr(n.left.func, "id", None) == "len"]
    assert eqs, "the verdict must assert exactly two samples were taken"


def test_the_gap_is_a_real_interval_not_zero():
    assert attack.GUEST_PROGRESS_GAP >= 0.25


def test_the_timeout_clears_the_largest_measured_healthy_stall():
    """Measured 0.000 s at 50 ms resolution over 20 s on this row."""
    assert attack.GUEST_PROGRESS_TIMEOUT >= 5.0


def test_booted_is_recorded_only_after_the_guest_check():
    tree = ast.parse(_source(attack.__file__))
    booted_line = None
    check_line = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.value, ast.Name)
                        and tgt.value.id == "res"
                        and getattr(tgt.slice, "value", None) == "booted"
                        and isinstance(node.value, ast.Constant)
                        and node.value.value is True):
                    booted_line = node.lineno
        if (isinstance(node, ast.Call)
                and getattr(node.func, "id", None) == "guest_is_executing"):
            check_line = node.lineno
    assert booted_line is not None and check_line is not None
    assert check_line < booted_line, (check_line, booted_line)


def test_the_stall_control_is_inert_unless_set_and_announces_itself():
    src = _source(irq_pump.__file__)
    assert 'os.environ.get("HAL_PLANCK_STALL_AFTER_BIND")' in src
    fn = _function(irq_pump, "_maybe_stall")
    used = _names_used(fn)
    assert "STALL_AFTER_BIND" in used
    assert "warning" in used, "the knob must PRINT when it fires (w73/w75)"


def test_the_park_address_is_one_the_image_already_documents_as_a_halt_loop():
    """0x080070EC is a `halt_probe` site in this row's own generated config."""
    cfg = os.path.join(SRC, "rehostry_planck", "configs", "planck_addrs.yaml")
    with open(cfg, "r") as handle:
        text = handle.read()
    assert "%08X" % irq_pump.EXISTING_SPIN in text.upper()


@pytest.mark.parametrize("samples,ok", [
    ([], False),
    ([0], False),
    ([5], False),
    ([5, 5], False),
    ([0, 9], False),
    ([5, 9], True),
])
def test_the_verdict_shape(samples, ok):
    computed = (len(samples) == 2 and samples[0] > 0
                and samples[1] > samples[0])
    assert computed is ok


def test_the_parser_matches_the_bridges_OWN_format_string():
    """⚠ ADDED BECAUSE A DELIBERATE BREAK WAS NOT CAUGHT.

    Renaming the counter the rung greps for (`col_reads` -> `col_readsQQ`) left
    every other test green: the structural tests check WHERE the value comes
    from and WHAT is required of it, and nothing checked that the parser and
    the emitter still speak the same language. A break that nothing catches is
    a hole in the suite, not a spare break -- so the hole is filled here rather
    than the break dropped from the tally.
    """
    from rehostry_planck.peripheral_models import usb_host

    fmt = None
    for node in ast.walk(ast.parse(_source(usb_host.__file__))):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and "scans=" in node.value and "col_reads=" in node.value):
            fmt = node.value
    assert fmt is not None, "the bridge no longer emits a MATRIX line"
    reply = "MATRIX " + (fmt % (11, 22, 33, "")).strip()
    assert attack._guest_col_reads(reply) == 33, reply
    assert attack._guest_col_reads("STATE enumerated=1 configured=1") is None
