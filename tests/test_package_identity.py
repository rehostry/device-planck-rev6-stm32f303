# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guard: the package this suite imports must be THIS repo's own ``src/``.

Not hypothetical. ``device-neuralert-release``'s suite imported
``rehostry_neuralert`` -- ``device-neuralert-da16200``'s package -- in four
places across two files. The sibling was installed and this repo's package was
not, so 30 tests passed while validating the *other* device's configs and
pinning the *other* device's ZMQ ports. Nothing in the suite could notice: a
green run measuring the wrong repo looks exactly like a green run.

It needs no shared package name. Any importable ``rehostry_*`` sibling will do,
and installs are per-venv, so which tree a name resolves to is a property of the
environment, not of this source tree -- which is precisely why it has to be
asserted at run time rather than reviewed once.
"""
from __future__ import annotations

import importlib
import pathlib

PKG = "rehostry_planck"

REPO = pathlib.Path(__file__).resolve().parents[1]
OWN_SRC = (REPO / "src" / PKG).resolve()


def _is_own(module_file) -> bool:
    """True iff `module_file` is this repo's own copy of PKG."""
    if not module_file:
        return False                    # namespace package: no real source
    return pathlib.Path(module_file).resolve().parent == OWN_SRC


def test_package_under_test_is_this_repos_own_src():
    """Fail loudly if PKG is missing, or resolves into another device's tree."""
    mod = importlib.import_module(PKG)
    got = getattr(mod, "__file__", None)
    assert _is_own(got), (
        "%s resolves to %r, not this repo's %r -- this suite would be "
        "measuring another device's code" % (PKG, got, str(OWN_SRC))
    )


def test_the_guard_can_actually_fail():
    """Positive control: a check never shown to fire is not a check.

    Exercised in both directions, so the guard above cannot quietly decay
    into `assert True` if the comparison is ever refactored.
    """
    assert not _is_own(
        "/nonexistent/device-some-sibling/src/%s/__init__.py" % PKG)
    assert not _is_own(None)
    assert _is_own(str(OWN_SRC / "__init__.py"))
