# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Facts recovered from the firmware image, loaded from the generated YAML.

The matrix geometry, the GPIO pin lists, QMK's HID host-state addresses and
every USB descriptor byte are produced by ``tools/extract_firmware.py`` into
``configs/planck_facts.yaml``. Loading them from there rather than hardcoding
them in Python is what makes a firmware rebuild fail at *extraction* -- loudly,
with a named mismatch -- instead of as a confusing runtime symptom somewhere
else entirely (playbook trap 64: check your extractor's exit status, not just
its output).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from . import paths

_FACTS: Optional[Dict[str, Any]] = None


def load() -> Dict[str, Any]:
    """Parse and cache ``configs/planck_facts.yaml``."""
    global _FACTS
    if _FACTS is None:
        import yaml
        path = paths.configs_dir() / "planck_facts.yaml"
        if not path.is_file():
            raise RuntimeError(
                "%s is missing -- run tools/extract_firmware.py first "
                "(it derives the image AND these facts from the vendor .bin)"
                % path)
        with open(path, "r") as fh:
            _FACTS = yaml.safe_load(fh)
    return _FACTS


def descriptor(name: str) -> bytes:
    """A predicted descriptor's bytes, straight out of the firmware image.

    ``name`` is ``device``, ``config``, ``report0``..``report2`` or
    ``string1``/``string2``.
    """
    usb = load()["usb"]
    if name == "device":
        return bytes.fromhex(usb["device_descriptor"])
    if name == "config":
        return bytes.fromhex(usb["config_descriptor"])
    if name.startswith("report"):
        return bytes.fromhex(usb["report_descriptors"][int(name[6:])]["bytes"])
    if name.startswith("string"):
        idx = int(name[6:])
        # index 1 is the manufacturer, 2 the product; the extractor lists them
        # in address order, so match on the text rather than on position.
        want = {1: "OLKB", 2: "Planck"}.get(idx)
        for entry in usb["strings"]:
            if entry["text"] == want:
                return bytes.fromhex(entry["bytes"])
    raise KeyError(name)
