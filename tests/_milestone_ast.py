# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every write to a `milestone` key/attribute must be one of exactly two shapes.

The test this replaces was a SUBSTRING SCAN of `inspect.getsource()` for two
literal spellings. The auditor enumerated 8 working equivalents and it caught
0 of 8. This walks the AST instead, so the property is structural rather than
lexical: it does not care how the assignment is spelled, only that a
`milestone` key is being written and by what.

ALLOWED, and nothing else:

  A. the RESULT INITIALISER  -- a dict literal whose "milestone" key is the
     constant "M0" (the floor every result starts at);
  B. the GRADE ASSIGNMENT    -- `<x>["milestone"], <x>["rungs_met"] = grade(...)`,
     the single tuple-unpack that takes both values off the LADDER walk.

Anything else -- including a computed key, an attribute write, a `.update()`,
a `|=` merge, or a `setdefault` -- is reported. A computed subscript key is
reported *even though we cannot prove it is "milestone"*, because that is the
point: `res[KEY_MS] = "M7"` was one of the 8 evasions and an analysis that
only looked at constant keys would wave it through.
"""
import ast
import re


def _dict_milestone_value(node):
    """If `node` is a dict literal with a "milestone" key, return its value."""
    if not isinstance(node, ast.Dict):
        return None
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == "milestone":
            return v
    return None


def _is_milestone_subscript(node):
    return (isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "milestone")


def _is_rungs_met_subscript(node):
    return (isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "rungs_met")


def _is_grade_call(node):
    """A call to a bare name `grade` (however its argument is spelled)."""
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Name) and node.func.id == "grade")
        or (isinstance(node.func, ast.Attribute) and node.func.attr == "grade"))


#: A milestone literal, and nothing else. "M8 DEFINED and UNMET at %d of %d"
#: is prose and must not match; "M7" must.
_RUNG_LITERAL = re.compile(r"^M\d+$")


def _base_name(node):
    """The name a subscript is taken on: `res["x"]` -> "res"; else None."""
    while isinstance(node, ast.Subscript):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _result_bases(tree):
    """DERIVED, not hardcoded: which variables hold the result dict.

    Taken from the module's OWN two allowed shapes -- the base of the
    `x["milestone"], x["rungs_met"] = grade(...)` target, and the name the M0
    initialiser dict is assigned to. So a device that calls its result
    something else is covered without this test being told the name.
    """
    bases = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Assign):
            continue
        for tg in n.targets:
            if (isinstance(tg, ast.Tuple) and len(tg.elts) == 2
                    and _is_milestone_subscript(tg.elts[0])):
                b = _base_name(tg.elts[0])
                if b:
                    bases.add(b)
            if isinstance(tg, ast.Name) and _dict_milestone_value(n.value) is not None:
                bases.add(tg.id)
    return bases


def _exempt_lines(tree):
    """Line numbers where a rung literal legitimately appears.

    Exactly two places: the LADDER table itself (the rung names ARE the data
    there) and the body of `grade()` (whose whole job is to pick one).
    """
    lines = set()
    for n in ast.walk(tree):
        # `LADDER = (...)` and `LADDER: Tuple[...] = (...)` alike -- planck
        # annotates its table, and an Assign-only test silently missed it.
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            if any(isinstance(t, ast.Name) and t.id == "LADDER" for t in tgts):
                lines.update(range(n.lineno, (n.end_lineno or n.lineno) + 1))
        if isinstance(n, ast.FunctionDef) and n.name == "grade":
            lines.update(range(n.lineno, (n.end_lineno or n.lineno) + 1))
    return lines


def milestone_writes(src: str):
    """-> [(lineno, kind, snippet)] for every write of a `milestone` key.

    `kind` is "ALLOWED:initialiser", "ALLOWED:grade", or a violation label.
    """
    tree = ast.parse(src)
    found = []
    bases = _result_bases(tree)
    exempt = _exempt_lines(tree)

    def note(node, kind):
        try:
            snippet = ast.unparse(node)
        except Exception:                                   # noqa: BLE001
            snippet = "<unparseable>"
        found.append((getattr(node, "lineno", -1), kind,
                      " ".join(snippet.split())[:110]))

    for n in ast.walk(tree):
        # ---- A. dict literals carrying a "milestone" key -------------------
        val = _dict_milestone_value(n)
        if val is not None:
            if isinstance(val, ast.Constant) and val.value == "M0":
                note(n, "ALLOWED:initialiser")
            else:
                note(n, "VIOLATION:dict-literal-non-M0")

        # ---- B. assignments ------------------------------------------------
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = (n.targets if isinstance(n, ast.Assign) else [n.target])

            # the one blessed tuple form: x["milestone"], x["rungs_met"] = grade(...)
            if (isinstance(n, ast.Assign) and len(targets) == 1
                    and isinstance(targets[0], ast.Tuple)
                    and len(targets[0].elts) == 2
                    and _is_milestone_subscript(targets[0].elts[0])
                    and _is_rungs_met_subscript(targets[0].elts[1])
                    and _is_grade_call(n.value)):
                note(n, "ALLOWED:grade")
                continue

            flat = []
            for t in targets:
                flat.extend(t.elts if isinstance(t, (ast.Tuple, ast.List))
                            else [t])
            for t in flat:
                if isinstance(t, ast.Subscript):
                    if _is_milestone_subscript(t):
                        note(n, "VIOLATION:subscript-assign")
                    elif (not isinstance(t.slice, ast.Constant)
                          and _base_name(t) in bases):
                        # `res[KEY_MS] = ...` on the RESULT dict -- we cannot
                        # prove the key is not "milestone", so it does not get
                        # the benefit of the doubt. An unrelated dict keyed by
                        # a loop variable (`have[name] = ...`) is not this.
                        note(n, "VIOLATION:computed-key-assign")
                elif isinstance(t, ast.Attribute) and t.attr == "milestone":
                    note(n, "VIOLATION:attribute-assign")
                elif isinstance(t, ast.Name) and t.id == "milestone":
                    # a bare `milestone = "M7"` inside grade() is the LADDER
                    # walk's own accumulator; only flag it outside grade().
                    pass

            # `res |= {"milestone": "M7"}`
            if (isinstance(n, ast.AugAssign) and isinstance(n.op, ast.BitOr)
                    and _dict_milestone_value(n.value) is not None):
                note(n, "VIOLATION:merge-assign")

        # ---- C. call-based writes -----------------------------------------
        if isinstance(n, ast.Call):
            # setattr(ns, "milestone", "M7")
            if (isinstance(n.func, ast.Name) and n.func.id == "setattr"
                    and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
                    and n.args[1].value == "milestone"):
                note(n, "VIOLATION:setattr")
            if isinstance(n.func, ast.Attribute):
                # d.update({"milestone": ...}) / d.update(milestone=...)
                if n.func.attr == "update":
                    if any(_dict_milestone_value(a) is not None
                           for a in n.args):
                        note(n, "VIOLATION:update-call")
                    if any(kw.arg == "milestone" for kw in n.keywords):
                        note(n, "VIOLATION:update-kwarg")
                # d.setdefault("milestone", "M7")
                if (n.func.attr == "setdefault" and n.args
                        and isinstance(n.args[0], ast.Constant)
                        and n.args[0].value == "milestone"):
                    note(n, "VIOLATION:setdefault")

        # ---- D. a rung LITERAL assigned anywhere it does not belong -------
        #    Key-blind on purpose: this is what catches `res[KEY_MS] = "M7"`
        #    and every `.update` / `|=` / `setattr` spelling at once, without
        #    having to recognise the container it is being written into.
        if (isinstance(n, ast.Constant) and isinstance(n.value, str)
                and _RUNG_LITERAL.match(n.value)
                and n.lineno not in exempt
                and not (n.value == "M0")):
            note(n, "VIOLATION:rung-literal-outside-the-ladder")

    return sorted(set(found))


def unexpected_milestone_writes(src: str):
    """The violations only -- what a test asserts is empty."""
    return [w for w in milestone_writes(src) if w[1].startswith("VIOLATION")]
