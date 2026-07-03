#!/usr/bin/env python3
"""Validate taxonomy files: structure, unique ids, CWE format, one-rung rule,
and that every row's control resolves in profiles/verification-sources.yaml.
Requires PyYAML. jsonschema is used when available; structural checks run
regardless so CI fails loudly either way."""
import glob
import json
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
CWE_RE = re.compile(r"^(CWE-\d+|\*|class:[A-Z]+)$")
ID_RE = re.compile(r"^CC-[A-Z]+-[A-Z0-9-]+$")
MOVES = {"high-to-low", "floor-defeated", "epss-residual", "evidence-input", "none-pointer-to-vex"}
LANES = {"impact", "likelihood"}

def fail(msg, errors):
    errors.append(msg)

def main():
    errors = []
    with open(os.path.join(ROOT, "profiles", "verification-sources.yaml")) as fh:
        controls = set((yaml.safe_load(fh) or {}).get("controls", {}))
    with open(os.path.join(ROOT, "classes.yaml")) as fh:
        classes = set((yaml.safe_load(fh) or {}).get("classes", {}))

    seen_ids = set()
    row_files = [os.path.join(ROOT, "examples.yaml")]
    for path in row_files:
        with open(path) as fh:
            doc = yaml.safe_load(fh) or {}
        rel = os.path.relpath(path, ROOT)
        for row in doc.get("rows", []):
            rid = row.get("id", "<missing id>")
            where = f"{rel}:{rid}"
            if not ID_RE.match(rid):
                fail(f"{where}: bad id format", errors)
            if rid in seen_ids:
                fail(f"{where}: duplicate id", errors)
            seen_ids.add(rid)
            for key in ("title", "control", "counters", "credit", "confidence", "provenance"):
                if key not in row:
                    fail(f"{where}: missing {key}", errors)
            ctrl = (row.get("control") or {}).get("name")
            is_vex_pointer = (row.get("credit") or {}).get("move") == "none-pointer-to-vex"
            if ctrl and ctrl not in controls and not is_vex_pointer:
                # pointer-to-vex rows grant no credit, so their control is
                # deliberately unverifiable (that is why they point at VEX)
                fail(f"{where}: control '{ctrl}' not in verification-sources.yaml", errors)
            for c in (row.get("counters") or {}).get("cweClasses", []):
                if not CWE_RE.match(str(c)):
                    fail(f"{where}: bad CWE class '{c}'", errors)
                if str(c).startswith("class:") and str(c)[6:] not in classes:
                    fail(f"{where}: unknown outcome class '{c}'", errors)
            if len(((row.get("counters") or {}).get("rationale") or "")) < 40:
                fail(f"{where}: rationale too short to be a causal story", errors)
            credit = row.get("credit") or {}
            if credit.get("lane") not in LANES:
                fail(f"{where}: bad lane", errors)
            if credit.get("move") not in MOVES:
                fail(f"{where}: bad move", errors)
            if credit.get("move") == "high-to-low" and credit.get("lane") != "impact":
                fail(f"{where}: high-to-low is an impact-lane move", errors)
            if "none" in [str(m).lower() for m in credit.get("metrics", [])]:
                fail(f"{where}: metric None is reserved for VEX", errors)
            rf = credit.get("residualFactor")
            tiers = credit.get("residualTiers") or []
            if rf is not None:
                if credit.get("move") != "epss-residual" or credit.get("lane") != "likelihood":
                    fail(f"{where}: residualFactor only valid on likelihood epss-residual rows", errors)
                if not (0 < rf < 1):
                    fail(f"{where}: residualFactor must be in (0,1)", errors)
            for t in tiers:
                tf = t.get("residualFactor")
                if credit.get("move") != "epss-residual" or credit.get("lane") != "likelihood":
                    fail(f"{where}: residualTiers only valid on likelihood epss-residual rows", errors)
                if not (isinstance(tf, (int, float)) and 0 < tf < 1):
                    fail(f"{where}: residualTiers factor must be in (0,1)", errors)
            if credit.get("move") == "epss-residual" and rf is None and not tiers:
                fail(f"{where}: epss-residual move requires a residualFactor or residualTiers", errors)

    # optional full-schema pass
    try:
        import jsonschema
        with open(os.path.join(ROOT, "schema", "pain-relief.schema.json")) as fh:
            schema = json.load(fh)
        for path in row_files:
            with open(path) as fh:
                jsonschema.validate(yaml.safe_load(fh), schema)
    except ImportError:
        print("note: jsonschema not installed; structural checks only")
    except Exception as e:  # schema violations
        fail(f"jsonschema: {e}", errors)

    if errors:
        print("\n".join(f"FAIL {e}" for e in errors))
        sys.exit(1)
    print(f"OK: {len(seen_ids)} rows validated across {len(row_files)} files")

if __name__ == "__main__":
    main()
