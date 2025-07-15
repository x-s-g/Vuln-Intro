#!/usr/bin/env python3
"""
impacting_line_finder.py
========================

Find code lines that *data‑impact* a specified target line in a C‑like
source snippet. Supports **forward** (lines after the target) and
**backward** (lines before the target) dependency tracing.

Highlights
----------
- **ImpactingLineFinder** – core engine with *direction* parameter.
- **ImpactingLinesResult** – dataclass with the mapping result.
- **CLI** – ``python impacting_line_finder.py <file|-> <line> [-d forward|backward] [-v]``.

Example (library)::

    finder = ImpactingLineFinder(direction="backward", verbose=True)
    result = finder.find(code_str, target_line=42)
    for ln, txt in result.impacting_lines.items():
        print(f"{ln}: {txt}")
"""
from __future__ import annotations

import argparse
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ImpactingLinesResult:
    """Holds the mapping from line numbers to source code lines."""

    impacting_lines: Dict[int, str]


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------


class ImpactingLineFinder:
    """Detect lines that have data‑flow impact on *target_line*.

    Parameters
    ----------
    direction : {"forward", "backward"}
        Direction to search for impacting lines relative to *target_line*.
    verbose : bool, default ``False``
        Enable debug‑level logging.
    """

    def __init__(self, *, direction: str = "backward", verbose: bool = False):
        direction = direction.lower()
        if direction not in {"forward", "backward"}:
            raise ValueError("direction must be 'forward' or 'backward'")
        self.direction = direction
        if verbose:
            logger.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def find(self, code: str, target_line: int) -> ImpactingLinesResult:
        if self.direction == "forward":
            mapping = self._find_forward(code, target_line)
        else:
            mapping = self._find_backward(code, target_line)
        return ImpactingLinesResult(impacting_lines=mapping)

    # ------------------------------------------------------------------
    # Forward search (lines after target)
    # ------------------------------------------------------------------
    def _find_forward(self, code: str, target_line: int) -> Dict[int, str]:
        lines = code.strip().splitlines()
        if target_line < 1 or target_line > len(lines):
            raise ValueError("target_line out of range")

        target_src = lines[target_line - 1].strip()
        deps: Set[str] = self._extract_variables(target_src)
        logger.debug("[forward] target(%d): %s", target_line, target_src)
        logger.debug("[forward] initial dependencies: %s", deps)

        impacting: Dict[int, str] = {}

        for lineno in range(target_line + 1, len(lines) + 1):
            src = lines[lineno - 1].strip()
            vars_in_line = self._extract_variables(src)

            common = {d for d in deps for v in vars_in_line if d.split("->", 1)[0] == v.split("->", 1)[0]}
            if common:
                impacting[lineno] = src
                deps -= common
                logger.debug("[forward] line %d impacts via %s", lineno, common)

            if not deps:
                break
        return impacting

    # ------------------------------------------------------------------
    # Backward search (lines before target)
    # ------------------------------------------------------------------
    def _find_backward(self, code: str, target_line: int) -> Dict[int, str]:
        lines = code.strip().splitlines()
        if target_line < 1 or target_line > len(lines):
            raise ValueError("target_line out of range")

        target_src = lines[target_line - 1].strip()
        deps: Set[str] = self._extract_variables(target_src)
        logger.debug("[backward] target(%d): %s", target_line, target_src)
        logger.debug("[backward] initial dependencies: %s", deps)

        impacting: Dict[int, str] = {}

        # Scan backwards
        for lineno in range(target_line - 1, 0, -1):
            src = lines[lineno - 1].strip()

            # Check assignments or pointer accesses (var = expr or ptr->field)
            if "=" in src or "->" in src:
                var_name, _ = self._extract_assignment(src)
                if var_name:
                    matched = [d for d in deps if var_name == d.split("->", 1)[0]]
                    if matched:
                        impacting[lineno] = src
                        deps -= set(matched)
                        logger.debug("[backward] line %d impacts via %s", lineno, matched)

            # Check function calls
            if self._is_function_call(src):
                vars_in_call = self._extract_variables(src)
                matched = [d for d in deps for v in vars_in_call if v == d.split("->", 1)[0]]
                if matched:
                    impacting[lineno] = src
                    deps -= set(matched)
                    logger.debug("[backward] line %d impacts via call %s", lineno, matched)

            if not deps:
                break

        return dict(sorted(impacting.items()))

    # ------------------------------------------------------------------
    # Helper routines (static)
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_variables(expr: str) -> Set[str]:
        expr = expr.strip().rstrip(";")
        expr = re.sub(r"\b\w+\s*\(", "(", expr)  # strip fn names

        # return statement
        if expr.startswith("return "):
            return set(re.findall(r"\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b", expr[len("return "):]))

        # args inside first parentheses
        m = re.search(r"\(([^()]*)\)", expr)
        if m:
            return set(re.findall(r"\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b", m.group(1)))

        # assignment right‑hand side
        if "=" in expr:
            _, right = expr.split("=", 1)
            return set(re.findall(r"\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b", right))

        return set()

    @staticmethod
    def _extract_assignment(line: str) -> (str, str):
        line = line.strip()

        if "=" in line:
            left, right = line.split("=", 1)
            var_name = left.strip().split()[-1]
            if var_name.startswith("*"):
                var_name = var_name[1:]
            return var_name, right.strip()
        elif "->" in line:
            left, right = line.split("->", 1)
            return left.strip(), right.strip()
        return "", line

    @staticmethod
    def _is_function_call(line: str) -> bool:
        line = re.sub(r"\s*//.*$", "", line).strip()
        pattern = r"^\s*\w+\s*\([^)]*\)\s*(?:;|\s*$)"
        if re.search(pattern, line):
            return not any(k in line for k in ["while", "if", "for", "switch", "case", "default", "do"])
        return False


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Find lines that data‑impact a target line (forward or backward).")
    p.add_argument("file", type=Path, help="Source file path or '-' for STDIN")
    p.add_argument("line", type=int, help="Target line number (1‑based)")
    p.add_argument("--direction", "-d", choices=["forward", "backward"], default="backward", help="Search direction (default: backward)")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return p.parse_args()


def _read_source(path: Path | str) -> str:
    if path == "-":
        import sys
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def main() -> None:  # pragma: no cover
    args = _parse_args()
    finder = ImpactingLineFinder(direction=args.direction, verbose=args.verbose)
    src = _read_source(args.file)
    result = finder.find(src, target_line=args.line)

    if not result.impacting_lines:
        print("No impacting lines found.")
    else:
        print("Impacting lines:")
        for ln, txt in result.impacting_lines.items():
            print(f"{ln}: {txt}")

# ====================== Program Entry ======================
if __name__ == "__main__":  # pragma: no cover
    main()
