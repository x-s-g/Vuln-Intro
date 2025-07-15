from __future__ import annotations

import argparse
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Set

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@dataclass
class ImpactingLinesResult:
    """Holds the mapping from line numbers to source code lines."""

    impacting_lines: Dict[int, str]


class ImpactingLineFinder:
    """Core engine for backward data‑dependency line discovery."""

    def __init__(self, *, verbose: bool = False):
        if verbose:
            logger.setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def find(self, code: str, target_line: int) -> ImpactingLinesResult:
        """Return lines that impact *target_line*.

        Parameters
        ----------
        code : str
            Full source snippet.
        target_line : int
            One‑based index of the target line inside *code*.
        """
        lines = code.strip().splitlines()
        if target_line < 1 or target_line > len(lines):
            raise ValueError("target_line is out of range for provided code snippet")

        target_src = lines[target_line - 1].strip()
        dependencies: Set[str] = self._extract_variables(target_src)

        logger.debug("Target (%d): %s", target_line, target_src)
        logger.debug("Initial dependencies: %s", dependencies)

        impacting: Dict[int, str] = {}

        # Scan *forward* to propagate dependencies to subsequent lines.
        for lineno in range(target_line + 1, len(lines) + 1):
            src = lines[lineno - 1].strip()
            vars_in_line = self._extract_variables(src)

            # If any existing dependency matches vars in current line -> impacting
            common = {dep for dep in dependencies for v in vars_in_line if dep.split("->", 1)[0] == v.split("->", 1)[0]}
            if common:
                impacting[lineno] = src
                logger.debug("Line %d impacts via %s -> %s", lineno, common, src)
                # Remove resolved dependencies to avoid duplicates
                dependencies -= common

            # Additionally, any *new* vars used together with deps extend the dependency set
            if dependencies & vars_in_line:
                impacting[lineno] = src
                dependencies -= dependencies & vars_in_line

            if not dependencies:
                break  # All dependencies resolved

        return ImpactingLinesResult(impacting_lines=impacting)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_variables(expression: str) -> Set[str]:
        """Lightweight parser for variable identifiers in a C‑like expression."""
        expression = expression.strip().rstrip(";")
        expression = re.sub(r"\b\w+\s*\(", "(", expression)  # drop fn names but keep args

        # Return statement
        if expression.startswith("return "):
            return set(re.findall(r"\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b", expression[len("return "):]))

        # Args inside first pair of parentheses
        m = re.search(r"\(([^()]*)\)", expression)
        if m:
            return set(re.findall(r"\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b", m.group(1)))

        # Assignment – right‑hand side
        if "=" in expression:
            _, right = expression.split("=", 1)
            return set(re.findall(r"\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b", right))

        return set()


# ------------------------------------------------------------------
# CLI helpers
# ------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Find lines that impact a target line via variable usage.")
    p.add_argument("file", type=Path, help="Path to C/C‑like source file (use - for STDIN)")
    p.add_argument("line", type=int, help="One‑based line number to analyze")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return p.parse_args()


def _read_source(path: Path | str) -> str:
    if path == "-":  # stdin passthrough
        import sys
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def main() -> None:  # pragma: no cover
    args = _parse_args()
    finder = ImpactingLineFinder(verbose=args.verbose)
    source = _read_source(args.file)
    result = finder.find(source, target_line=args.line)

    if not result.impacting_lines:
        print("No impacting lines found.")
    else:
        print("Impacting lines:")
        for lineno, src in result.impacting_lines.items():
            print(f"{lineno}: {src}")

# ====================== Program Entry ======================
if __name__ == "__main__":  # pragma: no cover
    main()
