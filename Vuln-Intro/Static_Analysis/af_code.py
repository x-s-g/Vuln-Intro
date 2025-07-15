from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Tuple

# ----------------------------------------------------------------------
# import your existing filter module (add its path if needed)
# ----------------------------------------------------------------------
import sys
sys.path.append('/Data_Crawling/filter')   # adjust if necessary
# import filter                              # noqa: E402  (external module)


# ======================================================================
# 1) Diff‑oriented helper
# ======================================================================
class PatchDiffHelper:
    """Extract function names that appear in @@ … @@ hunks."""

    _LOC_PATTERN = re.compile(r"@@ -\d+,\d+ \+\d+,\d+ @@")
    _FUNC_PATTERN = re.compile(r"@@ -\d+,\d+ \+\d+,\d+ @@ (.*)$", re.MULTILINE)

    @staticmethod
    def _remove_loc_header(line: str) -> str:
        """Strip @@ -a,b +c,d @@ header, keep the trailing function signature."""
        return PatchDiffHelper._LOC_PATTERN.sub("", line).strip()

    # ------------------------------------------------------------------
    # public api
    # ------------------------------------------------------------------
    @classmethod
    def extract_func_names(cls, diff_blocks: List[List[str]]) -> List[str]:
        """
        Collect unique function signature strings from diff hunks.

        Parameters
        ----------
        diff_blocks : nested diff list, as returned by filter.main()

        Returns
        -------
        unique function signature strings, e.g. 'static int foo'
        """
        sigs: List[str] = []

        for block in diff_blocks:
            for line in block:
                if line.startswith("@@"):
                    sig = cls._remove_loc_header(line)
                    if sig:
                        sigs.append(sig)

        # de‑duplicate while preserving order
        seen = set()
        uniq = []
        for s in sigs:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        return uniq


# ======================================================================
# 2) Source‑file scanner
# ======================================================================
class SourceScanner:
    """Locate C functions inside a given source file."""

    # leading C keywords that hint a new top‑level declaration
    _DECL_KEYWORDS = (
        "int", "void", "char", "float", "double", "struct",
        "static", "long", "short", "__cold", "unsigned", "signed",
    )

    # ------------------------------------------------------------------
    # locate function boundaries
    # ------------------------------------------------------------------
    @classmethod
    def _find_func_range(cls, lines: List[str], signature: str) -> Tuple[int, int]:
        """
        Return (start_line, end_line_exclusive) for the first function that
        matches `signature`. Lines are 1‑indexed to mimic editors.
        """
        start = end = 0
        inside = False

        for idx, text in enumerate(lines, 1):
            # match signature (not a prototype ‑ no semicolon)
            if not inside and signature in text and not text.rstrip().endswith(";"):
                start = idx
                inside = True
                continue

            # after we've entered a function, a new top‑level decl indicates end
            if inside:
                keyword_pat = re.compile(rf"^({'|'.join(map(re.escape, cls._DECL_KEYWORDS))})\b")
                if keyword_pat.match(text) and not text.startswith((" ", "\t")):
                    end = idx - 1
                    break

        if inside and end == 0:      # function reaches file EOF
            end = len(lines)

        # rewind to trailing '}' (pyc style)
        while end > 0 and lines[end - 1].strip() != "}":
            end -= 1
        return start, end

    # ------------------------------------------------------------------
    # public api
    # ------------------------------------------------------------------
    @staticmethod
    def find_c_file(cve_dir: Path) -> Path:
        """Pick the first file whose name starts with 'af#'."""
        for file in cve_dir.iterdir():
            if file.name.startswith("af#"):
                return file
        raise FileNotFoundError("No source file starting with 'af#' found under %s" % cve_dir)

    @classmethod
    def extract_functions(cls, file_path: Path, signatures: List[str]) -> List[str]:
        """Return cleaned source code (raw, not yet stripped) for each signature."""
        lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        output: List[str] = []

        for sig in signatures:
            beg, end = cls._find_func_range(lines, sig)
            snippet = "".join(lines[beg - 1 : end]).strip() if beg and end else ""
            output.append(snippet)
        return output


# ======================================================================
# 3) High‑level orchestrator
# ======================================================================
class PatchCodeCollector:
    """
    Main façade:

        Patch diff  -> function names  -> locate source  -> remove blanks & comments
    """

    # comment prefixes
    _CMT_PREFIXES = ("//", "/*", "*/", "* ", "*\t")

    # ------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------
    @classmethod
    def _strip_comments_and_blanks(cls, code: str) -> str:
        cleaned = []
        for ln in code.splitlines():
            s = ln.strip()
            if not s or any(s.startswith(p) for p in cls._CMT_PREFIXES):
                continue
            cleaned.append(ln)
        return "\n".join(cleaned)

    # ------------------------------------------------------------
    # public api
    # ------------------------------------------------------------
    @classmethod
    def collect(cls, cve_id: str, *, echo: bool = False) -> Tuple[List[str], int]:
        """
        Parameters
        ----------
        cve_id : str
        echo   : bool  – print each cleaned snippet when True

        Returns
        -------
        cleaned_code_list : List[str]
            Source of each affected function, with comments / blanks removed.
        skipped_line_count : int
            Total number of blank‑or‑comment lines discarded across all functions.
        """

        # 1) get diff (already noise‑filtered)
        diff_blocks = filter.main(cve_id)

        # 2) extract function names from diff
        func_sigs = PatchDiffHelper.extract_func_names(diff_blocks)

        # 3) locate source file under CVE dir
        cve_dir = Path("CVE-1") / cve_id
        src_file = SourceScanner.find_c_file(cve_dir)

        # 4) pull raw code snippets
        raw_snippets = SourceScanner.extract_functions(src_file, func_sigs)

        # 5) strip comments / blanks
        cleaned, skipped = [], 0
        for snippet in raw_snippets:
            raw_lines = snippet.splitlines()
            cleaned_code = cls._strip_comments_and_blanks(snippet)
            skipped += len(raw_lines) - len(cleaned_code.splitlines())
            cleaned.append(cleaned_code)

            if echo:
                print(f"\n=== {func_sigs[cleaned.index(cleaned_code)]} ===")
                print(cleaned_code)

        return cleaned, skipped


# ====================== Program Entry ======================
if __name__ == "__main__":
    CVE = "CVE-2023-6111"
    codes, removed = PatchCodeCollector.collect(CVE, echo=True)
    print(f"\nTotal comment / blank lines removed: {removed}")
