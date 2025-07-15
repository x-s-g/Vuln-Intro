from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

try:
    import filter as diff_filter  # Renamed to avoid shadowing built‑in filter
    import af_code
    import re_refactor
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "Required helper modules ('filter', 'af_code', 're_refactor') are missing."
    ) from exc

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

ROOT_DIR = Path("CVE-1")  # Base directory where CVE folders reside


@dataclass
class CVEPatchCodeExtractionResult:
    """Container for extraction output."""

    cleaned_code: List[str]
    change_count: int


class CVEPatchCodeExtractor:
    """Encapsulates patch code extraction workflow for a single CVE."""

    def __init__(self, cve_id: str, *, verbose: bool = False):
        if not cve_id.startswith("CVE-"):
            raise ValueError("Invalid CVE identifier format (expected 'CVE-YYYY-NNNN').")
        self.cve_id = cve_id
        self.verbose = verbose
        if self.verbose:
            logger.setLevel(logging.DEBUG)

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------
    def run(self) -> CVEPatchCodeExtractionResult:
        """Execute the full extraction pipeline."""
        logger.info("Starting patch code extraction for %s", self.cve_id)

        # 1. Load patch diff blocks
        patch_blocks = diff_filter.main(self.cve_id)
        logger.debug("Loaded %d diff blocks", len(patch_blocks))

        # 2. Identify changed function names
        func_names = af_code.find_patch_func(patch_blocks)
        logger.debug("Detected %d function(s) in patch", len(func_names))

        # 3. Handle function renaming (old -> new)
        renamed, old_name, new_name = re_refactor.old_and_new_func(self.cve_id)
        if renamed:
            func_names = [new_name[0] if fn == old_name[0] else fn for fn in func_names]
            logger.debug("Applied renaming: %s -> %s", old_name[0], new_name[0])

        # 4. Locate and extract raw function code
        raw_code_list = self._find_patch_code(func_names)
        logger.debug("Extracted raw code for %d function(s)", len(raw_code_list))

        # 5. Remove comments / blank lines
        cleaned_code_list, change_count = af_code.code_filter(raw_code_list)
        logger.debug("Code cleaned; %d lines retained", sum(map(len, cleaned_code_list)))

        return CVEPatchCodeExtractionResult(cleaned_code=cleaned_code_list, change_count=change_count)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _find_patch_code(self, func_names: List[str]) -> List[str]:
        """Locate the patched file and extract code blocks for the specified functions."""
        cve_dir = ROOT_DIR / self.cve_id
        bf_files = af_code.find_files_with_prefix(str(cve_dir), "bf#")
        if not bf_files:
            raise FileNotFoundError(f"No patched files (prefix 'bf#') found in {cve_dir}")

        patch_file_path = cve_dir / bf_files[0]
        file_lines = af_code.read_file_lines(patch_file_path)
        if file_lines is None:
            raise FileNotFoundError(f"File {patch_file_path} cannot be read.")

        extracted: List[str] = []
        for func in func_names:
            start, end = af_code.find_target_function(file_lines, func)
            code = af_code.extract_lines_from_file(patch_file_path, start, end - 1).strip()
            extracted.append(code)
            if self.verbose:
                logger.debug("Function %s: lines %d‑%d extracted", func, start, end - 1)
        return extracted

# -------------------------------------------------------------------------
# CLI entry point
# -------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract cleaned source code of functions affected by a CVE patch."
    )
    parser.add_argument("cve_id", help="CVE identifier, e.g., CVE-2023-6111")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> None:  # pragma: no cover
    args = _parse_args()
    extractor = CVEPatchCodeExtractor(args.cve_id, verbose=args.verbose)
    result = extractor.run()

    logger.info(
        "Extraction complete: %d function(s) processed, %d change lines detected.",
        len(result.cleaned_code),
        result.change_count,
    )

# ====================== Program Entry ======================
if __name__ == "__main__":  # pragma: no cover
    main()
