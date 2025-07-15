from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from typing import Any, List

try:
    import bf_code  # Patch‑level diff collector
    import bf_ast   # Builds AST + CFG for patched functions
    import af_cfg   # CFG utilities (all_path, print_paths)
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "Required modules 'bf_code', 'bf_ast', and 'af_cfg' could not be imported. "
        "Ensure they are installed and available on the PYTHONPATH."
    ) from exc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class CVEPathExtractionResult:
    """Results returned from :class:`CVEPathExtractor`."""

    file_paths: List[Any]
    change_count: int


class CVEPathExtractor:
    """Encapsulates end‑to‑end control‑flow path extraction for a CVE."""

    def __init__(self, cve_id: str, *, verbose: bool = False):
        if not cve_id.startswith("CVE-"):
            raise ValueError("Invalid CVE identifier format (expected 'CVE-YYYY-NNNN').")
        self.cve_id = cve_id
        self.verbose = verbose
        # Adjust logger level for verbose output
        if self.verbose:
            logger.setLevel(logging.DEBUG)

    def run(self) -> CVEPathExtractionResult:
        logger.info("Extracting control‑flow paths for %s", self.cve_id)

        # 1. Collect patched code blocks (diff hunks)
        patch_blocks, change_count = bf_code.main(self.cve_id)
        logger.debug("Collected %d patch blocks", len(patch_blocks))

        # 2. Build AST and CFGs for each patched function
        storage, cfg_graphs, _ = bf_ast.main(self.cve_id)
        logger.debug("Constructed %d CFGs", len(cfg_graphs))

        # 3. Enumerate all execution paths in each CFG
        file_paths: list = []
        for idx, cfg in enumerate(cfg_graphs):
            if self.verbose:
                # Optionally show the AST for inspection
                storage.show_ast(idx)
            paths = af_cfg.all_path(cfg)
            if self.verbose:
                af_cfg.print_paths(paths)
            file_paths.append(paths)

        return CVEPathExtractionResult(file_paths=file_paths, change_count=change_count)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract CFG paths for functions modified by a CVE patch."
    )
    parser.add_argument("cve_id", help="CVE identifier, e.g., CVE-2023-6111")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed AST/CFG information"
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    extractor = CVEPathExtractor(args.cve_id, verbose=args.verbose)
    result = extractor.run()

    logger.info(
        "Extraction finished: %d files processed, %d changes detected.",
        len(result.file_paths),
        result.change_count,
    )

# ====================== Program Entry ======================
if __name__ == "__main__":
    main()
