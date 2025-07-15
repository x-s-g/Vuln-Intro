from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from typing import Any

try:
    import bf_code
    import af_ast
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Required modules 'bf_code' and 'af_ast' could not be imported. "
        "Ensure they are installed and on PYTHONPATH."
    ) from exc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class CVEProcessingResult:
    """Container for results produced by CVEProcessor."""

    storage: Any
    graph: Any
    change_count: int


class CVEProcessor:
    """Encapsulates the workflow of generating AST representations for a CVE."""

    def __init__(self, cve_id: str) -> None:
        if not cve_id.startswith("CVE-"):
            raise ValueError("Invalid CVE identifier format.")
        self.cve_id = cve_id

    def run(self) -> CVEProcessingResult:
        """Run the end‑to‑end processing pipeline.

        Returns
        -------
        CVEProcessingResult
            Dataclass containing the storage dict, the generated graph Gs, and the number
            of changes detected.
        """
        logger.info("Processing %s", self.cve_id)

        # Step 1: Pre‑processing
        file_list, change_count = bf_code.main(self.cve_id)
        logger.debug("Collected %d files", len(file_list))

        # Step 2: AST Construction
        storage, graph = af_ast.build_ast(file_list)
        logger.debug("AST construction complete.")

        return CVEProcessingResult(storage=storage, graph=graph, change_count=change_count)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build AST representations for a given CVE."
    )
    parser.add_argument(
        "cve_id",
        metavar="CVE_ID",
        help="CVE identifier, e.g., CVE-2023-6111",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for command‑line usage."""
    args = _parse_args()
    processor = CVEProcessor(args.cve_id)
    result = processor.run()

    logger.info(
        "Processing finished. AST storage entries: %d, Changes detected: %d",
        len(result.storage),
        result.change_count,
    )

# ====================== Program Entry ======================
if __name__ == "__main__":
    main()
