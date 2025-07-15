from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from lxml import etree
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------------- Utility Layer -------------------------
def build_retry_session(retries: int = 3, backoff: float = 0.4) -> requests.Session:
    """Returns a requests.Session with automatic retries and backoff."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def extract_commit_hash(url: str) -> Optional[str]:
    """Extracts a Git commit hash (7–40 hex characters) from a given URL."""
    patterns = [
        r"/commit(?:/\?id=|/)([0-9a-fA-F]{7,40})",
        r"[?&]id=([0-9a-fA-F]{7,40})",
        r"/([0-9a-fA-F]{7,40})$",
        r"([^/]{7,40})$",
    ]
    for pat in patterns:
        m = re.search(pat, url)
        if m:
            return m.group(1)
    return None


# ------------------------- Core Logic Layer -------------------------
@dataclass
class LinuxKernelPatchFetcher:
    """Main interface to fetch patch, A/B source files, and diff hunks for a CVE."""
    cve_id: str
    workdir: Path = Path("CVE")
    session: requests.Session = field(default_factory=build_retry_session)
    git_root: str = "https://git.kernel.org"
    commit_template: str = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={hash}"
    )

    # --- Main execution ---
    def run(self) -> Tuple[str, Path]:
        """
        Full execution pipeline:
        1. Locate the commit hash from the NVD CVE detail page
        2. Download patch and pre/post-fix (A/B) versions of modified files
        3. Return the commit hash and the output directory
        """
        commit_hash = self._find_commit_hash()
        if not commit_hash:
            raise RuntimeError(f"Failed to locate commit link for {self.cve_id} on NVD.")

        cve_dir = self._prepare_folder()
        commit_url = self.commit_template.format(hash=commit_hash)

        self._download_ab_files(commit_url, cve_dir)
        self._download_patch(commit_url, cve_dir)
        return commit_hash, cve_dir

    # --- Step 1: Extract commit hash from NVD page ---
    def _find_commit_hash(self) -> Optional[str]:
        url = f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"
        r = self.session.get(url, timeout=10)
        root = etree.HTML(r.content)
        trs = root.xpath(
            "//div[@id='vulnHyperlinksPanel']//table[contains(@class,'detail-table')]/tbody/tr"
        )
        for tr in trs:
            hrefs = tr.xpath("./td/a/@href")
            if not hrefs:
                continue
            href = hrefs[0]
            if any(domain in href for domain in ("github.com", "git.kernel.org")):
                return extract_commit_hash(href)
        return None

    # --- Step 2: Prepare the output directory ---
    def _prepare_folder(self) -> Path:
        out_dir = self.workdir / self.cve_id
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    # --- Step 3: Download pre- and post-patch versions of affected files ---
    def _download_ab_files(self, commit_url: str, out_dir: Path) -> None:
        r = self.session.get(commit_url, timeout=10)
        root = etree.HTML(r.content)
        heads = root.xpath("//table[@class='diff']/tr/td//div[@class='head']")

        for head in heads:
            a_href, b_href = head.xpath("./a/@href")
            a_name, b_name = head.xpath("./a/text()")
            for href, name, tag in (
                (a_href, a_name, "af"),
                (b_href, b_name, "bf"),
            ):
                clean_name = name.replace("/", "#")
                blob_url = self.git_root + href
                blob_html = self.session.get(blob_url, timeout=10).content
                blob_root = etree.HTML(blob_html)
                plain_href = blob_root.xpath("//div[@class='content']/a/@href")[0]
                plain_txt = self.session.get(self.git_root + plain_href, timeout=10).text
                (out_dir / f"{tag}#{clean_name}").write_text(plain_txt, encoding="utf-8")

    # --- Step 4: Extract patch hunks from the diff table ---
    def _download_patch(self, commit_url: str, out_dir: Path) -> None:
        r = self.session.get(commit_url, timeout=10)
        root = etree.HTML(r.content)
        diffs = root.xpath("//table[@class='diff']/tr/td//div")
        patch_path = out_dir / "patch.txt"
        for d in diffs:
            if d.xpath("@class")[0] in {"hunk", "add", "del", "ctx"}:
                patch_path.write_text(d.text + "\n", encoding="utf-8", append=True)


# ====================== Program Entry ======================
def cli(cve_id: str) -> None:
    """Simple CLI entry for testing or batch usage."""
    fetcher = LinuxKernelPatchFetcher(cve_id)
    commit_hash, folder = fetcher.run()
    print(f"{cve_id} -> commit {commit_hash}")
    print(f"Output saved in: {folder.resolve()}")


if __name__ == "__main__":
    # Example usage: fetch patch for CVE-2020-25284
    cli("CVE-2020-25284")
