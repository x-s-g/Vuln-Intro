from __future__ import annotations
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional

import requests
from lxml import etree
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ====================== Configuration Layer ======================
@dataclass
class NVDSpiderConfig:
    """Configurable parameters for the NVD spider."""
    keyword: str = "linux kernel"
    pages: int = 5                      # Number of pages to crawl (20 items per page)
    delay: float = 0.4                  # Request interval in seconds
    output_file: Optional[Path | str] = "nvd_links.txt"

    # HTTP headers
    headers: Dict[str, str] = field(
        default_factory=lambda: {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/116.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.7",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    params: Dict[str, str] = field(default_factory=lambda: {"h": "v5.17"})

    # Retry strategy
    retries: int = 3
    backoff: float = 0.5                # Backoff factor for exponential backoff in retries (in seconds)


# ====================== Crawler Layer ======================
class NVDSpider:
    BASE_URL = (
        "https://nvd.nist.gov/vuln/search/results?"
        "form_type=Basic&results_type=overview&query={kw}"
        "&search_type=all&isCpeNameSearch=&startIndex={idx}"
    )
    ROOT = "https://nvd.nist.gov"

    def __init__(self, cfg: NVDSpiderConfig):
        self.cfg = cfg
        self.session = self._build_session()

    # --- Public API ---
    def run(self) -> List[str]:
        """Crawl and return the list of CVE detail page links."""
        links: List[str] = []
        for page in range(self.cfg.pages):
            start = page * 20
            url = self.BASE_URL.format(kw=self.cfg.keyword, idx=start)
            print(f"⏳  [Page {page + 1}/{self.cfg.pages}] {url}")

            resp = self.session.get(
                url, headers=self.cfg.headers, params=self.cfg.params, timeout=10
            )
            if resp.status_code != 200:
                print(f"HTTP {resp.status_code}, skipping this page")
                continue

            page_links = self._parse_links(resp.content)
            links.extend(page_links)
            time.sleep(max(self.cfg.delay, 0))
        return links

    # --- Internal Helpers ---
    @staticmethod
    def _parse_links(html: bytes) -> List[str]:
        tree = etree.HTML(html, parser=etree.HTMLParser(encoding="utf-8"))
        rows = tree.xpath("//div[@id='row']//table[contains(@class,'table')]/tbody/tr")
        links = [NVDSpider.ROOT + row.xpath("./th/strong/a/@href")[0] for row in rows]
        for link in links:
            print("   ➜", link)
        return links

    def _build_session(self) -> requests.Session:
        retry = Retry(
            total=self.cfg.retries,
            status_forcelist=(429, 500, 502, 503, 504),
            backoff_factor=self.cfg.backoff,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s = requests.Session()
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        return s


# ====================== Entry Point Function ======================
def fetch_nvd_links(cfg: NVDSpiderConfig | None = None) -> List[str]:
    """
    Crawl NVD CVE links based on the given configuration.
    If output_file is specified, the result will be written to that file.

    Parameters
    ----------
    cfg : NVDSpiderConfig | None
        Configuration object. If None, default configuration is used.

    Returns
    -------
    List[str]
        List of CVE detail page URLs from search results.
    """
    cfg = cfg or NVDSpiderConfig()
    spider = NVDSpider(cfg)
    links = spider.run()

    if cfg.output_file:
        path = Path(cfg.output_file).expanduser()
        path.write_text("\n".join(links), encoding="utf-8")
        print(f"{len(links)} links written to {path}")

    return links


# ====================== Program Entry ======================
if __name__ == "__main__":
    # Example: Search for "linux kernel", fetch 5 pages, and write to nvd_links.txt
    fetch_nvd_links()
