The Data_Collection directory is designed to support automated collection of vulnerability-related datasets.

It contains two main modules:

Data_NVD.py
A web crawler that scrapes CVE detail page URLs from the NVD (National Vulnerability Database) based on a specified keyword (e.g., a project name).
The results are stored in a plain text file named nvd_links.txt.

Data_URL.py
A web crawler that visits each CVE detail page (from nvd_links.txt) and extracts available patch links, especially GitHub commit URLs associated with the vulnerability.
The results are written to url.txt.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional
import requests
from lxml import etree
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry