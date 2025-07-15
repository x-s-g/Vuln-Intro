Filename: load_file.py

Description: This script is designed to automatically download the patch information and related source code files for a given CVE.

Input:
The script takes a CVE identifier (CVE-ID) as input through the main function.

Output:
The following files will be generated under the directory CVE/<CVE-ID>/:

patch.txt: Contains the diff hunk information of the patch (including lines classified as hunk, add, del, and ctx).

af#<filename>: The complete source code of the affected file before the patch.

bf#<filename>: The complete source code of the affected file after the patch.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
import requests
from lxml import etree
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

------------------------------------------------------------------------------------------------------------------------

Filename: patch_list.py
Description: This script is designed to download the list of historical commit URLs related to a target patch, including the target commit itself and all earlier commits.

Input:
A CVE identifier, e.g., "CVE-2020-25284"

Output:
The file CVE/<CVE-id>/patch_list.txt, which contains a list of commit URLs associated with the specified CVE. Each line in the file corresponds to one commit link.

The following Python standard and third-party libraries are required:
import requests
from lxml import etree
import load_file

------------------------------------------------------------------------------------------------------------------------

Filename: re_refactor.py
Description:
This script is designed to filter out several types of refactorings in patches that do not affect the vulnerability.

Input:
The relative path to the patch file for a specified CVE, for example, "CVE-1/CVE-2023-45863/patch.txt".

Output:
A nested list (list of lists) structured as follows:
[
    [  # First diff chunk (list)
        "+ static int new_function(int a) {",
        "+     return a + 1;",
        "+ }",
        "- int old_code() {",
        "-     return 0;",
        ...
    ],
    [  # Second diff chunk
        "+ void another_new_func() {",
        ...
    ],
    ...
]
Each inner list corresponds to a diff chunk, containing lines from the patch prefixed with '+' (additions) or '-' (deletions).

The following Python standard and third-party libraries are required:
import re

------------------------------------------------------------------------------------------------------------------------

Filename: filter.py

Description:
This program is designed to filter out noise statements from patch data.

Input:
cve_id: A string representing the vulnerability identifier (CVE ID), for example, "CVE-2023-6111".
Internally, the program calls re_refactor.main(cve_id), which produces a nested list output that serves as the input for this filtering process.

Output:
Returns a filtered nested list (list of lists).
[
    [  # First diff chunk (list)
        "+ static int new_function(int a) {",
        "+     return a + 1;",
        "+ }",
        "- int old_code() {",
        "-     return 0;",
        ...
    ],
    [  # Second diff chunk
        "+ void another_new_func() {",
        ...
    ],
    ...
]
Each inner list corresponds to a diff chunk, containing lines from the patch prefixed with '+' (additions) or '-' (deletions).

The following Python standard and third-party libraries are required:
import re
import re_refactor