match.py
This script is designed to match historical commits with the vulnerability-critical statement sequence.

Input:
cve_id: str — The CVE identifier, e.g., "CVE-2023-6111"
The script depends on the following modules:
filter.main(cve_id): Extracts the patch diff statements.
patch_label.main(cve_id): Returns contextual labels for the diff statements, in the format [(function_name, line_number, critical_statement)...]
af_code.find_patch_func(list2): Returns the names of functions affected by the patch.
traver.extract_function_name(func_signature): Extracts the function name from its definition.

Output:
The file path where a match is found.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import argparse
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

------------------------------------------------------------------------------------------------------------------------

patch_label.py
This script identifies the corresponding patterns for all vulnerability-related statements through diff analysis.

Input:
cve_id: str — The CVE identifier, e.g., "CVE-2023-6111"
The script depends on the following modules:
filter.main(cve_id): Extracts the patch diff statements.
af_code.find_patch_func(list2): Returns the names of functions affected by the patch.

Output:
Patterns corresponding to the vulnerability-related statements extracted through diff analysis.

The following Python standard and third-party libraries are required:
import af_ast
import af_cfg
import af_code
import bf_ast
import bf_cfg
import bf_code
import select_path
import filter
import re
from pycparser import c_parser, c_ast
from collections import Counter
------------------------------------------------------------------------------------------------------------------------

rename_lower_version.py
This script is designed to track historical commits and record the renaming of vulnerable functions.

Input:
CVE ID, for example "CVE-2023-4459"

Output:
A trace chain of function name changes detected in the patch:
old_func_name
('<commit_id>', 'old_func_name')
('<commit_id2>', 'refactored_func_name')

The following Python standard and third-party libraries are required:
import os
import re
import requests
from lxml import etree
import af_code
import filter
import load_file
import re_refactor

------------------------------------------------------------------------------------------------------------------------

select_path.py
This script is designed to extract the vulnerability-critical statement sequence.

Input:
Patterns corresponding to the vulnerability-related statements extracted through diff analysis.

Output:
The extracted vulnerability-critical statement sequence.

The following Python standard and third-party libraries are required:
import af_ast
import af_cfg
import af_code
import bf_ast
import bf_cfg
import bf_code
import select_path
import filter
import re
from pycparser import c_parser, c_ast
from collections import Counter

------------------------------------------------------------------------------------------------------------------------

traver.py
This script traces historical commits to identify changes related to the target function.

Input:
cve_id (e.g., "CVE-2023-4459"): The identifier of the target vulnerability.

Output:
Historical patch diffs containing the definition of the target function are saved to the directory:
CVE/<CVE-ID>/change_low_version/*.txt,
where each filename includes the corresponding commit ID.

The following Python standard and third-party libraries are required:
import re
from pathlib import Path
import patch_label
import filter
import af_code
import load_file