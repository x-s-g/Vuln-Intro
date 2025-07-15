af_ast.py
This program is designed to construct abstract syntax trees (ASTs) for functions before the application of vulnerability patches.

Input:
cve_id: A string representing the vulnerability identifier, such as "CVE-2023-6111".
The input function is internally provided by the module af_code, which extracts the vulnerable function and supplies it to this program.

Output:
storage: An ASTStorage object that holds all the generated abstract syntax trees (ASTs). You can access the i-th AST using the .get(i) method.
cfgs: A list of control flow graphs (List[nx.DiGraph]), where each element is a networkx.DiGraph representing the control flow of a corresponding code snippet.
count: An integer indicating the total number of code snippets returned by af_code.main.


The following Python standard and third-party libraries are required:
import networkx as nx
from pycparser import c_parser, c_ast
import af_code
import filter

------------------------------------------------------------------------------------------------------------------------

af_cfg.py
This program is responsible for generating complete control flow graphs (CFGs) for functions before vulnerability patches are applied.

Input:
CVE_id (type: str): A string representing the identifier of a specific CVE (e.g., "CVE-2023-6111").
Dependencies:
af_code.main(CVE_id): Extracts the code snippets related to the specified CVE, such as the function bodies modified by the patch.
af_ast.main(CVE_id): Builds abstract syntax trees (ASTs) based on the code snippets from af_code and constructs the corresponding control flow graphs (CFGs).

Output:
all_paths (type: list[list[list[c_ast.Node]]]):
Outer list: Represents the collection of paths for each code snippet (typically one function per snippet);
Middle list: Each element is a control flow path from the entry node to an exit node of the function;
Inner list: Nodes along each path, where each node is an instance of pycparser.c_ast.Node (e.g., If, Return, Assignment, etc.).
total_snippets (type: int): Indicates the total number of code snippets associated with the given CVE, corresponding to the number of modified functions in the patch.

The following Python standard and third-party libraries are required:
import networkx as nx
from pycparser import c_ast
import af_code
import af_ast
import filter

------------------------------------------------------------------------------------------------------------------------

af_code.py
This program is designed to extract the source code of vulnerable functions before the patch is applied for a specified CVE.

Input:
cve_id (type: str): A string representing the identifier of the CVE to be processed, e.g., "CVE-2023-6111".

Output:
List[str]: A list of cleaned function source code strings.
Each element corresponds to a modified function, with blank lines and comment lines removed, preserving only the actual code.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import List, Tuple
import filter

------------------------------------------------------------------------------------------------------------------------

bf_ast.py
This program is designed to construct abstract syntax trees (ASTs) for functions after vulnerability patches have been applied.

Input:
cve_id: A string representing the vulnerability identifier, such as "CVE-2023-6111".
The vulnerable function is internally provided by the module bf_code, which extracts and passes it to this program.

Output:
storage: An ASTStorage object that stores all generated abstract syntax trees. You can access the i-th AST using the .get(i) method.
cfgs: A list of control flow graphs (List[nx.DiGraph]), where each element is a networkx.DiGraph representing the control flow structure of a code snippet.
count: An integer indicating the total number of code snippets returned by bf_code.main.

The following Python standard and third-party libraries are required:
import argparse
import logging
from dataclasses import dataclass
from typing import Any
import bf_code
import af_ast

------------------------------------------------------------------------------------------------------------------------

bf_cfg.py
This program is responsible for generating complete control flow graphs (CFGs) for functions after a vulnerability patch has been applied.

Input:
CVE_id (type: str): A string representing the identifier of a specific CVE (e.g., "CVE-2023-6111").
Dependencies:
bf_code.main(CVE_id): Extracts the code snippets related to the specified CVE, such as the function bodies modified by the patch.
bf_ast.main(CVE_id): Builds abstract syntax trees (ASTs) based on the output of bf_code, and generates the corresponding control flow graphs (CFGs).

Output:
all_paths (type: list[list[list[c_ast.Node]]]):
Outer list: Represents the collection of paths for each code snippet (typically one function per snippet);
Middle list: Each element is a control flow path from the entry node to an exit node within the function;
Inner list: Nodes along the path, where each node is an instance of pycparser.c_ast.Node (e.g., If, Return, Assignment, etc.).
total_snippets (type: int): The total number of code snippets associated with the given CVE, corresponding to the number of modified functions in the patch.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import argparse
import logging
from dataclasses import dataclass
from typing import Any, List
import bf_code  # Patch‑level diff collector
import bf_ast   # Builds AST + CFG for patched functions
import af_cfg   # CFG utilities (all_path, print_paths)

------------------------------------------------------------------------------------------------------------------------

bf_code.py
This program is designed to extract the source code of vulnerable functions after the patch has been applied for a specified CVE.

Input:
cve_id (type: str): A string representing the identifier of the CVE to be processed, such as "CVE-2023-6111".

Output:
List[str]: A list of cleaned function source code strings.
Each element corresponds to a function that was modified by the patch, with blank lines and comments removed to retain only the effective code.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import argparse
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List
import filter as diff_filter  # Renamed to avoid shadowing built‑in filter
import af_code
import re_refactor

------------------------------------------------------------------------------------------------------------------------

back.py
This program is designed to identify the subsequent position node within the given source code.

Input:
The complete source code of a vulnerable function.

Output:
A mapping of the line numbers of the impacting statements to their corresponding source code lines.
The result is returned as a dictionary, where each key is a line number and the value is the corresponding line of code from the original source.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import argparse
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Set

------------------------------------------------------------------------------------------------------------------------

front.py
This program is designed to identify the previous position node within the given source code.

Input:
The complete source code of a vulnerable function.

Output:
A mapping of the line numbers of the impacting statements to their corresponding source code lines.
The result is returned as a dictionary, where each key represents a line number and the value is the corresponding line of code from the original source.

The following Python standard and third-party libraries are required:
from __future__ import annotations
import argparse
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set