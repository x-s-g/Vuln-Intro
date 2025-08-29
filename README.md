# Vuln-Intro: Accurate Identification of the Vulnerability-introducing Commit based on Differential Analysis of Patching Patterns

## Project Overview
This repository contains the code used to run experiments for the paper: "Accurate Identification of the Vulnerability-introducing Commit based on Differential Analysis of Patching Patterns".
Vuln-Intro is a toolkit designed for localizing the commit where a vulnerability was introduced. It analyzes CVE (Common Vulnerabilities and Exposures) patches to trace back to the specific commit that originally introduced the vulnerability. The toolkit includes a complete pipeline of data collection, static analysis, and vulnerability identification.

## Attention
1. The main script can be executed directly using match.py.

2. Copy the CVE files from the example directory to your working directory to use them, following the example of the cve-2023-6176 file.

3. Each specific functionality can be tested by running its corresponding script to examine the output results.

## Project Structure

```
Vuln-Intro-main/
├── Dataset/                    # Dataset directory
│   ├── Dataset/               # Full dataset
│   │   ├── CVE/              # CVE vulnerability data
│   │   ├── CVE_list.txt      # List of CVEs
│   │   └── README.txt        # Dataset description
│   └── Example/              # Example cases
│       ├── CVE-2023-1476/   # Sample CVE case
│       ├── CVE-2023-3439/   # Sample CVE case
│       └── ...               # More examples
└── Vuln-Intro/              # Main tool directory
    ├── Data_Crawling/       # Data crawling module
    ├── Identification/      # Vulnerability identification module
    └── Static_Analysis/    # Static analysis module
```
## Directory Description

### Dataset/ Directory

#### Dataset/Dataset/
- **Purpose**: Stores the complete experimental dataset (large corpus) including CVE links collected from NVD.
- **Contents**:
  - `CVE/`: Full CVE vulnerability data
  - `CVE_list.txt`: List of CVE IDs
  - `README.txt`: Dataset description

#### Dataset/Example/
- **Purpose**: Contains representative CVE cases with both raw inputs and resulting artifacts for end-to-end demonstration.
- **Typical per-CVE layout**:
  - `patch.txt`: Patch diff blocks related to the CVE
  - `patch_list.txt`: List of URLs to relevant commits/patches
  - `af#<path>` / `bf#<path>`: Full source of affected files before/after the patch (flattened path markers)
  - `change_low_version/`: Trace chain files for lower-version changes (historical tracking)
  - `commit/`: Raw commit metadata and patch contents
  - `htmls/` and `diff.html`: Archived HTML snapshots of patch/commit pages
  - `result/`: Intermediate and final outputs (e.g., `af#*`, `bf#*`, `Vul-Crit-Seq.txt`, `Vul-Rel-St.txt`, `groundtruth.txt`, final `<hash>.txt`)
  - `Vul-Crit-Seq.txt`: Extracted vulnerability-critical statement sequence (top-level copy)

Example (abridged):
```
Dataset/Example/CVE-XXXX-YYYY/
├── af#...                             # before-patch source (flattened path)
├── bf#...                             # after-patch source (flattened path)
├── change_low_version/                # historical trace chain files
├── commit/                            # raw commit metadata/diffs
├── diff.html                          # HTML for crawled patch/commit data
├── htmls/                             # HTMLs for crawled commit links
├── patch_list.txt                     # commit/patch URLs
├── patch.txt                          # patch diff blocks
├── result/
│   ├── af#...
│   ├── bf#...
│   ├── Vul-Crit-Seq.txt
│   ├── Vul-Rel-St.txt
│   ├── groundtruth.txt
│   └── <hash>.txt                     # final vulnerability-introducing commit
└── Vul-Crit-Seq.txt                   # top-level copy
```

### Vuln-Intro/ Directory

#### Data_Crawling/ Module
- **Purpose**: Automatically download patch information and related source code files
- **Main Files**:
  - `crawl_diff.py`: Crawl raw patch diffs/commit data for a CVE
  - `getLink.py`: Retrieve patch/commit links related to the target CVE
  - `re_refactor.py`: Filters out types of refactorings that do not affect the vulnerability
  - `filter.py`: Filters out noisy statements from the patch data
  - `nvd/getCveId.py`: Fetch target CVE IDs from NVD and export a list

**Usage**:
```bash
# (Optional) Fetch target CVE IDs from NVD
python nvd/getCveId.py

# Get patch/commit links for a CVE
python getLink.py

# Crawl raw diffs/commits for the CVE
python crawl_diff.py

# Remove refactoring-only chunks
python re_refactor.py

# Filter noise statements for the CVE
python filter.py
```

#### Identification/ Module
- **Purpose**: Vulnerability identification and matching
- **Main Files**:
  - `match.py`: Matches historical commits with the sequence of key vulnerability statements
  - `patch_label.py`: Identifies the corresponding patterns of all vulnerability-related statements through differential analysis
  - `rename_lower_version.py`: Tracks historical commits and records renaming of vulnerable functions
  - `select_path.py`: Extracts the sequence of key vulnerability statements
  - `traver.py`: Tracks historical commits to identify changes related to the target function

**Usage**:
```bash
# Match historical commits
python match.py 

# Generate patch labels
python patch_label.py

# Track function renaming
python rename_lower_version.py

# Select path
python select_path.py

# Track historical commits
python traver.py
```

#### Static_Analysis/ Module
- **Purpose**: Static code analysis, constructing Abstract Syntax Trees (AST) and Control Flow Graphs (CFG)
- **Main Files**:
  - `af_ast.py`: Constructs the AST for functions before the vulnerability patch is applied
  - `af_cfg.py`: Generates the complete CFG for functions before the vulnerability patch is applied
  - `af_code.py`: Extracts the source code of vulnerable functions before the patch is applied
  - `bf_ast.py`: Constructs the AST for functions after the vulnerability patch is applied
  - `bf_cfg.py`: Generates the complete CFG for functions after the vulnerability patch is applied
  - `bf_code.py`: Extracts the source code of vulnerable functions after the patch is applied
  - `back.py`: Identifies the successor nodes in the given source code
  - `front.py`: Identifies the predecessor nodes in the given source code

**Usage**:
```bash
# Construct AST before patch
python af_ast.py

# Construct CFG before patch
python af_cfg.py

# Extract code before patch
python af_code.py

# Construct AST after patch
python bf_ast.py

# Construct CFG after patch
python bf_cfg.py

# Extract code after patch
python bf_code.py
```

## Dependency Requirements

### Python Standard Library
- `from __future__ import annotations`
- `import time`
- `import re`
- `import os`
- `import argparse`
- `import logging`
- `from dataclasses import dataclass, field`
- `from pathlib import Path`
- `from typing import List, Dict, Optional, Tuple, Set, Any`
- `from collections import Counter`

### Third-Party Libraries
- `requests`: HTTP request library  
- `lxml`: XML and HTML processing library  
- `networkx`: Graph theory and network analysis library  
- `pycparser`: C language parser

**Install Dependencies**:
```bash
pip install requests lxml networkx pycparser
```

## Usage Workflow

### 1. Data Crawling
```bash
cd Vuln-Intro/Data_Crawling
python nvd/getCveId.py            # Optional
python getLink.py                 # Produce patch_list.txt
python crawl_diff.py              # Download raw diffs/commits
python re_refactor.py             # Remove refactoring-only chunks
python filter.py                  # Filter noisy statements
```

### 2. Static Analysis
```bash
cd ../Static_Analysis
python af_code.py
python af_ast.py 
python af_cfg.py 
python bf_code.py 
python bf_ast.py 
python bf_cfg.py
```

### 3. Vulnerability Identification
```bash
cd ../Identification
python patch_label.py 
python select_path.py
python match.py 
```

## Examples

The project includes ten example CVE cases located in the `Dataset/Example/` directory:
- CVE-2023-1476
- CVE-2023-3439
- CVE-2023-3777
- CVE-2023-40791
- CVE-2023-45871
- CVE-2023-46862
- CVE-2023-5345
- CVE-2023-6039
- CVE-2023-6111
- CVE-2023-6176
- CVE-2023-6622

Each example contains complete experimental data and results, which can be used as references to understand how to use the tool.

## Output File Description

- `patch.txt`: The patch diff block information  
- `af#<filename>`: Complete source code of affected files before the patch  
- `bf#<filename>`: Complete source code of affected files after the patch  
- `Vul-Crit-Seq.txt`: Extracted key vulnerability statement sequence  
- `Vul-Rel-St.txt`: Extracted vulnerability-related statements  
- `<hash>.txt`: Final experimental result — vulnerability introduction commit


## Notes

1. Ensure all required Python dependencies are installed before running the scripts  
2. Use a valid CVE-ID as the input parameter  
3. Make sure network connection is stable for fetching data from NVD and GitHub  
4. Processing large datasets may take considerable time  
5. It is recommended to run in a virtual environment to avoid dependency conflicts

## License

This project follows the corresponding open-source license. Please check the license file in the project root directory for details.



