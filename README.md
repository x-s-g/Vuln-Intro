# Vuln-Intro: Accurate Identification of the Vulnerability-introducing Commit based on Differential Analysis of Patching Patterns

## Project Overview

Vuln-Intro is a toolkit designed for localizing the commit where a vulnerability was introduced. It analyzes CVE (Common Vulnerabilities and Exposures) patches to trace back to the specific commit that originally introduced the vulnerability. The toolkit includes a complete pipeline of data collection, static analysis, and vulnerability identification.

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
- **Purpose**: Stores the complete experimental dataset, including all CVE links collected from NVD.
- **Contents**:
  - `CVE/`: Directory containing all CVE vulnerability data
  - `CVE_list.txt`: CVE list file
  - `README.txt`: Dataset description document

#### Dataset/Example/ 
- **Purpose**: Contains ten sample CVE cases, including raw data and experimental results.
- **Structure**: Each CVE case includes the following files:
  - `patch.txt`: Patch information related to the CVE
  - `patch_list.txt`: List of all commit URLs related to vulnerable files
  - `commit/`: All commits related to vulnerable files
  - `result/`: Intermediate and final outputs of the experiment
  - `a.c`: Complete source code of the vulnerable file before patch
  - `b.c`: Complete source code of the vulnerable file after patch
  - `Vul-Crit-Seq.txt`: Vulnerability-critical statement sequence extracted during the experiment
  - `Vul-Rel-St.txt`: Vulnerability-related statements extracted during the experiment
  - `<hash>.txt`: Final result — vulnerability-introducing commit, named by the corresponding commit hash

### Vuln-Intro/ Directory

#### Data_Crawling/ Module
- **Purpose**: Automatically download patch information and related source code files
- **Main Files**:
  - `load_file.py`: Automatically downloads patch information and related source code files for the specified CVE
  - `patch_list.py`: Downloads the list of historical commit URLs related to the target patch
  - `re_refactor.py`: Filters out types of refactorings that do not affect the vulnerability
  - `filter.py`: Filters out noisy statements from the patch data

**Usage**:
```bash
# Download CVE patch information
python load_file.py CVE-2023-6111

# Generate patch list
python patch_list.py CVE-2023-6111

# Filter refactorings
python re_refactor.py CVE-2023-6111

# Filter noise
python filter.py CVE-2023-6111
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
python match.py CVE-2023-6111

# Generate patch labels
python patch_label.py CVE-2023-6111

# Track function renaming
python rename_lower_version.py CVE-2023-6111

# Select path
python select_path.py

# Track historical commits
python traver.py CVE-2023-6111
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
python af_ast.py CVE-2023-6111

# Construct CFG before patch
python af_cfg.py CVE-2023-6111

# Extract code before patch
python af_code.py CVE-2023-6111

# Construct AST after patch
python bf_ast.py CVE-2023-6111

# Construct CFG after patch
python bf_cfg.py CVE-2023-6111

# Extract code after patch
python bf_code.py CVE-2023-6111
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
python load_file.py <CVE-ID>
python patch_list.py <CVE-ID>
python filter.py <CVE-ID>
```

### 2. Static Analysis
```bash
cd ../Static_Analysis
python af_code.py <CVE-ID>
python af_ast.py <CVE-ID>
python af_cfg.py <CVE-ID>
python bf_code.py <CVE-ID>
python bf_ast.py <CVE-ID>
python bf_cfg.py <CVE-ID>
```

### 3. Vulnerability Identification
```bash
cd ../Identification
python patch_label.py <CVE-ID>
python select_path.py
python match.py <CVE-ID>
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
