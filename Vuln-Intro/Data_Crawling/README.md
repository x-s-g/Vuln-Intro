# Data_Crawling Module

This directory contains scripts for automatically downloading patch information and related source code files for specified CVEs.

## Scripts

- `re_refactor.py`: Filters out types of refactorings in patches that do not affect the vulnerability. Input: Patch file path. Output: Nested list of diff chunks.
- `filter.py`: Filters out noise statements from patch data. Input: CVE-ID. Output: Filtered nested list of diff chunks.

## Dependencies

- Python standard libraries: `re`, `dataclasses`, `pathlib`, `typing`
- Third-party libraries: `requests`, `lxml`, `urllib3`

## Usage Examples

```bash

# Filter refactorings
python re_refactor.py 

# Filter noise
python filter.py 

```


