# Data_Crawling Module

This directory contains scripts for automatically downloading patch information and related source code files for specified CVEs.

## Scripts

- `load_file.py`: Automatically downloads the patch information and related source code files for a given CVE. Input: CVE-ID. Output: Patch diff (`patch.txt`), source code before (`af#<filename>`) and after (`bf#<filename>`) the patch.
- `patch_list.py`: Downloads the list of historical commit URLs related to a target patch, including the target commit and all earlier commits. Input: CVE-ID. Output: `patch_list.txt`.
- `re_refactor.py`: Filters out types of refactorings in patches that do not affect the vulnerability. Input: Patch file path. Output: Nested list of diff chunks.
- `filter.py`: Filters out noise statements from patch data. Input: CVE-ID. Output: Filtered nested list of diff chunks.

## Dependencies

- Python standard libraries: `re`, `dataclasses`, `pathlib`, `typing`
- Third-party libraries: `requests`, `lxml`, `urllib3`

## Usage Examples

```bash
# Download CVE patch information
python load_file.py CVE-2023-6111

# Generate patch list
python patch_list.py CVE-2023-6111

# Filter refactorings
python re_refactor.py CVE-1/CVE-2023-45863/patch.txt

# Filter noise
python filter.py CVE-2023-6111
```