# Data_Crawling Module

This directory contains scripts to collect vulnerability-related patch information and raw sources for given CVE IDs, and to pre-process the diffs before downstream analysis.

## Directory Structure

```
Data_Crawling/
├── crawl_diff.py            # Crawl raw patch diffs/commit data for a CVE
├── filter.py                # Filter noisy statements from patch data
├── getLink.py               # Retrieve patch/commit links for a CVE
├── re_refactor.py           # Filter refactoring chunks that do not affect vulnerability
├── nvd/
│   ├── getCveId.py          # Fetch NVD CVE IDs (e.g., Linux kernel) and export list
│   ├── linux_kernel_cve_ids.txt
│   └── README.md
└── README.md
```

## Scripts

- `crawl_diff.py`
  - Purpose: Download/crawl raw patch diffs and/or commit metadata for the specified CVE.
  - Input: CVE-ID (e.g., CVE-2023-6176) or a list of commit links.
  - Output: Raw diff files and auxiliary metadata saved under a CVE-specific directory.

- `getLink.py`
  - Purpose: Obtain patch/commit links related to the vulnerable files for the given CVE.
  - Input: CVE-ID.
  - Output: `patch_list.txt` containing URLs of relevant commits/patches.

- `re_refactor.py`
  - Purpose: Remove refactoring-only changes that do not affect vulnerability logic.
  - Input: Patch file path or raw diff content.
  - Output: A nested list of diff chunks that excludes refactoring-only parts.

- `filter.py`
  - Purpose: Filter noise statements from patch data to keep vulnerability-relevant edits.
  - Input: CVE-ID (uses previously downloaded/cached patch data).
  - Output: Filtered nested list of diff chunks for downstream analysis.

- `nvd/getCveId.py`
  - Purpose: Query NVD and export a list of target CVE IDs (e.g., for Linux kernel).
  - Output: `linux_kernel_cve_ids.txt` under `nvd/`.

## Dependencies

- Python standard libraries: `re`, `dataclasses`, `pathlib`, `typing`
- Third-party libraries: `requests`, `lxml`, `urllib3`

## Usage Examples

```bash
# 1) (Optional) Fetch target CVE IDs from NVD
python nvd/getCveId.py

# 2) Get patch/commit links for a CVE
python getLink.py

# 3) Crawl raw diffs/commits for the CVE
python crawl_diff.py

# 4) Remove refactoring-only chunks
python re_refactor.py

# 5) Filter noise statements for the CVE
python filter.py
```
