# Identification Module

This directory contains scripts for vulnerability identification and matching.

# Attention


## Scripts

- `match.py`: Matches historical commits with the vulnerability-critical statement sequence. Input: CVE-ID. Output: File path where a match is found.
- `patch_label.py`: Identifies the corresponding patterns for all vulnerability-related statements through diff analysis. Input: CVE-ID. Output: Patterns for vulnerability-related statements.
- `rename_lower_version.py`: Tracks historical commits and records the renaming of vulnerable functions. Input: CVE-ID. Output: Trace chain of function name changes.
- `select_path.py`: Extracts the vulnerability-critical statement sequence. Input: Patterns from diff analysis. Output: Statement sequence.
- `traver.py`: Traces historical commits to identify changes related to the target function. Input: CVE-ID. Output: Patch diffs containing the target function definition.

## Dependencies

- Python standard libraries: `os`, `re`, `argparse`, `logging`, `dataclasses`, `pathlib`, `typing`, `collections`
- Third-party libraries: `requests`, `lxml`, `pycparser`, `networkx`

## Usage Examples

```bash
# Match historical commits
python match.p

# Generate patch labels
python patch_label.py

# Track function renaming
python rename_lower_version.py 

# Select path
python select_path.py

# Trace historical commits
python traver.py 

```

