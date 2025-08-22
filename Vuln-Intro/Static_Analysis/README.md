# Static_Analysis Module

This directory contains scripts for static code analysis, including the construction of Abstract Syntax Trees (ASTs) and Control Flow Graphs (CFGs) for vulnerable functions before and after patching.

## Scripts

- `af_ast.py`: Constructs ASTs for functions before the vulnerability patch is applied. Input: CVE-ID. Output: ASTStorage object, CFGs, count.
- `af_cfg.py`: Generates complete CFGs for functions before the patch. Input: CVE-ID. Output: List of control flow paths, total snippets.
- `af_code.py`: Extracts the source code of vulnerable functions before the patch. Input: CVE-ID. Output: List of cleaned function source code strings.
- `bf_ast.py`: Constructs ASTs for functions after the patch. Input: CVE-ID. Output: ASTStorage object, CFGs, count.
- `bf_cfg.py`: Generates complete CFGs for functions after the patch. Input: CVE-ID. Output: List of control flow paths, total snippets.
- `bf_code.py`: Extracts the source code of vulnerable functions after the patch. Input: CVE-ID. Output: List of cleaned function source code strings.
- `back.py`: Identifies the successor nodes in the given source code. Input: Source code. Output: Mapping of line numbers to code lines.
- `front.py`: Identifies the predecessor nodes in the given source code. Input: Source code. Output: Mapping of line numbers to code lines.

## Dependencies

- Python standard libraries: `os`, `re`, `argparse`, `logging`, `dataclasses`, `pathlib`, `typing`
- Third-party libraries: `networkx`, `pycparser`

## Usage Examples

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
