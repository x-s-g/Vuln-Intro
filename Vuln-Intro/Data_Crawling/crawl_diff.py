import os
import sys
import glob
from typing import List, Optional, Tuple, Dict

from bs4 import BeautifulSoup


def read_file_text(file_path: str, encoding: str = "utf-8") -> str:

    with open(file_path, "r", encoding=encoding, errors="ignore") as f:
        return f.read()


def ensure_directory(dir_path: str) -> None:

    if not os.path.isdir(dir_path):
        os.makedirs(dir_path, exist_ok=True)


def normalize_whitespace(text: str) -> str:

    return "\n".join(line.rstrip("\r\n ") for line in text.splitlines())


def extract_diff_blocks_from_html(html_text: str) -> List[Tuple[Optional[str], List[str]]]:

    soup = BeautifulSoup(html_text, "html.parser")

    diff_table = soup.find("table", class_="diff")
    if not diff_table:
        return []

    container_td = diff_table.find("td")
    if not container_td:
        return []

    current_file_header: Optional[str] = None
    current_lines: List[str] = []
    results: List[Tuple[Optional[str], List[str]]] = []

    def flush_current():
        nonlocal current_file_header, current_lines
        if current_lines:
            results.append((current_file_header, current_lines))
        current_file_header = None
        current_lines = []

    for div in container_td.find_all("div", recursive=False):
        class_attr = div.get("class", [])
        if not class_attr:
            continue
        kind = class_attr[0]

        # Convert <br/> into newlines
        text = div.get_text("\n")
        text = normalize_whitespace(text)

        if kind == "head":
            # New file header
            flush_current()
            current_file_header = text
            # Emit as a comment-like header for readability
            current_lines.append(f"# {text}")
        elif kind == "hunk":
            # Unified diff hunk header, already starts with @@
            for line in text.splitlines():
                current_lines.append(line)
        elif kind == "ctx":
            for line in text.splitlines():
                current_lines.append(f" {line}")
        elif kind == "add":
            for line in text.splitlines():
                current_lines.append(f"+{line}")
        elif kind == "del":
            for line in text.splitlines():
                current_lines.append(f"-{line}")
        else:
            # Unknown, keep raw
            for line in text.splitlines():
                current_lines.append(line)

    flush_current()
    return results


def write_diff_output(output_dir: str, base_name: str, blocks: List[Tuple[Optional[str], List[str]]]) -> str:

    ensure_directory(output_dir)
    out_path = os.path.join(output_dir, f"{base_name}.diff")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for idx, (header, lines) in enumerate(blocks):
            if idx > 0:
                f.write("\n")
            if header:
                # Already added as a comment line at block start
                pass
            for line in lines:
                f.write(f"{line}\n")
    return out_path


def parse_a_b_paths_from_heads(blocks: List[Tuple[Optional[str], List[str]]]) -> Tuple[List[str], List[str]]:

    a_paths: List[str] = []
    b_paths: List[str] = []
    seen_a: set[str] = set()
    seen_b: set[str] = set()
    for header, lines in blocks:
        block_a_added = False
        block_b_added = False
        head_text = header or ""
        # Try several patterns, the header text may contain multiple lines including
        #   diff --git a/path b/path
        #   --- a/path
        #   +++ b/path
        head_lines = head_text.splitlines() if head_text else []
        for idx, line in enumerate(head_lines):
            s = line.strip()
            if s.startswith("--- a/"):
                val = s[6:]
                if not val and idx + 1 < len(head_lines):
                    nxt = head_lines[idx + 1].strip()
                    if not (nxt.startswith("+++") or nxt.startswith("---") or nxt.startswith("diff ")):
                        val = nxt
                if val and not block_a_added and val not in seen_a:
                    a_paths.append(val)
                    seen_a.add(val)
                    block_a_added = True
            elif s.startswith("+++ b/"):
                val = s[6:]
                if not val and idx + 1 < len(head_lines):
                    nxt = head_lines[idx + 1].strip()
                    if not (nxt.startswith("+++") or nxt.startswith("---") or nxt.startswith("diff ")):
                        val = nxt
                if val and not block_b_added and val not in seen_b:
                    b_paths.append(val)
                    seen_b.add(val)
                    block_b_added = True
        # Fallback: sometimes our stored header in lines[0] is prefixed with '# ' and wrapped
        # Try to split that header back into lines and parse again
        if lines and (not block_a_added or not block_b_added):
            if lines[0].startswith("# "):
                pseudo_head = lines[0][2:]
                pseudo_lines = pseudo_head.splitlines()
                for idx, line in enumerate(pseudo_lines):
                    s = line.strip()
                    if s.startswith("--- a/"):
                        val = s[6:]
                        if not val and idx + 1 < len(pseudo_lines):
                            nxt = pseudo_lines[idx + 1].strip()
                            if not (nxt.startswith("+++") or nxt.startswith("---") or nxt.startswith("diff ")):
                                val = nxt
                        if val and not block_a_added and val not in seen_a:
                            a_paths.append(val)
                            seen_a.add(val)
                            block_a_added = True
                    elif s.startswith("+++ b/"):
                        val = s[6:]
                        if not val and idx + 1 < len(pseudo_lines):
                            nxt = pseudo_lines[idx + 1].strip()
                            if not (nxt.startswith("+++") or nxt.startswith("---") or nxt.startswith("diff ")):
                                val = nxt
                        if val and not block_b_added and val not in seen_b:
                            b_paths.append(val)
                            seen_b.add(val)
                            block_b_added = True
        # As a last resort, scan all lines for first occurrences
        if not a_paths or not b_paths:
            for line in lines:
                s = line.lstrip("# ")
                if not a_paths and s.startswith("--- a/"):
                    a_paths.append(s[6:])
                if not b_paths and s.startswith("+++ b/"):
                    b_paths.append(s[6:])
                if a_paths and b_paths:
                    break
    return a_paths, b_paths


def collect_plain_diff_lines(blocks: List[Tuple[Optional[str], List[str]]]) -> List[str]:

    out: List[str] = []
    for _, lines in blocks:
        for line in lines:
            # Skip our comment header lines that start with '# '
            if line.startswith("# "):
                continue
            out.append(line)
        # Separate blocks with a blank line
        if out and out[-1] != "":
            out.append("")
    # Trim trailing blank lines
    while out and out[-1] == "":
        out.pop()
    return out


def write_txt(output_dir: str, file_name: str, diff_lines: List[str]) -> str:

    ensure_directory(output_dir)
    d_file = os.path.join(output_dir,file_name)

    with open(d_file, "w", encoding="utf-8", newline="\n") as fd:
        for l in diff_lines:
            fd.write(f"{l}\n")

    return d_file


def process_directory(html_dir: str = "htmls", output_dir: str = "diffs",filename: str="patch.txt") -> str:

    html_files = sorted(glob.glob(os.path.join(html_dir, "diff.html")))
    if not html_files:
        raise FileNotFoundError(f"No HTML files found in '{html_dir}' matching pattern '*.html'")
    res = ""
    for html_file in html_files:
        html_text = read_file_text(html_file)
        blocks = extract_diff_blocks_from_html(html_text)
        # # Write unified diff snapshot (existing behavior)
        # out_path = write_diff_output(output_dir, filename, blocks)

        # Additionally, write txt file: plain diff
        plain_diff = collect_plain_diff_lines(blocks)
        for line in plain_diff:
            print(line)
        res = write_txt(output_dir,filename,  plain_diff)
    return res


if __name__ == "__main__":
    htmls_dir: str = "../"
    CVE_ID = "CVE-2023-6176"
    dir = os.path.join(htmls_dir, CVE_ID)
    outputdir = os.path.join(htmls_dir, CVE_ID,"test")
    file_name ="patch.txt"
    try:
        output = os.path.abspath(process_directory(dir,outputdir,file_name))
        print("=================================================")
        print(f"saved to file: {output}")
    except FileNotFoundError as e:
        print(f"Cannot find HTML files:：{e}")
        sys.exit(1)


