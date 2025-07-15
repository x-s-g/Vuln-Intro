import re
from pathlib import Path
import patch_label
import filter
import af_code
import load_file


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TYPES = [
    'static ', 'struct ', 'int ', 'short ', 'long ', 'long long ', 'unsigned int ',
    'unsigned short ', 'unsigned long ', 'unsigned long long ', 'signed int ',
    'signed short ', 'signed long ', 'signed long long ', 'float ', 'double ',
    'long double ', 'char ', 'unsigned char ', 'signed char ', 'void ', 'enum ', 'union ', '__cold'
]


# ---------------------------------------------------------------------------
# Core Functionality
# ---------------------------------------------------------------------------

class PatchChangeExtractor:
    def __init__(self):
        pass

    def extract_function_name(self, definition: str) -> str | None:
        m = re.search(r'\w+\s+\*?\s*(\w+)\s*\(', definition)
        return m.group(1) if m else None

    def check_space_before_string(self, line: str, target: str) -> bool:
        return bool(re.search(r'[ \*]+' + re.escape(target), line))

    def load_change_file(self, cve_id: str, func_name: str, patch_list: list[str]) -> None:
        file_num = 0
        for patch in patch_list[1:]:
            try:
                commit_path = f"CVE/{cve_id}/commit/{patch.split('id=', 1)[1]}.txt"
                with open(commit_path, "r") as f:
                    diffs = f.readlines()

                found = False
                for diff in diffs:
                    diff = diff.strip()
                    if diff.startswith(('+', '-')):
                        diff = diff[1:].strip()
                    elif diff.startswith("@@"):
                        diff = re.sub(r'^.*?@@.*?@@', '', diff, 1, flags=re.DOTALL).strip()

                    fn_call = func_name + "("
                    for t in TYPES:
                        if diff.startswith(t) and fn_call in diff and not diff.endswith(";") \
                                and self.check_space_before_string(diff, func_name):
                            print(patch)
                            print(diff)
                            found = True

                    if diff.startswith(fn_call) and not diff.endswith(";"):
                        print(patch)
                        print(diff)
                        found = True

                if found:
                    file_num += 1
                    save_path = f"CVE/{cve_id}/change_low_version/{file_num}_{patch.split('id=', 1)[1]}.txt"
                    with open(save_path, "w") as f:
                        f.writelines(diffs)

            except (FileNotFoundError, UnicodeDecodeError):
                continue

    def run(self, cve_id: str, target_func: str = "vmxnet3_rq_cleanup") -> None:
        filtered = filter.main(cve_id)
        _ = patch_label.main(cve_id)  # not used directly here

        patch_list_file = Path(f"CVE/{cve_id}/patch_list.txt")
        patch_list = patch_list_file.read_text(encoding="utf-8").splitlines()

        func_list = af_code.find_patch_func(filtered)

        for name in func_list:
            print(name)
            self.load_change_file(cve_id, name, patch_list)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract historical patch diffs that contain vulnerable function definitions")
    parser.add_argument("cve_id", help="CVE ID, e.g., CVE-2023-4459")
    parser.add_argument("--func", default="vmxnet3_rq_cleanup", help="Target vulnerable function name")
    args = parser.parse_args()

    extractor = PatchChangeExtractor()
    extractor.run(args.cve_id, args.func)

# ====================== Program Entry ======================
if __name__ == "__main__":
    main()
