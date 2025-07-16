import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Data_Crawling')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Static_Analysis')))

import patch_label
import filter
import af_code
import re
import load_file

# List of common C/C++ type keywords for matching function declarations
types = [
    'static ', 'struct ', 'int ', 'short ', 'long ', 'long long ', 'unsigned int ',
    'unsigned short ', 'unsigned long ', 'unsigned long long ', 'signed int ',
    'signed short ', 'signed long ', 'signed long long ', 'float ', 'double ',
    'long double ', 'char ', 'unsigned char ', 'signed char ', 'void ', 'enum ', 'union ', '__cold'
]


def extract_function_name(function_definition):
    """
    Extract the function name from a function definition string using regex.

    Args:
    - function_definition: String containing the function signature or definition.

    Returns:
    - The function name if matched, otherwise None.
    """
    match = re.search(r'\w+\s+\*?\s*(\w+)\s*\(', function_definition)
    if match:
        return match.group(1)
    return None


def check_space_before_string(line, target):
    """
    Check if the target string in a line is preceded by spaces or asterisks.

    Args:
    - line: The line of code to check.
    - target: The target substring to find.

    Returns:
    - True if target is preceded by space(s) or '*', False otherwise.
    """
    pattern = r'[ \*]+' + re.escape(target)
    match = re.search(pattern, line)

    return match is not None


def load_change_file(cve_id, name, patch_list):
    """
    Load and filter patch files related to the specified function name.

    Args:
    - cve_id: CVE identifier string.
    - name: Function name to look for.
    - patch_list: List of patch filenames or identifiers.

    Behavior:
    - Reads patch files.
    - Identifies lines related to the function by matching patterns.
    - Saves filtered patches to a new directory for further analysis.
    """
    file_num = 0
    for patch in patch_list[1:]:
        try:
            with open("../" + cve_id + "/commit/" + patch.split("id=", 1)[1] + ".txt", "r") as file:
                diffs = file.readlines()

            flag = False
            for diff in diffs:
                diff = diff.strip()

                if diff.startswith("+"):
                    diff = diff.split("+", 1)[1].strip()
                elif diff.startswith("-"):
                    diff = diff.split("-", 1)[1].strip()
                elif diff.startswith("@@"):
                    pattern = r'^.*?@@.*?@@'
                    # Remove everything before the second '@@'
                    diff = re.sub(pattern, '', diff, count=1, flags=re.DOTALL).strip()

                # Compose pattern to check function call
                name1 = name + "("
                for t in types:
                    if diff.startswith(t) and not diff.endswith(";") and name1 in diff and check_space_before_string(diff, name):
                        print(patch)
                        print(diff)
                        flag = True

                if diff.startswith(name1) and not diff.endswith(";"):
                    print(patch)
                    print(diff)
                    flag = True

            if flag:
                file_num += 1
                with open(f"../{cve_id}/change_low_version/" + str(file_num) + "_" + patch.split("id=", 1)[1] + ".txt", "w") as file:
                    for diff in diffs:
                        file.write(diff)

        except FileNotFoundError:
            # Skip files that don't exist
            pass
        except UnicodeDecodeError:
            # Skip files with decoding errors
            pass


def main(cve_id):
    """
    Main process to filter and save patch files related to specific functions for the CVE.

    Args:
    - cve_id: The CVE identifier string.

    Behavior:
    - Loads filtered patch content and vulnerability links.
    - Reads patch list from file.
    - Finds patch functions.
    - For each function, loads related change files.
    """
    # Load filtered patch content
    list2 = filter.main(cve_id)
    vuln_links = patch_label.main(cve_id)

    with open("../" + cve_id + "/patch_list.txt", "r") as file:
        patch_list = file.readlines()

    patch_list = [line.strip() for line in patch_list]

    list1 = filter.main(cve_id)
    func_name_list = af_code.find_patch_func(list1)

    for i in func_name_list:
        name = "vmxnet3_rq_cleanup"  # Hardcoded function name; can replace with variable i if needed
        print(name)
        load_change_file(cve_id, name, patch_list)

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
