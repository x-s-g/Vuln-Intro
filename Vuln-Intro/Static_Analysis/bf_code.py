import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Data_Crawling')))
import af_code
import filter
import re_refactor

def find_patch_code(func_name_list, cve_id):
    """
    Extract the code blocks of specified functions from patch files.

    Args:
        func_name_list (list): List of function names to extract.
        cve_id (str): The CVE identifier to locate the patch directory.

    Returns:
        list: List of extracted function code strings.
    """
    # Find patch files starting with "bf#" prefix
    b_code_path = af_code.find_files_with_prefix("../" + cve_id, "bf#")
    file_lines = af_code.read_file_lines("../" + cve_id + "/" + b_code_path[0])
    if file_lines is None:
        print("File not found")
        return False

    code_list = []
    for func in func_name_list:
        # Locate function start and end lines
        start_line, end_line = af_code.find_target_function(file_lines, func)
        # Extract lines of the function from file and strip trailing spaces
        code_list.append(af_code.extract_lines_from_file("../" + cve_id + "/" + b_code_path[0], start_line, end_line - 1).strip())

    return code_list


def main(CVE_id):
    """
    Main entry function to extract filtered patch code list for a CVE.

    Args:
        CVE_id (str): The CVE identifier.

    Returns:
        tuple: (new_patch_code_list, count)
            - new_patch_code_list: List of patch code snippets without comments and empty lines.
            - count: Number of removed comment and empty lines.
    """
    # Get the raw patch diffs
    list1 = filter.main(CVE_id)

    # Find changed function names from patch diffs
    func_name_list = af_code.find_patch_func(list1)

    # Check if function names have changed between old and new versions
    flag, old_names, new_names = re_refactor.old_and_new_func(CVE_id)
    if flag:
        # Replace old function names with new names in the function list
        func_name_list = [new_names[0] if x == old_names[0] else x for x in func_name_list]

    # Extract code blocks for the identified functions
    patch_code_list = find_patch_code(func_name_list, CVE_id)

    # Filter out comments and empty lines, get count of filtered lines
    new_patch_code_list, count = af_code.code_filter(patch_code_list)

    return new_patch_code_list, count

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
