import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Data_Crawling')))
import filter
import re


def extract_function_code(input_string, c_file_path):
    """
    Extract complete function definitions from the C file based on patch input string.

    :param input_string: The patch diff string containing function signatures.
    :param c_file_path: Path to the C source file.
    :return: List of full function code strings.
    """
    pattern = r'@@ -\d+,\d+ \+\d+,\d+ @@ (.*)$'
    matches = re.findall(pattern, input_string, re.MULTILINE)

    with open(c_file_path, 'r') as file:
        c_code = file.read()

    function_code = []
    for match in matches:
        function_signature = match.strip()
        if function_signature:
            func_pattern = rf'{re.escape(function_signature)}\s*\(.*?\)\s*\{{[\s\S]*?\}}'
            func_match = re.search(func_pattern, c_code)
            if func_match:
                function_code.append(func_match.group(0))

    return function_code


def find_files_with_prefix(directory, prefix):
    """
    Find all files in a directory that start with a given prefix.

    :param directory: Directory path.
    :param prefix: Filename prefix string.
    :return: List of matching filenames.
    """
    matching_files = []
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            matching_files.append(filename)
    return matching_files


def remove_location_info(input_str):
    """
    Remove diff location information lines like '@@ -xx,xx +xx,xx @@' from a string.

    :param input_str: Input string possibly containing diff location info.
    :return: String with location info removed.
    """
    pattern = r'@@ -\d+,\d+ \+\d+,\d+ @@'
    cleaned_str = re.sub(pattern, '', input_str).strip()
    return cleaned_str


def remove_duplicates(input_list):
    """
    Remove duplicate entries from a list while preserving order.

    :param input_list: List possibly containing duplicates.
    :return: List with duplicates removed.
    """
    seen = set()
    output_list = []
    for item in input_list:
        if item not in seen:
            seen.add(item)
            output_list.append(item)
    return output_list


def find_patch_func(diffs):
    """
    Extract function names from diff data lines starting with '@@'.

    :param diffs: List of diff hunks (lists of strings).
    :return: List of unique function names found in diffs.
    """
    filename = []
    for diff in diffs:
        for line in diff:
            if line.startswith("@@"):
                file_name = remove_location_info(line)
                filename.append(file_name)
    filename = remove_duplicates(filename)
    return filename


def read_file_lines(file_path):
    """
    Read all lines from a file.

    :param file_path: Path to the file.
    :return: List of lines or None if file not found.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"文件 {file_path} 未找到。")
        return None


def find_target_function(file_lines, func):
    """
    Find start and end line numbers of a function in a file by its name.

    :param file_lines: List of lines of the file.
    :param func: Function name to find.
    :return: Tuple (start_line, end_line)
    """
    FIND = False
    num = 0
    start_num = 0
    end_num = 0
    func = func.strip()
    for line in file_lines:
        num += 1
        if func in line and not line.split("\n", 1)[0].endswith(";"):
            start_num = num
            FIND = True
            continue

        if FIND:
            keywords = ["int", "void", "char", "float", "double", "struct", "static", "__cold"]
            pattern = re.compile(r'^(?:' + '|'.join(re.escape(keyword) for keyword in keywords) + r')\b')
            match = pattern.match(line)
            if match and not line[0].isspace():
                end_num = num
                break
    if end_num == 0:
        end_num = num
    while file_lines[end_num - 1] != "}\n" and end_num > -1 and end_num <= len(file_lines):
        end_num -= 1

    return start_num, end_num + 1


def extract_lines_from_file(filename, start_line, end_line):
    """
    Extract lines from a file between start_line and end_line inclusive.

    :param filename: File path.
    :param start_line: Starting line number.
    :param end_line: Ending line number.
    :return: String containing extracted lines concatenated.
    """
    lines = []
    with open(filename, 'r') as file:
        for current_line_number, line in enumerate(file, start=1):
            if start_line <= current_line_number <= end_line:
                lines.append(line)
            elif current_line_number > end_line:
                break
    return ''.join(lines)


def find_patch_code(func_name_list, cve_id):
    """
    Find the patch code snippets for the list of function names within the CVE directory.

    :param func_name_list: List of function names.
    :param cve_id: CVE identifier string.
    :return: List of code snippets corresponding to the functions.
    """
    a_code_path = find_files_with_prefix("../" + cve_id, "af#")
    file_lines = read_file_lines("../" + cve_id + "/" + a_code_path[0])
    if file_lines is None:
        print("文件不存在")
        return False
    code_list = []
    for func in func_name_list:
        a, b = find_target_function(file_lines, func)
        code_list.append(extract_lines_from_file("../" + cve_id + "/" + a_code_path[0], a, b - 1).strip())
    return code_list


def code_filter(codes):
    """
    Remove empty lines and comment lines from code snippets.

    :param codes: List of code snippet strings.
    :return: Tuple (filtered_code_list, count_of_removed_lines)
    """
    new_codes = []
    empty_lines_count = 0
    comment_lines_count = 0

    for code in codes:
        lines = code.splitlines()
        filtered_lines = []

        for line in lines:
            stripped_line = line.strip()
            if not stripped_line:
                empty_lines_count += 1
            elif stripped_line.startswith('//') or stripped_line.startswith('/*') or stripped_line.startswith('*/') or stripped_line.startswith('* ') or stripped_line.startswith('*\t'):
                comment_lines_count += 1
            else:
                filtered_lines.append(line)

        new_codes.append('\n'.join(filtered_lines))
    count = empty_lines_count + comment_lines_count
    return new_codes, count


def main(CVE_id):
    """
    Main function entry:
    1. Obtain patch diffs by calling filter.main.
    2. Extract function names from patch diffs.
    3. Extract the full function code snippets from patch files.
    4. Filter out comments and empty lines.
    5. Return cleaned patch code and count of filtered lines.

    :param CVE_id: CVE identifier string.
    :return: Tuple (list_of_clean_code, count_of_filtered_lines)
    """
    list1 = filter.main(CVE_id)

    func_name_list = find_patch_func(list1)

    patch_code_list = find_patch_code(func_name_list, CVE_id)

    new_patch_code_list, count = code_filter(patch_code_list)

    return new_patch_code_list, count

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
