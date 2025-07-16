import re

# List of C-style types used to detect function definitions
types = [
    'static ', 'struct ', 'int ', 'short ', 'long ', 'long long ', 'unsigned int ',
    'unsigned short ', 'unsigned long ', 'unsigned long long ', 'signed int ',
    'signed short ', 'signed long ', 'signed long long ', 'float ', 'double ',
    'long double ', 'char ', 'unsigned char ', 'signed char ', 'void ', 'enum ', 'union ','__cold'
]

def find_new_functions(lines):
    """
    Identify new function definitions from diff lines.

    Args:
        lines (list): Lines of diff containing '+' additions.

    Returns:
        list: List of lists, where each sublist represents a detected function block.
    """
    in_function_body = False
    new_functions = []
    current_function = []
    for line in lines:
        if not line.strip():
            continue
        if line.startswith('+'):
            stripped_line = line[1:]
            if any(stripped_line.startswith(t) for t in types) and '(' in stripped_line and ')' in stripped_line:
                current_function.append(stripped_line)
                in_function_body = True
            elif stripped_line.endswith('}'):
                if in_function_body:
                    current_function.append(stripped_line)
                    if '{' in ''.join(current_function):
                        new_functions.append(current_function)
                        current_function = []
                        in_function_body = False
            elif in_function_body:
                current_function.append(stripped_line)
    return new_functions

def extract_function_name(c_code_line):
    """
    Extract function name from a C code function declaration line.

    Args:
        c_code_line (str): A line of C code.

    Returns:
        str or None: Extracted function name if found, otherwise None.
    """
    pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{?'
    match = re.search(pattern, c_code_line)
    if match:
        return match.group(1)
    return None

def contains_element_but_not_function_def(line, element):
    """
    Check if a line contains a given element but is not a function definition.

    Args:
        line (str): The line to check.
        element (str): The element to find.

    Returns:
        bool: True if the line contains the element but is not a function definition.
    """
    if not line.startswith('+'):
        return False
    line = line[1:]
    function_def_pattern = r'^\s*(?:[\w\*]+\s+)+([\w\*]+)\s*\([^)]*\)\s*(?:\{)?\s*$'
    if element in line:
        if re.search(function_def_pattern, line.strip()):
            return False
        return True
    return False

def extract_function_body(lines):
    """
    Extracts the body of a function from its code block.

    Args:
        lines (list): List of lines representing a function.

    Returns:
        list: Lines inside the function body.
    """
    function_body = []
    inside_function = False
    for line in lines:
        stripped_line = line.strip()
        if stripped_line == '{':
            inside_function = True
            continue
        elif stripped_line == '}':
            inside_function = False
            continue
        if inside_function:
            function_body.append(line.strip())
    return function_body

def contains_function_body(diff_lines, function_body):
    """
    Checks whether the diff contains a deleted version of the function body.

    Args:
        diff_lines (list): Diff lines (including deletions).
        function_body (list): Lines of function body.

    Returns:
        bool: True if function body is matched in deleted lines.
    """
    stripped_function_body = [line.strip() for line in function_body]
    stripped_diff_lines = [line[1:].strip() for line in diff_lines if line.startswith('-')]

    def is_subsequence(sub, main):
        iter_main = iter(main)
        return all(any(item == sub_item for sub_item in iter_main) for item in sub)

    return is_subsequence(stripped_function_body, stripped_diff_lines)

def normalize_line(line):
    """
    Normalize line by removing all spaces and tabs.

    Args:
        line (str): A source code line.

    Returns:
        str: Normalized line.
    """
    return line.replace('\t', '').replace(' ', '')

def remove_sublist_new(main_list, sublist):
    """
    Remove a specific sublist from the main diff list (new additions).

    Args:
        main_list (list): The main list of diff lines.
        sublist (list): Sublist to be removed.

    Returns:
        list: Modified main list with sublist removed.
    """
    sublist_with_plus = ['+' + line for line in sublist]
    sublist_len = len(sublist_with_plus)
    for i in range(len(main_list)):
        if main_list[i:i + sublist_len] == sublist_with_plus:
            del main_list[i:i + sublist_len]
            break
    return main_list

def remove_sublist_tran_1(main_list, sublist):
    """
    Remove lines (e.g. function body) from diff regardless of leading whitespace.

    Args:
        main_list (list): The full diff block.
        sublist (list): The lines to remove.

    Returns:
        list: Diff with sublist removed.
    """
    sublist_with_plus = ['-' + line for line in sublist]
    normalized_sublist = [normalize_line(line) for line in sublist_with_plus]
    sublist_len = len(normalized_sublist)
    for i in range(len(main_list) - sublist_len + 1):
        main_list_segment = [normalize_line(line) for line in main_list[i:i + sublist_len]]
        if main_list_segment == normalized_sublist:
            del main_list[i:i + sublist_len]
            break
    return main_list

def remove_sublist_tran_2(lst, substrings):
    """
    Remove lines containing a specific substring.

    Args:
        lst (list): List of lines.
        substrings (str): Substring to match.

    Returns:
        list: List with matching lines removed.
    """
    return [line for line in lst if substrings not in line]

def clean_and_check_list(lst):
    """
    Check if a diff block contains valid + or - lines.

    Args:
        lst (list): Diff block.

    Returns:
        bool: True if it contains valid code lines.
    """
    cleaned_list = [
        line for line in lst
        if not ((line.startswith('+') or line.startswith('-')) and line.strip() in ('+', '-', ''))
    ]
    for line in cleaned_list:
        if (line.startswith('+') or line.startswith('-')) and line.strip() not in ('+', '-', ''):
            return True
    return False

def detect_extracted_method(diff):
    """
    Detect function extraction refactoring from a diff.

    Args:
        diff (list): List of lines from the patch file.

    Returns:
        list: Cleaned diff list with extracted functions processed.
    """
    flag = 0
    sections = []
    temp = []
    for line in diff:
        line = line.rstrip()
        if line.startswith('@@'):
            if temp:
                sections.append(temp)
                temp = []
            temp.append(line)
        else:
            temp.append(line)
    sections.append(temp)

    new = False
    refactor = False
    for i, ev_list in enumerate(sections):
        new_funcs = find_new_functions(ev_list)
        if new_funcs:
            new_func_flag = i + 1
            new_func_code = new_funcs[0]
            for line in new_funcs[0]:
                if any(line.startswith(t) for t in types) and '(' in line and ')' in line:
                    func_name = extract_function_name(line)
            func_body = extract_function_body(new_funcs[0])
            new = True
            break

    if new:
        for i, ev_list in enumerate(sections):
            trans_flag = any(contains_element_but_not_function_def(line, func_name) for line in ev_list)
            if trans_flag and contains_function_body(ev_list, func_body):
                tran_func_flag = i + 1
                refactor = True
                print("Refactoring detected: function extracted")

        if refactor:
            sections[new_func_flag - 1] = remove_sublist_new(sections[new_func_flag - 1], new_func_code)
            sections[tran_func_flag - 1] = remove_sublist_tran_2(
                remove_sublist_tran_1(sections[tran_func_flag - 1], func_body),
                func_name
            )

    return [sec for sec in sections if clean_and_check_list(sec)]

def refactor_detect_extracted(patch_file):
    """
    Detect extracted method refactorings from patch file.

    Args:
        patch_file (str): Path to patch file.

    Returns:
        list: Cleaned diff sections.
    """
    with open(patch_file, "r") as file:
        diff = file.readlines()
    return detect_extracted_method(diff)

def find_duplicates(list1, list2):
    """
    Find duplicate elements in two lists.

    Args:
        list1 (list): First list.
        list2 (list): Second list.

    Returns:
        list: List of duplicates.
    """
    return list(set(list1) & set(list2))

def refactor_rename(diffs):
    """
    Detect renaming refactoring in diffs.

    Args:
        diffs (list): List of diff blocks.

    Returns:
        list: Processed diff blocks with renaming handled.
    """
    func_definition_del = []
    func_definition_add = []
    rename_flag = 0
    for diff in diffs:
        for line in diff:
            if line.startswith('+'):
                stripped_line = line[1:]
                if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                    func_name = extract_function_name(line)
                    func_definition_add.append(func_name)
            if line.startswith('-'):
                stripped_line = line[1:]
                if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                    func_name = extract_function_name(line)
                    func_definition_del.append(func_name)
    duplicate = find_duplicates(func_definition_add, func_definition_del)
    if duplicate:
        print("Renaming detected!")
        rename_diff = []
        for diff_idx, diff in enumerate(diffs):
            for line in diff:
                if line.startswith('+'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                        func_name = extract_function_name(line)
                        if func_name == duplicate[0]:
                            rename_flag = diff_idx + 1
                            rename_diff = remove_sublist_tran_2(rename_diff, line)
                if line.startswith('-'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                        func_name = extract_function_name(line)
                        if func_name == duplicate[0]:
                            rename_diff = remove_sublist_tran_2(diff, line)
            if rename_flag - 1 < len(diffs):
                diffs[rename_flag - 1] = rename_diff

    return [diff for diff in diffs if clean_and_check_list(diff)]

def remove_special_comments(code_list):
    """
    Remove special comments from code list (starting with //, /*, */ etc.).

    Args:
        code_list (list): List of code lines.

    Returns:
        list: List with comments removed.
    """
    result = []
    for line in code_list:
        stripped_line = line.lstrip()
        if stripped_line.startswith('+') or stripped_line.startswith('-'):
            stripped_line = stripped_line[1:].lstrip()
            stripped_line = stripped_line.lstrip('\t')
            if not (stripped_line.startswith('//') or stripped_line.startswith('/*') or
                    stripped_line.startswith('*/') or stripped_line.startswith('* ')):
                result.append(line)
        else:
            result.append(line)
    return result

def delete_comment(lst):
    """
    Remove comments from all diff blocks.

    Args:
        lst (list): List of diff blocks.

    Returns:
        list: Diff blocks with comments removed.
    """
    list_1 = [remove_special_comments(diff) for diff in lst]
    return [diff for diff in list_1 if clean_and_check_list(diff)]

def refactor_new_func(diffs):
    """
    Remove newly added functions that are not called anywhere.

    Args:
        diffs (list): Diff blocks.

    Returns:
        list: Updated diffs with uncalled new functions removed.
    """
    again = False
    new = False
    new_func_flag = 0
    for i, ev_list in enumerate(diffs):
        new_funcs = find_new_functions(ev_list)
        if new_funcs:
            print("New function detected!")
            if len(new_funcs) != 1:
                again = True
            new_func_flag = i + 1
            new_func_code = new_funcs[0]
            new = True
            break

    if new and new_func_flag != 0:
        diffs[new_func_flag - 1] = remove_sublist_new(diffs[new_func_flag - 1], new_func_code)

    if again:
        diffs = refactor_new_func(diffs)

    if diffs:
        return [diff for diff in diffs if clean_and_check_list(diff)]
    else:
        print("Error occurred")
        return diffs

def refactor_empty_line(diffs):
    """
    Remove empty added/removed lines from diffs.

    Args:
        diffs (list): List of diff blocks.

    Returns:
        list: Cleaned diff blocks.
    """
    new_diffs = []
    for diff in diffs:
        new_diff = []
        for line in diff:
            if line.startswith('+') or line.startswith('-'):
                strip_line = line[1:].lstrip()
                if strip_line:
                    new_diff.append(line)
            else:
                new_diff.append(line)
        new_diffs.append(new_diff)
    return new_diffs

def old_and_new_name(diffs):
    """
    Find old and new function names in diffs (detect renaming).

    Args:
        diffs (list): List of diff blocks.

    Returns:
        tuple: (rename_flag (bool), old_names (list), new_names (list))
    """
    func_definition_del = []
    func_definition_add = []
    new_name_b_file = []
    new_name_a_file = []
    RENAME = False
    for diff in diffs:
        for line in diff:
            if line.startswith('+'):
                stripped_line = line[1:]
                if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                    func_name = extract_function_name(line)
                    func_definition_add.append(func_name)
            if line.startswith('-'):
                stripped_line = line[1:]
                if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                    func_name = extract_function_name(line)
                    func_definition_del.append(func_name)
    duplicate = find_duplicates(func_definition_add, func_definition_del)
    if duplicate:
        print("Renaming detected!")
        RENAME = True
        rename_diff = []
        rename_flag = 0
        for diff_idx, diff in enumerate(diffs):
            for line in diff:
                if line.startswith('+'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                        func_name = extract_function_name(line)
                        if func_name == duplicate[0]:
                            new_name_b_file.append(stripped_line)
                            rename_flag = diff_idx + 1
                            rename_diff = remove_sublist_tran_2(rename_diff, line)
                if line.startswith('-'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in types) and '(' in line and ')' in line:
                        func_name = extract_function_name(line)
                        if func_name == duplicate[0]:
                            new_name_a_file.append(stripped_line)
                            rename_diff = remove_sublist_tran_2(diff, line)
    return RENAME, new_name_a_file, new_name_b_file

def old_and_new_func(cve_id):
    """
    Handle refactor detection for extracted methods and renaming based on a CVE patch.

    Args:
        cve_id (str): CVE identifier.

    Returns:
        tuple: (rename_flag, old_names, new_names)
    """
    list1 = refactor_detect_extracted("../" + cve_id + "/patch.txt")
    RENAME, new_name_a_file, new_name_b_file = old_and_new_name(list1)
    return RENAME, new_name_a_file, new_name_b_file

def main(cve_id):
    """
    Main entry to perform refactoring detection on a patch file.

    Args:
        cve_id (str): CVE identifier.

    Returns:
        list: Processed diff blocks after all refactorings and cleaning.
    """
    list1 = refactor_detect_extracted("../" + cve_id + "/patch.txt")
    list2 = refactor_rename(list1)
    list3 = delete_comment(list2)
    list4 = refactor_new_func(list3)
    list5 = refactor_empty_line(list4)
    return list5

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
    old_and_new_func(CVE_id)
