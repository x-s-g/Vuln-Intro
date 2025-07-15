import re

class PatchRefactor:
    types = [
        'static ', 'struct ', 'int ', 'short ', 'long ', 'long long ', 'unsigned int ',
        'unsigned short ', 'unsigned long ', 'unsigned long long ', 'signed int ',
        'signed short ', 'signed long ', 'signed long long ', 'float ', 'double ',
        'long double ', 'char ', 'unsigned char ', 'signed char ', 'void ', 'enum ', 'union ', '__cold'
    ]

    @staticmethod
    def find_new_functions(lines):
        """
        Identify newly added functions from diff lines.
        """
        in_function_body = False  # Track if inside function body
        new_functions = []  # Store identified new functions
        current_function = []  # Store current function lines

        for line in lines:
            if not line.strip():
                continue

            if line.startswith('+'):
                stripped_line = line[1:]

                if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in stripped_line and ')' in stripped_line:
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

    @staticmethod
    def extract_function_name(c_code_line):
        """
        Extract function name from a C function definition line.
        """
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{?'
        match = re.search(pattern, c_code_line)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def contains_element_but_not_function_def(line, element):
        """
        Check if a diff line contains a specific element but is NOT a function definition.
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

    @staticmethod
    def extract_function_body(lines):
        """
        Extract the body of a function from a list of lines.
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

    @staticmethod
    def contains_function_body(diff_lines, function_body):
        """
        Check if the diff contains the given function body.
        """
        stripped_function_body = [line.strip() for line in function_body]
        stripped_diff_lines = [line[1:].strip() for line in diff_lines if line.startswith('-')]

        def is_subsequence(sub, main):
            iter_main = iter(main)
            return all(any(item == sub_item for sub_item in iter_main) for item in sub)

        return is_subsequence(stripped_function_body, stripped_diff_lines)

    @staticmethod
    def remove_sublist_new(main_list, sublist):
        """
        Remove a specified sublist from the main list (for added lines with '+').
        """
        sublist_with_plus = ['+' + line for line in sublist]
        sublist_len = len(sublist_with_plus)

        for i in range(len(main_list)):
            if main_list[i:i + sublist_len] == sublist_with_plus:
                del main_list[i:i + sublist_len]
                break
        return main_list

    @staticmethod
    def normalize_line(line):
        """
        Remove all spaces and tabs from a line.
        """
        return line.replace('\t', '').replace(' ', '')

    @staticmethod
    def remove_sublist_tran_1(main_list, sublist):
        """
        Remove a specified sublist from the main list ignoring leading spaces and tabs.
        """
        sublist_with_minus = ['-' + line for line in sublist]
        normalized_sublist = [PatchRefactor.normalize_line(line) for line in sublist_with_minus]
        sublist_len = len(normalized_sublist)

        for i in range(len(main_list) - sublist_len + 1):
            main_list_segment = [PatchRefactor.normalize_line(line) for line in main_list[i:i + sublist_len]]
            if main_list_segment == normalized_sublist:
                del main_list[i:i + sublist_len]
                break

        return main_list

    @staticmethod
    def remove_sublist_tran_2(lst, substrings):
        """
        Remove lines containing the specified substring from the list.
        """
        return [line for line in lst if substrings not in line]

    @staticmethod
    def clean_and_check_list(lst):
        """
        Check and clean a list by removing invalid + or - lines,
        then check if valid + or - lines exist.
        """
        cleaned_list = [
            line for line in lst
            if not ((line.startswith('+') or line.startswith('-')) and line.strip() in ('+', '-', ''))
        ]

        for line in cleaned_list:
            if (line.startswith('+') or line.startswith('-')) and line.strip() not in ('+', '-', ''):
                return True
        return False

    @staticmethod
    def detect_extracted_method(diff):
        """
        Detect extracted method refactoring from patch diff lines.
        """
        flag = 0
        chunks = []
        current_chunk = []

        for line in diff:
            line = line.rstrip()
            if line.startswith('@@'):
                if not current_chunk:
                    current_chunk.append(line)
                    continue
                else:
                    chunks.append(current_chunk)
                    current_chunk = [line]
                    continue
            current_chunk.append(line)
        chunks.append(current_chunk)

        new = False
        refactor = False
        new_func_flag = 0
        tran_func_flag = 0
        new_func_code = []
        func_name = None
        func_body = []

        for ev_list in chunks:
            flag += 1
            new_funcs = PatchRefactor.find_new_functions(ev_list)

            if new_funcs:
                new_func_flag = flag
                new_func_code = new_funcs[0]

                for line in new_func_code:
                    if any(line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                        func_name = PatchRefactor.extract_function_name(line)
                func_body = PatchRefactor.extract_function_body(new_func_code)
                new = True

        if new:
            flag = 0
            for ev_list in chunks:
                flag += 1
                trans_flag = False
                for line in ev_list:
                    if PatchRefactor.contains_element_but_not_function_def(line, func_name):
                        trans_flag = True

                if trans_flag:
                    if PatchRefactor.contains_function_body(ev_list, func_body):
                        tran_func_flag = flag
                        refactor = True
                        print("Refactoring detected")

            if refactor:
                flag = 0
                for ev_list in chunks:
                    flag += 1
                    if flag == new_func_flag and new_func_flag != 0:
                        result_new_list = PatchRefactor.remove_sublist_new(ev_list, new_func_code)
                    if flag == tran_func_flag and tran_func_flag != 0:
                        result_tran_list_1 = PatchRefactor.remove_sublist_tran_1(ev_list, func_body)
                        result_tran_list_2 = PatchRefactor.remove_sublist_tran_2(result_tran_list_1, func_name)

                chunks[new_func_flag - 1] = result_new_list
                chunks[tran_func_flag - 1] = result_tran_list_2

        real_list = []
        for diff_chunk in chunks:
            if PatchRefactor.clean_and_check_list(diff_chunk):
                real_list.append(diff_chunk)

        return real_list

    @staticmethod
    def refactor_detect_extracted(patch_file):
        """
        Read patch file and detect extracted method refactoring.
        """
        with open(patch_file, "r") as file:
            diff = file.readlines()
        return PatchRefactor.detect_extracted_method(diff)

    @staticmethod
    def find_duplicates(list1, list2):
        """
        Find duplicate elements in two lists.
        """
        duplicates = list(set(list1) & set(list2))
        return duplicates

    @staticmethod
    def refactor_rename(diffs):
        """
        Detect and process function renaming in diffs.
        """
        func_definition_del = []
        func_definition_add = []
        rename_flag = 0

        for diff in diffs:
            for line in diff:
                if line.startswith('+'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                        func_name = PatchRefactor.extract_function_name(line)
                        func_definition_add.append(func_name)
                if line.startswith('-'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                        func_name = PatchRefactor.extract_function_name(line)
                        func_definition_del.append(func_name)

        duplicate = PatchRefactor.find_duplicates(func_definition_add, func_definition_del)
        if duplicate:
            print("Renaming detected!")
            rename_diff = []
            flag = 0
            for diff in diffs:
                flag += 1
                for line in diff:
                    if line.startswith('+'):
                        stripped_line = line[1:]
                        if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                            func_name = PatchRefactor.extract_function_name(line)
                            if func_name == duplicate[0]:
                                rename_flag = flag
                                rename_diff = PatchRefactor.remove_sublist_tran_2(rename_diff, line)
                    if line.startswith('-'):
                        stripped_line = line[1:]
                        if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                            func_name = PatchRefactor.extract_function_name(line)
                            if func_name == duplicate[0]:
                                rename_diff = PatchRefactor.remove_sublist_tran_2(diff, line)

            diffs[rename_flag - 1] = rename_diff

        real_list = [diff for diff in diffs if PatchRefactor.clean_and_check_list(diff)]
        return real_list

    @staticmethod
    def remove_special_comments(code_list):
        """
        Remove lines that are special comments from a code list.
        """
        result = []
        for line in code_list:
            stripped_line = line.lstrip()
            if stripped_line.startswith('+') or stripped_line.startswith('-'):
                stripped_line = stripped_line[1:].lstrip().lstrip('\t')
                if not (stripped_line.startswith('//') or stripped_line.startswith('/*') or
                        stripped_line.startswith('*/') or stripped_line.startswith('* ')):
                    result.append(line)
            else:
                result.append(line)
        return result

    @staticmethod
    def delete_comment(lst):
        """
        Remove comments from a list of diffs.
        """
        list_1 = [PatchRefactor.remove_special_comments(diff) for diff in lst]
        real_list = [diff for diff in list_1 if PatchRefactor.clean_and_check_list(diff)]
        return real_list

    @staticmethod
    def refactor_new_func(diffs):
        """
        Remove unused newly added functions from diffs.
        """
        again = False
        new = False
        new_func_flag = 0

        for ev_list in diffs:
            new_funcs = PatchRefactor.find_new_functions(ev_list)
            if new_funcs:
                print("New function detected!")
                if len(new_funcs) != 1:
                    again = True
                new_func_flag = diffs.index(ev_list) + 1
                new_func_code = new_funcs[0]
                new = True

        if new:
            for idx, ev_list in enumerate(diffs, 1):
                if idx == new_func_flag and new_func_flag != 0:
                    result_new_list = PatchRefactor.remove_sublist_new(ev_list, new_func_code)
                    diffs[idx - 1] = result_new_list

        if again:
            diffs = PatchRefactor.refactor_new_func(diffs)

        if diffs is not None:
            real_list = [diff for diff in diffs if PatchRefactor.clean_and_check_list(diff)]
            return real_list
        else:
            print("Error occurred")
            return []

    @staticmethod
    def refactor_empty_line(diffs):
        """
        Remove empty added or removed lines from diffs.
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

    @staticmethod
    def old_and_new_name(diffs):
        """
        Identify renamed functions and collect old and new names.
        """
        func_definition_del = []
        func_definition_add = []
        new_name_b_file = []
        new_name_a_file = []
        rename_flag = 0
        flag = 0
        RENAME = False

        for diff in diffs:
            for line in diff:
                if line.startswith('+'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                        func_name = PatchRefactor.extract_function_name(line)
                        func_definition_add.append(func_name)
                if line.startswith('-'):
                    stripped_line = line[1:]
                    if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                        func_name = PatchRefactor.extract_function_name(line)
                        func_definition_del.append(func_name)

        duplicate = PatchRefactor.find_duplicates(func_definition_add, func_definition_del)
        if duplicate:
            print("Renaming detected!")
            RENAME = True
            rename_diff = []
            for diff in diffs:
                flag += 1
                for line in diff:
                    if line.startswith('+'):
                        stripped_line = line[1:]
                        if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                            func_name = PatchRefactor.extract_function_name(line)
                            if func_name == duplicate[0]:
                                new_name_b_file.append(stripped_line)
                                rename_flag = flag
                                rename_diff = PatchRefactor.remove_sublist_tran_2(rename_diff, line)
                    if line.startswith('-'):
                        stripped_line = line[1:]
                        if any(stripped_line.startswith(t) for t in PatchRefactor.types) and '(' in line and ')' in line:
                            func_name = PatchRefactor.extract_function_name(line)
                            if func_name == duplicate[0]:
                                new_name_a_file.append(stripped_line)
                                rename_diff = PatchRefactor.remove_sublist_tran_2(diff, line)

        return RENAME, new_name_a_file, new_name_b_file

    @staticmethod
    def old_and_new_func(cve_id):
        """
        Process refactoring extraction and renaming for given CVE patch file.
        """
        list1 = PatchRefactor.refactor_detect_extracted(f"CVE-1/{cve_id}/patch.txt")
        RENAME, new_name_a_file, new_name_b_file = PatchRefactor.old_and_new_name(list1)
        return RENAME, new_name_a_file, new_name_b_file

    @staticmethod
    def main(cve_id):
        """
        Main function to process patch file for extracted methods, renaming, comment removal, unused new functions, and empty line cleanup.
        """
        list1 = PatchRefactor.refactor_detect_extracted(f"CVE-1/{cve_id}/patch.txt")
        list2 = PatchRefactor.refactor_rename(list1)
        list3 = PatchRefactor.delete_comment(list2)
        list4 = PatchRefactor.refactor_new_func(list3)
        list5 = PatchRefactor.refactor_empty_line(list4)
        return list5

# ====================== Program Entry ======================

if __name__ == "__main__":
    CVE_id = "CVE-2023-45863"
    processed_diffs = PatchRefactor.main(CVE_id)
    rename_info = PatchRefactor.old_and_new_func(CVE_id)
