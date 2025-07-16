import sys
import os

# Add parent directories to the module search path for custom imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Data_Crawling')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Static_Analysis')))

# Import internal modules and standard libraries
import af_ast
import af_cfg
import af_code
import bf_ast
import bf_cfg
import bf_code
import select_path
import filter
import re
from pycparser import c_parser, c_ast
from collections import Counter


def find_impacting_lines_back(lines, target_line):
    """
    Find lines impacted by the target line (data flow forward).
    Parameters:
        lines (list): All lines of code in the function.
        target_line (int): Target line number (1-based index).
    Returns:
        dict: Line numbers and code strings that are impacted.
    """
    impacting_lines = {}
    target_code = lines[target_line - 1].strip()
    dependencies = extract_variables_back(target_code)

    for lineno in range(target_line + 1, len(lines) + 1):
        line = lines[lineno - 1].strip()
        current_vars = extract_variables_back(line)

        flag = False
        var = []
        for i in current_vars:
            for j in dependencies:
                if i == j.split("->", 1)[0] or j == i.split("->", 1)[0]:
                    flag = True
                    var.append(j)
        if flag and var:
            impacting_lines[lineno] = line
            for i in var:
                dependencies.discard(i)

        if dependencies.intersection(current_vars):
            flag = dependencies.intersection(current_vars)
            impacting_lines[lineno] = line
            for i in flag:
                dependencies.discard(i)

    return impacting_lines


def extract_variables_back(expression):
    """
    Extract variables used in a line (forward direction, for target impact analysis).
    Parameters:
        expression (str): A single line of C code.
    Returns:
        set: Set of variable names extracted.
    """
    expression = expression.strip().rstrip(';')
    expression = re.sub(r'\b\w+\s*\(', '(', expression)

    if expression.startswith("return "):
        return set(re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', expression[len("return "):]))

    variables_str = re.findall(r'\((.*?)\)', expression)
    if variables_str:
        return {var.strip() for var in re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', variables_str[0])}

    if "=" in expression:
        _, expression_right = expression.split("=", 1)
        return set(re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', expression_right))

    return set()


def find_impacting_lines_front(lines, target_line):
    """
    Find lines that influence the target line (data flow backward).
    Parameters:
        lines (list): All lines of code in the function.
        target_line (int): Target line number (1-based index).
    Returns:
        dict: Line numbers and code strings that affect the target.
    """
    dependencies = set()
    impacting_lines = {}
    target_code = lines[target_line - 1].strip()
    dependencies = extract_variables_front(target_code)

    for lineno in range(target_line - 1, 0, -1):
        line = lines[lineno - 1].strip()

        if "=" in line:
            var_name, expression = extract_assignment(line)
            var_name = var_name.strip()
            flag_dep = False
            var = []
            for i in dependencies:
                if var_name == i.split("->", 1)[0]:
                    flag_dep = True
                    var.append(i)
            if flag_dep and var:
                impacting_lines[lineno] = line
                for i in var:
                    dependencies.discard(i)
            if var_name in dependencies:
                impacting_lines[lineno] = line
                dependencies.discard(var_name)

        if is_function_call(line):
            func_call_vars = extract_variables_front(line)
            flag_dep = False
            var = []
            for i in dependencies:
                for j in func_call_vars:
                    if j == i.split("->", 1)[0]:
                        flag_dep = True
                        var.append(i)
            if flag_dep and var:
                impacting_lines[lineno] = line
                for i in var:
                    dependencies.discard(i)
            if dependencies.intersection(func_call_vars):
                flag = dependencies.intersection(func_call_vars)
                impacting_lines[lineno] = line
                for i in flag:
                    dependencies.discard(i)

    impacting_lines_sorted = dict(sorted(impacting_lines.items()))
    return impacting_lines_sorted


def extract_variables_front(expression):
    """
    Extract variables from a line of code (used in backward analysis).
    """
    expression = expression.strip().rstrip(';')
    variables = set()
    expression = re.sub(r'\([^\(\)]*\*\)', '', expression)

    variable_pattern = re.compile(r'\b[a-zA-Z_]\w*(?:\s*->\s*[a-zA-Z_]\w*|\s*\.\s*[a-zA-Z_]\w*)*\b')
    exclude_pattern = re.compile(
        r'^(if|else|for|while|return|switch|case|default|break|continue|do|sizeof|typedef|enum|struct|union|static|extern|const|volatile|register|signed|unsigned|int|long|short|float|double|char|void|unsigned|static|inline|__inline|goto|restrict|_Bool|_Complex|_Imaginary|alignof|alignas|asm|auto|bool|complex|imaginary|noreturn|static_assert|thread_local|_Atomic|_Generic|_Noreturn|_Static_assert|_Thread_local|[A-Z_]+)$')

    def parse_expression(expr):
        for var in variable_pattern.finditer(expr):
            var_name = var.group().strip()
            if not exclude_pattern.match(var_name):
                variables.add(var_name)

    parse_expression(expression)
    return variables


def extract_assignment(line):
    """
    Extract the left and right parts of an assignment expression.
    """
    line = line.strip()
    if "=" in line:
        left, right = line.split("=", 1)
        left = left.strip()
        right = right.strip()
        var_name = left.split()[-1]
        if var_name.startswith('*'):
            var_name = var_name[1:]
        return var_name, right
    elif "->" in line:
        left, right = line.split("->", 1)
        left = left.strip()
        right = right.strip()
        return left, right
    return "", line


def is_function_call(line):
    """
    Determine if a line is a function call (not a control structure).
    """
    line = re.sub(r'\s*//.*$', '', line).strip()
    pattern = r'^\s*\w+\s*\([^)]*\)\s*(?:;|\s*$)'
    if re.search(pattern, line):
        return not any(keyword in line for keyword in ['while', 'if', 'for', 'switch', 'case', 'default', 'do'])
    return False


def b_to_a(target, code_b, code_a, bf_paths, diff):
    """
    Map a target line number in code_b to its corresponding line number in code_a.

    Parameters:
        target (int): Target line number in code_b.
        code_b (list): List of lines from code version B.
        code_a (list): List of lines from code version A.
        bf_paths (list): Paths related to code_b for analysis.
        diff (list): List of diff lines for reference.

    Returns:
        int or None: Corresponding line number in code_a if found, else None.
    """
    flag = False
    count = 0
    pre = None
    next = None
    target_line = None

    # Iterate over code_b lines to find target and its surrounding lines
    for line in code_b:
        count += 1
        if count == target:
            target_line = line
            flag = True
        if not flag:
            flag_pre = False
            for bf_path in bf_paths:
                if line in bf_path[0] and bf_path[0].startswith("+"):
                    flag_pre = True
            if not flag_pre:
                pre = line
        if flag and count != target:
            flag_next = False
            for bf_path in bf_paths:
                if line in bf_path[0] and bf_path[0].startswith("+"):
                    flag_next = True
            if not flag_next:
                next = line
                break

    flag_pre = False
    flag_next = False
    target_num = None
    count = 0

    # Search corresponding line number in code_a based on pre and next lines
    for line in code_a:
        count += 1
        if line == pre:
            flag_pre = True
        if flag_pre:
            if line == target_line:
                target_num = count
        if line == next and target_num is not None:
            return target_num

    return target_num


def remove_duplicates(nested_list):
    """
    Remove duplicate sublists from a nested list.

    Parameters:
        nested_list (list of lists): Input nested list with possible duplicates.

    Returns:
        list of lists: Nested list with duplicates removed.
    """
    seen = set()
    unique_list = []
    for sublist in nested_list:
        sublist_tuple = tuple(sublist)
        if sublist_tuple not in seen:
            seen.add(sublist_tuple)
            unique_list.append(sublist)
    return unique_list


def label_A(bf_path, list1_b, list1_a, diff, num, bf_paths):
    """
    Trace data flow for added code, returning upstream and downstream impacting code lines.

    Rules:
    - If both front and back are additions, discard.
    - If one side is addition, record the other.
    - If neither side is addition, record both.

    Parameters:
        bf_path (list): Path info related to added code.
        list1_b (list): Lines of code from B version.
        list1_a (list): Lines of code from A version.
        diff (list): Diff lines.
        num (int): Index for current diff block.
        bf_paths (list): Paths for code B.

    Returns:
        list: List of traces showing impacting lines and their info.
    """
    front = []
    back = []
    traces = []

    # Iterate paths to find impacting lines front and back of the target
    for path in bf_path[4:]:
        codes = []
        flag = None
        line_num = 0
        for node in path:
            line_num += 1
            if node.coord.line == bf_path[2].coord.line:
                flag = line_num
            code = select_path.get_line_from_code(list1_b[num].splitlines(), node.coord.line)
            codes.append(code)

        impacting_lines_front = find_impacting_lines_front(codes, flag)
        for lineno, code_line in impacting_lines_front.items():
            ev_front = []
            flag_front = None
            line_num = 0
            for node in path:
                line_num += 1
                if line_num == lineno:
                    flag_front = node.coord.line
            ev_front.append(flag_front)
            ev_front.append(code_line)
            front.append(ev_front)

        impacting_lines_back = find_impacting_lines_back(codes, flag)
        for lineno, code_line in impacting_lines_back.items():
            ev_back = []
            flag_back = None
            line_num = 0
            for node in path:
                line_num += 1
                if line_num == lineno:
                    flag_back = node.coord.line
            ev_back.append(flag_back)
            ev_back.append(code_line)
            back.append(ev_back)

    front = remove_duplicates(front)
    back = remove_duplicates(back)

    for f in front:
        if f is None:
            continue
        front_num = b_to_a(f[0], list1_b[num].splitlines(), list1_a[num].splitlines(), bf_paths, diff)
        trace = [
            af_code.remove_location_info(diff[0]),
            front_num,
            f[1]
        ]
        traces.append(trace)

    for b in back:
        if b is None:
            continue
        back_num = b_to_a(b[0], list1_b[num].splitlines(), list1_a[num].splitlines(), bf_paths, diff)
        trace = [
            af_code.remove_location_info(diff[0]),
            back_num,
            b[1]
        ]
        traces.append(trace)

    traces = remove_duplicates(traces)
    return traces


def label_D(af_path, diff):
    """
    Trace deleted code lines.

    Parameters:
        af_path (list): Path info related to deleted code.
        diff (list): Diff lines.

    Returns:
        list or None: Trace info for deleted line or None if not applicable.
    """
    if af_path[2] is not None:
        trace = [
            af_code.remove_location_info(diff[0]),
            af_path[2].coord.line,
            af_path[0].split("-", 1)[1]
        ]
        return trace
    return None


def label_M_1(af_path, diff):
    """
    Trace modified code, version M.1.

    Parameters:
        af_path (list): Path info related to modified code.
        diff (list): Diff lines.

    Returns:
        list: Trace info of the modified line.
    """
    trace = [
        af_code.remove_location_info(diff[0]),
        af_path[2].coord.line,
        af_path[0].split("-", 1)[1]
    ]
    return trace


def label_M_2(af_path, diff):
    """
    Trace modified code, version M.2.

    Parameters:
        af_path (list): Path info related to modified code.
        diff (list): Diff lines.

    Returns:
        list: Trace info of the modified line.
    """
    trace = [
        af_code.remove_location_info(diff[0]),
        af_path[2].coord.line,
        af_path[0].split("-", 1)[1]
    ]
    return trace


def label_M_3(af_path, diff):
    """
    Trace modified code, version M.3.

    Parameters:
        af_path (list): Path info related to modified code.
        diff (list): Diff lines.

    Returns:
        list: Trace info of the modified line.
    """
    trace = [
        af_code.remove_location_info(diff[0]),
        af_path[2].coord.line,
        af_path[0].split("-", 1)[1]
    ]
    return trace


def label_M_4(af_path, list1_b, list1_a, diff, num, bf_paths):
    """
    Trace modified code lines with backward and forward data flow.

    Parameters:
        af_path (list): Path info for modified code.
        list1_b (list): Lines from code B.
        list1_a (list): Lines from code A.
        diff (list): Diff lines.
        num (int): Index of current diff block.
        bf_paths (list): Paths for code B.

    Returns:
        list: List of traces showing impacted lines.
    """
    front = []
    back = []
    traces = []

    for path in af_path[4:]:
        codes = []
        flag = None
        line_num = 0
        for node in path:
            line_num += 1
            if node.coord.line == af_path[2].coord.line:
                flag = line_num
            code = select_path.get_line_from_code(list1_a[num].splitlines(), node.coord.line)
            codes.append(code)

        impacting_lines_front = find_impacting_lines_front(codes, flag)
        for lineno, code_line in impacting_lines_front.items():
            ev_front = []
            flag_front = None
            line_num = 0
            for node in path:
                line_num += 1
                if line_num == lineno:
                    flag_front = node.coord.line
            ev_front.append(flag_front)
            ev_front.append(code_line)
            front.append(ev_front)

        impacting_lines_back = find_impacting_lines_back(codes, flag)
        for lineno, code_line in impacting_lines_back.items():
            ev_back = []
            flag_back = None
            line_num = 0
            for node in path:
                line_num += 1
                if line_num == lineno:
                    flag_back = node.coord.line
            ev_back.append(flag_back)
            ev_back.append(code_line)
            back.append(ev_back)

    front = remove_duplicates(front)
    back = remove_duplicates(back)

    for f in front:
        if f is None:
            continue
        trace = [
            af_code.remove_location_info(diff[0]),
            f[0],
            f[1]
        ]
        traces.append(trace)

    for b in back:
        if b is None:
            continue
        trace = [
            af_code.remove_location_info(diff[0]),
            b[0],
            b[1]
        ]
        traces.append(trace)

    traces = remove_duplicates(traces)

    trace = [
        af_code.remove_location_info(diff[0]),
        af_path[2].coord.line,
        af_path[0].split("-", 1)[1]
    ]
    traces.append(trace)

    return traces


def label_M_5(bf_path, list1_b, list1_a, diff, num, bf_paths):
    """
    Trace control dependencies before and after M.5 modified code lines.

    Rules:
    - If both front and back are additions (including empty back node), discard.
    - If one side is addition, record the other side.

    Parameters:
        bf_path (list): Path info for modified code.
        list1_b (list): Lines from code B.
        list1_a (list): Lines from code A.
        diff (list): Diff lines.
        num (int): Index of current diff block.
        bf_paths (list): Paths for code B.

    Returns:
        list: List of traces showing control dependencies.
    """
    traces = []
    front_loc, back_loc = select_path.front_and_back_node(bf_path)

    if front_loc:
        for front in front_loc:
            trace = []
            front_code = select_path.get_line_from_code(list1_b[num].splitlines(), front)
            flag = False
            for line in diff:
                if front_code in line and line.startswith("+"):
                    flag = True
            if not flag:
                front = b_to_a(front, list1_b[num].splitlines(), list1_a[num].splitlines(), bf_paths, diff)
                if front is None:
                    continue
                trace = [
                    af_code.remove_location_info(diff[0]),
                    front,
                    front_code
                ]
                traces.append(trace)

    if back_loc:
        for back in back_loc:
            trace = []
            back_code = select_path.get_line_from_code(list1_b[num].splitlines(), back)
            flag = False
            for line in diff:
                if back_code in line:
                    flag = True
            if not flag:
                back = b_to_a(back, list1_b[num].splitlines(), list1_a[num].splitlines(), bf_paths, diff)
                if back is None:
                    continue
                trace = [
                    af_code.remove_location_info(diff[0]),
                    back,
                    back_code
                ]
                traces.append(trace)

    return traces


def main(CVE_id):
    """
    Main function to trace vulnerability based on CVE id.

    Parameters:
        CVE_id (str): CVE identifier string.

    Returns:
        list: All vulnerability traces found.
    """
    # Get patched code blocks from A and B versions
    list1_a, count_a = af_code.main(CVE_id)
    list1_b, count_b = bf_code.main(CVE_id)

    # Filtered patch content
    list2 = filter.main(CVE_id)

    # Get control flow paths from A and B
    af_paths, count_a = af_cfg.main(CVE_id)
    bf_paths, count_b = bf_cfg.main(CVE_id)

    # Get AST storage and graphs
    storage_a, Gs_a, count_a = af_ast.main(CVE_id)
    storage_b, Gs_b, count_b = bf_ast.main(CVE_id)

    del_and_add_path = select_path.main(CVE_id)
    all_vuln_link = []

    for i in range(len(list2)):
        vuln_link = []

        # Process deleted code lines
        for af_path in del_and_add_path[i][0]:
            if af_path[1] == "D":
                trace_line = label_D(af_path, list2[i])
                if trace_line is not None:
                    vuln_link.append(trace_line)

            if af_path[1] in ("M.1", "M.2", "M.3", "M.5"):
                trace_line = label_M_1(af_path, list2[i])
                vuln_link.append(trace_line)

            if af_path[1] == "M.4":
                func_name = select_path.find_func_name(list2[i])
                num = select_path.find_code_in_list1(list1_a, func_name)
                traces = label_M_4(af_path, list1_b, list1_a, list2[i], num, del_and_add_path[i][1])
                for trace in traces:
                    if trace[1] is not None:
                        vuln_link.append(trace)

        # Process added code lines
        for bf_path in del_and_add_path[i][1]:
            if bf_path[1] == "A":
                func_name = select_path.find_func_name(list2[i])
                num = select_path.find_code_in_list1(list1_a, func_name)
                traces = label_A(bf_path, list1_b, list1_a, list2[i], num, del_and_add_path[i][1])
                for trace in traces:
                    if trace[1] is not None:
                        vuln_link.append(trace)

            if bf_path[1] == "M.5":
                func_name = select_path.find_func_name(list2[i])
                num = select_path.find_code_in_list1(list1_a, func_name)
                traces = label_M_5(bf_path, list1_b, list1_a, list2[i], num, del_and_add_path[i][1])
                for trace in traces:
                    if trace[1] is not None:
                        vuln_link.append(trace)

        vuln_link = remove_duplicates(vuln_link)
        for link in vuln_link:
            print(link)
        all_vuln_link.append(vuln_link)

    return all_vuln_link

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
