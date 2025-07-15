"""
Module: cve_trace_analysis.py

This module provides functions to trace vulnerability-related code changes in CVE patches.
It performs data flow analysis, code diff alignment, and change impact tracking.
"""

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
    Find lines that are forward data-dependent on the target line.

    Args:
        lines (list): List of C code lines.
        target_line (int): Line number to analyze.

    Returns:
        dict: Mapping from line number to line content for impacting lines.
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
    Extract variables from a C expression for backward analysis.

    Args:
        expression (str): C expression.

    Returns:
        set: Set of variables.
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
    Find lines that are backward data-dependent (impact the target line).

    Args:
        lines (list): Code lines.
        target_line (int): Line index.

    Returns:
        dict: Impacting lines sorted by line number.
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

    return dict(sorted(impacting_lines.items()))


def extract_variables_front(expression):
    """
    Extract variables for front (backward) analysis.

    Args:
        expression (str): C expression.

    Returns:
        set: Variables extracted.
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
    Parse an assignment line and return (variable, expression).

    Args:
        line (str): C code line.

    Returns:
        tuple: (lhs variable name, rhs expression).
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
        return left.strip(), right.strip()
    return "", line


def is_function_call(line):
    """
    Check if a line is a function call.

    Args:
        line (str): C source code line.

    Returns:
        bool: True if line is function call, False otherwise.
    """
    line = re.sub(r'\s*//.*$', '', line).strip()
    pattern = r'^\s*\w+\s*\([^)]*\)\s*(?:;|\s*$)'
    if re.search(pattern, line):
        return not any(keyword in line for keyword in ['while', 'if', 'for', 'switch', 'case', 'default', 'do'])
    return False


def b_to_a(target, code_b, code_a, bf_paths, diff):
    """
    Map a line number from the 'before patch' version (code_b) to the 'after patch' version (code_a).

    Args:
        target (int): Line number in the 'b' file.
        code_b (list): List of lines in 'b' version.
        code_a (list): List of lines in 'a' version.
        bf_paths (list): CFG paths of 'b'.
        diff (list): Diff block.

    Returns:
        int or None: Mapped line number in 'a' or None if not found.
    """
    flag = False
    pre = None
    next = None
    target_line = None
    count = 0

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
    target_num = None
    count = 0
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

    Args:
        nested_list (list of list): A list containing sublists.

    Returns:
        list: A list with unique sublists only.
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
    Trace data dependencies of added lines (label 'A') forward and backward.

    Returns:
        list: List of traces including function name, line number, and code.
    """
    front = []
    back = []
    traces = []
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
        trace = []
        front_num = b_to_a(f[0], list1_b[num].splitlines(), list1_a[num].splitlines(), bf_paths, diff)
        trace.append(af_code.remove_location_info(diff[0]))
        trace.append(front_num)
        trace.append(f[1])
        traces.append(trace)

    for b in back:
        if b is None:
            continue
        trace = []
        back_num = b_to_a(b[0], list1_b[num].splitlines(), list1_a[num].splitlines(), bf_paths, diff)
        trace.append(af_code.remove_location_info(diff[0]))
        trace.append(back_num)
        trace.append(b[1])
        traces.append(trace)

    traces = remove_duplicates(traces)
    return traces


def label_D(af_path, diff):
    """
    Trace single-line deleted code (label 'D').

    Returns:
        list or None: [function name, line number, code] or None.
    """
    if af_path[2] is not None:
        trace = []
        trace.append(af_code.remove_location_info(diff[0]))
        trace.append(af_path[2].coord.line)
        trace.append(af_path[0].split("-", 1)[1])
        return trace
    else:
        return None


def label_M_1(af_path, diff):
    """
    Trace deleted code labeled M.1 by capturing the affected line.

    Returns:
        list: [function name, line number, code]
    """
    trace = []
    trace.append(af_code.remove_location_info(diff[0]))
    trace.append(af_path[2].coord.line)
    trace.append(af_path[0].split("-", 1)[1])
    return trace


def label_M_2(af_path, diff):
    """
    Trace deleted code labeled M.2 (identical structure to M.1).

    Returns:
        list: [function name, line number, code]
    """
    trace = []
    trace.append(af_code.remove_location_info(diff[0]))
    trace.append(af_path[2].coord.line)
    trace.append(af_path[0].split("-", 1)[1])
    return trace


def label_M_3(af_path, diff):
    """
    Trace deleted code labeled M.3 (identical structure to M.1).

    Returns:
        list: [function name, line number, code]
    """
    trace = []
    trace.append(af_code.remove_location_info(diff[0]))
    trace.append(af_path[2].coord.line)
    trace.append(af_path[0].split("-", 1)[1])
    return trace


def label_M_4(af_path, list1_b, list1_a, diff, num, bf_paths):
    """
    Trace data dependencies before and after a modified line (label M.4) in the 'a' file.

    Returns:
        list: A list of traced lines including dependencies and the original line.
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
        trace = []
        trace.append(af_code.remove_location_info(diff[0]))
        trace.append(f[0])
        trace.append(f[1])
        traces.append(trace)

    for b in back:
        if b is None:
            continue
        trace = []
        trace.append(af_code.remove_location_info(diff[0]))
        trace.append(b[0])
        trace.append(b[1])
        traces.append(trace)

    traces = remove_duplicates(traces)
    trace = []
    trace.append(af_code.remove_location_info(diff[0]))
    trace.append(af_path[2].coord.line)
    trace.append(af_path[0].split("-", 1)[1])
    traces.append(trace)

    return traces


def label_M_5(bf_path, list1_b, list1_a, diff, num, bf_paths):
    """
    Trace the control dependencies for added code (label M.5).

    Returns:
        list: A list of related context lines before or after the change.
    """
    traces = []
    front_loc, back_loc = select_path.front_and_back_node(bf_path)
    if front_loc != []:
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
                trace.append(af_code.remove_location_info(diff[0]))
                trace.append(front)
                trace.append(front_code)
                traces.append(trace)
    if back_loc != []:
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
                trace.append(af_code.remove_location_info(diff[0]))
                trace.append(back)
                trace.append(back_code)
                traces.append(trace)

    return traces

# ====================== Program Entry ======================
def main(CVE_id):
    """
    Main function that processes a CVE patch to identify and trace vulnerability-introducing changes.

    Args:
        CVE_id (str): CVE identifier.

    Returns:
        list: All trace links for the given CVE patch.
    """
    list1_a, count_a = af_code.main(CVE_id)
    list1_b, count_b = bf_code.main(CVE_id)
    list2 = filter.main(CVE_id)
    af_paths, count_a = af_cfg.main(CVE_id)
    bf_paths, count_b = bf_cfg.main(CVE_id)
    storage_a, Gs_a, count_a = af_ast.main(CVE_id)
    storage_b, Gs_b, count_b = bf_ast.main(CVE_id)
    diff = filter.get_diff(CVE_id)
    all_traces = []

    for num in range(count_a):
        af_path = af_paths[num]
        bf_path = bf_paths[num]
        if len(diff) == 1:
            if diff[0].startswith("+"):
                traces = label_A(bf_path, list1_b, list1_a, diff, num, bf_paths)
                all_traces.extend(traces)
            elif diff[0].startswith("-"):
                trace = label_D(af_path, diff)
                if trace:
                    all_traces.append(trace)
            else:
                continue
        else:
            if diff[0].startswith("-") and diff[-1].startswith("+"):
                trace_M_1 = label_M_1(af_path, diff)
                all_traces.append(trace_M_1)
                trace_M_2 = label_M_2(af_path, diff)
                all_traces.append(trace_M_2)
                trace_M_3 = label_M_3(af_path, diff)
                all_traces.append(trace_M_3)
                traces_M_4 = label_M_4(af_path, list1_b, list1_a, diff, num, bf_paths)
                all_traces.extend(traces_M_4)
                traces_M_5 = label_M_5(bf_path, list1_b, list1_a, diff, num, bf_paths)
                all_traces.extend(traces_M_5)

    return all_traces
