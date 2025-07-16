import sys
import os

# Add directories to sys.path for importing modules from parent directories
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Data_Crawling')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Static_Analysis')))

import re
from pycparser import c_parser, c_ast
import filter
import bf_code
import af_cfg
import bf_cfg
import bf_ast
import af_code
import af_ast
from collections import Counter
import time

M = ["M.1", "M.2", "M.3", "M.4", "M.5"]


def find_node_name(node):
    """
    Recursively find and return a representation of the AST node's name or structure.

    Args:
        node (c_ast.Node): An AST node from pycparser.

    Returns:
        str or tuple or list or None: A string name, tuple describing the node,
        list of names (for ExprList), or None if the node type is not handled.
    """
    if isinstance(node, c_ast.Compound):
        return "Compound"
    elif isinstance(node, c_ast.For):
        return find_node_name(node.cond)
    elif isinstance(node, c_ast.If):
        return find_node_name(node.cond)
    elif isinstance(node, c_ast.While):
        return find_node_name(node.cond)
    elif isinstance(node, c_ast.DoWhile):
        return find_node_name(node.cond)
    elif isinstance(node, c_ast.Switch):
        return find_node_name(node.cond)
    elif isinstance(node, c_ast.Case):
        return find_node_name(node.expr)
    elif isinstance(node, c_ast.Default):
        return "Default"
    elif isinstance(node, c_ast.FuncDef):  # Function definition
        return "FuncDef"
    elif isinstance(node, c_ast.FuncDecl):  # Function declaration
        return "FuncDecl"
    elif isinstance(node, c_ast.Return):
        return find_node_name(node.expr)
    elif isinstance(node, c_ast.Decl):
        return (node.name, node.type, find_node_name(node.init))
    elif isinstance(node, c_ast.ID):
        return find_node_name(node.name)
    elif isinstance(node, c_ast.BinaryOp):
        return (node.op, find_node_name(node.left), find_node_name(node.right))
    elif isinstance(node, c_ast.UnaryOp):
        return (node.op, find_node_name(node.expr))
    elif isinstance(node, c_ast.Assignment):
        return (node.op, find_node_name(node.lvalue), find_node_name(node.rvalue))
    elif isinstance(node, c_ast.ArrayDecl):
        return (find_node_name(node.type), node.dim)
    elif isinstance(node, c_ast.ArrayRef):
        return find_node_name(node.name)
    elif isinstance(node, c_ast.Struct):  # Struct
        return node.name
    elif isinstance(node, c_ast.Union):
        return node.name
    elif isinstance(node, c_ast.Typedef):
        return node.name
    elif isinstance(node, c_ast.Continue):
        return "Continue"
    elif isinstance(node, c_ast.TypeDecl):
        return node.declname
    elif isinstance(node, c_ast.PtrDecl):
        return "PtrDecl"
    elif isinstance(node, c_ast.ExprList):
        expr_names = []
        for expr in node.exprs:
            expr_name = find_node_name(expr)
            if expr_name:
                expr_names.append(expr_name)
        return expr_names
    elif isinstance(node, c_ast.FuncCall):
        return node.name.name, find_node_name(node.args)
    elif isinstance(node, c_ast.Constant):
        return node.type, node.value
    elif isinstance(node, c_ast.Break):
        return "Break"
    elif isinstance(node, c_ast.Goto):
        return node.name
    elif isinstance(node, c_ast.Label):
        return node.name
    elif isinstance(node, c_ast.TernaryOp):
        return (find_node_name(node.cond), find_node_name(node.iftrue), find_node_name(node.iffalse))
    # Handle other node types not explicitly covered
    return None


def find_func_name(diff):
    """
    Extract the function name from a diff block by parsing lines starting with "@@".

    Args:
        diff (list of str): List of diff lines.

    Returns:
        str: Extracted function name or file name.
    """
    for line in diff:
        if line.startswith("@@"):
            file_name = af_code.remove_location_info(line)
            return file_name


def find_code_in_list1(list1_a, func_name):
    """
    Find the index in list1_a where func_name appears in the first line.

    Args:
        list1_a (list of str): List of code blocks.
        func_name (str): Function name to search for.

    Returns:
        int or None: Index if found, else None.
    """
    for i in range(len(list1_a)):
        if func_name in list1_a[i].split('\n', 1)[0]:
            return i


def find_line_number(code_list, target_line, start_line, ele, empty_comment):
    """
    Find the line number of the nth occurrence of a target line in a list of code lines,
    starting the search from a given line adjusted by empty_comment.

    Args:
        code_list (list of str): List of code lines.
        target_line (str): The exact line content to find.
        start_line (int): The line number to start the search from.
        ele (int): The occurrence count of the target line to find.
        empty_comment (int): Number of empty comment lines to adjust the start_line.

    Returns:
        int: Line number (1-based) where the nth occurrence of target_line is found; -1 if not found.
    """
    start_line = start_line - empty_comment
    if start_line <= 0:
        start_line = 1

    code_string = ''.join(code_list)
    code_lines = code_string.split('\n')
    count = 0

    for i in range(start_line - 1, len(code_lines)):
        if code_lines[i].strip() == target_line.strip():
            count += 1
            if count == ele:
                return i + 1  # Lines numbered from 1

    return -1  # Not found


def find_node_by_line(G, line_number):
    """
    Find a node in graph G whose coordinate line equals line_number.

    Args:
        G (networkx.Graph): Graph containing nodes with 'coord' attribute.
        line_number (int): Line number to search for.

    Returns:
        node or None: Found node or None if not found.
    """
    for node in G.nodes():
        if hasattr(node, 'coord') and node.coord and node.coord.line == line_number:
            return node
    return None


def func_start(path, cve_id, func_name):
    """
    Determine the start line of a target function in a file.

    Args:
        path (list of str): List containing file path string.
        cve_id (str): CVE identifier.
        func_name (str): Target function name.

    Returns:
        int or bool: The start line number of the function if file exists, else False.
    """
    file_lines = af_code.read_file_lines("../" + cve_id + "/" + path[0])
    if file_lines is None:
        print("File does not exist")
        return False
    a, b = af_code.find_target_function(file_lines, func_name)
    return a


def extract_numbers_from_diff(diff_line):
    """
    Extract starting line numbers from a diff header line using regex.

    Args:
        diff_line (str): A diff header line, e.g. "@@ -12,8 +20,6 @@"

    Returns:
        tuple(int, int) or None: The two starting line numbers if matched; otherwise None.
    """
    match = re.search(r'@@ -(\d+),\d+ \+(\d+),\d+ @@', diff_line)
    if match:
        num1 = match.group(1)
        num2 = match.group(2)
        return int(num1), int(num2)
    else:
        return None


def nodes_equal(node1, node2):
    """
    Recursively check if two AST nodes are equal by comparing their types,
    attributes, and children nodes.

    Args:
        node1 (c_ast.Node): First AST node.
        node2 (c_ast.Node): Second AST node.

    Returns:
        bool: True if nodes are equivalent, False otherwise.
    """
    if type(node1) != type(node2):
        return False

    if isinstance(node1, c_ast.Node):
        # Compare attributes
        for attr in node1.attr_names:
            if getattr(node1, attr) != getattr(node2, attr):
                return False

        # Compare children
        children1 = [child for _, child in node1.children()]
        children2 = [child for _, child in node2.children()]

        if len(children1) != len(children2):
            return False

        for child1, child2 in zip(children1, children2):
            if not nodes_equal(child1, child2):
                # Debug print statements commented out
                # print("child1:",child1)
                # print("child2:", child2)
                return False

        return True

    return True


def include_path(diff, list1_a, Gs_a, af_paths, list1_b, Gs_b, bf_paths, CVE_id, count_a, count_b):
    """
    For a diff block, find the paths of deleted and added lines within functions.

    Args:
        diff (list of str): Lines in a diff block.
        list1_a (list): List of code blocks before the diff.
        Gs_a (list): Graphs corresponding to code before the diff.
        af_paths (list): Paths extracted from 'after fix' code analysis.
        list1_b (list): List of code blocks after the diff.
        Gs_b (list): Graphs corresponding to code after the diff.
        bf_paths (list): Paths extracted from 'before fix' code analysis.
        CVE_id (str): Identifier of the CVE.
        count_a (int): Empty comment count for before diff code.
        count_b (int): Empty comment count for after diff code.

    Returns:
        tuple: Two lists containing paths for deleted lines and added lines.
    """
    a, b = extract_numbers_from_diff(diff[0])
    func_name = find_func_name(diff)
    i = find_code_in_list1(list1_a, func_name)

    line_del_path = []
    line_add_path = []

    for line in diff:
        element_counter = Counter()
        del_path = []
        add_path = []
        if line.startswith("-"):
            element_counter[line] += 1
            ele = element_counter[line]
            del_path.append(line)
            del_path.append("D")
            line_content = line.split("-", 1)[1]
            a_code_path = af_code.find_files_with_prefix("../" + CVE_id, "af#")
            start = func_start(a_code_path, CVE_id, func_name)
            line_number = find_line_number(list1_a[i], line_content, a - start, ele, count_a)
            find_node = find_node_by_line(Gs_a[i], line_number)
            del_path.append(find_node)
            del_path.append(line_number)
            node_name = find_node_name(find_node)

            for paths in af_paths[i]:
                for node in paths:
                    if node.coord.line == line_number:
                        del_path.append(paths)

            if del_path:
                line_del_path.append(del_path)

        if line.startswith("+"):
            add_path.append(line)
            element_counter[line] += 1
            ele = element_counter[line]
            add_path.append("A")
            line_content = line.split("+", 1)[1]
            b_code_path = af_code.find_files_with_prefix("../" + CVE_id, "bf#")
            start = func_start(b_code_path, CVE_id, func_name)
            line_number = find_line_number(list1_b[i], line_content, b - start, ele, count_b)
            find_node = find_node_by_line(Gs_b[i], line_number)
            add_path.append(find_node)
            add_path.append(line_number)
            node_name = find_node_name(find_node)

            for paths in bf_paths[i]:
                for node in paths:
                    if node.coord.line == line_number:
                        add_path.append(paths)

            if add_path:
                line_add_path.append(add_path)

    return line_del_path, line_add_path


def get_node_type(node):
    """
    Get the type name of an AST node.

    Args:
        node (c_ast.Node): AST node.

    Returns:
        str: The class name of the node.
    """
    if hasattr(node, 'coord') and node.coord:
        return f"{type(node).__name__} "
    else:
        return f"{type(node).__name__} "


def remove_duplicates(lst):
    """
    Remove duplicate elements from a list while preserving order.

    Args:
        lst (list): List possibly containing duplicates.

    Returns:
        list: List with duplicates removed.
    """
    seen = set()
    output = []
    for item in lst:
        # Convert sublists to tuples so they can be added to a set
        t_item = tuple(item) if isinstance(item, list) else item
        if t_item not in seen:
            seen.add(t_item)
            output.append(item)  # Append original item, not tuple
    return output


def complete_path_to_type(paths):
    """
    Divide paths into two lists: types before and after a reference node in paths.

    Args:
        paths (list): List of paths, each a list of AST nodes.

    Returns:
        tuple: Two lists representing front (before) and back (after) node types.
    """
    front = []
    back = []
    for path in paths[4:]:
        front_path = []
        back_path = []
        flag = False
        for node in path:
            if nodes_equal(node, paths[2]):
                flag = True
                continue
            if not flag:
                front_path.append(get_node_type(node))
            else:
                back_path.append(get_node_type(node))

        front.append(front_path)
        back.append(back_path)

    front = remove_duplicates(front)
    back = remove_duplicates(back)
    return front, back


def front_and_back_node(paths):
    """
    Extract line numbers of nodes before and after a reference node in paths.

    Args:
        paths (list): List of paths, each a list of AST nodes.

    Returns:
        tuple: Two lists containing line numbers of nodes before and after the reference node.
    """
    front = []
    back = []
    for path in paths[4:]:
        pre_node = None
        next_node = None
        flag = False
        for node in path:
            if nodes_equal(node, paths[2]):
                flag = True
                continue
            if not flag:
                pre_node = node.coord.line
            else:
                next_node = node.coord.line
                break
        front.append(pre_node)
        back.append(next_node)

    front = remove_duplicates(front)
    back = remove_duplicates(back)
    front = [x for x in front if x is not None]
    back = [x for x in back if x is not None]
    return front, back


def compare_node_info(info_a, info_b):
    """
    Compare two node info objects for equality, handling tuples recursively.

    Args:
        info_a: Node info (str, tuple, etc.)
        info_b: Node info (str, tuple, etc.)

    Returns:
        bool: True if both node infos are equivalent, else False.
    """
    if info_a == info_b:
        return True
    elif isinstance(info_a, tuple) and isinstance(info_b, tuple):
        if len(info_a) == len(info_b):
            for a, b in zip(info_a, info_b):
                if not compare_node_info(a, b):
                    return False
            return True
    # Return False if types differ or length mismatch
    return False


def compare_part_path(a_paths, b_paths):
    """
    Check if any path in a_paths is exactly equal to any path in b_paths.

    Args:
        a_paths (list): List of paths.
        b_paths (list): List of paths.

    Returns:
        bool: True if there is at least one matching path, else False.
    """
    for a_path in a_paths:
        for b_path in b_paths:
            if a_path == b_path:
                return True
    return False


def get_line_from_code(code_list, line_number):
    """
    Get the content of a specific line from the code list.

    Args:
    - code_list: A list containing the code, each element is a line of code.
    - line_number: The target line number (1-based).

    Returns:
    - The content of the specified line number.
      If the line number is out of range, returns an error message.
    """
    # Ensure the line number is within valid range
    if line_number < 0 or line_number > len(code_list):
        return f"Error: Line number {line_number} is out of range. Total lines: {len(code_list)}."

    # Return the content of the specified line.
    # Note line_number is 1-based, so subtract 1 to get list index.
    return code_list[line_number - 1].replace("\t", "")


def compare_front_and_back_node(a_nodes, b_nodes, list1_a, list1_b, num):
    """
    Compare lines corresponding to front and back nodes from two code versions.

    Args:
    - a_nodes: List of line numbers for nodes in the first code version.
    - b_nodes: List of line numbers for nodes in the second code version.
    - list1_a: List of code blocks for the first version.
    - list1_b: List of code blocks for the second version.
    - num: Index to select specific code block from list1_a and list1_b.

    Returns:
    - True if any line content from a_nodes matches any line content from b_nodes.
      Otherwise, returns False.
    """
    for a_node in a_nodes:
        for b_node in b_nodes:
            if get_line_from_code(list1_a[num].splitlines(), a_node) == get_line_from_code(list1_b[num].splitlines(), b_node):
                return True
    return False


def compare_none_node(a_nodes, b_nodes):
    """
    Check if any node pair in two lists are both None.

    Args:
    - a_nodes: List of nodes.
    - b_nodes: List of nodes.

    Returns:
    - True if there exists at least one pair (a_node, b_node) where both are None.
      Otherwise, returns False.
    """
    for a_node in a_nodes:
        for b_node in b_nodes:
            if a_node is None and b_node is None:
                return True
    return False


def compare_node(a_node, b_node):
    """
    Compare two nodes for type and structural similarity.

    Args:
    - a_node: First AST node.
    - b_node: Second AST node.

    Returns:
    - True if both nodes are of the same type, are not None,
      and their node names match structurally.
      Otherwise, False.
    """
    if type(a_node) == type(b_node) and a_node is not None and b_node is not None:
        if compare_node_info(find_node_name(a_node), find_node_name(b_node)):
            return True
    return False


# Label deleted lines: Deletion 'D', Modification 'M'
# Cases:
# 1. Front and back paths are the same (by type) - most standard modification
# 2. Front and back nodes are the same (by source code)
# 3. Front or back path matches and nodes have the same type and name
# 4. FuncCall nodes call the same function but differ in data flow (all statements containing FuncCall)
# 5. Completely identical (by source code)

def label_af_node(af_path, line_add_path, list1_a, list1_b, num):
    """
    Label a deletion path (af_path) based on comparison with added paths (line_add_path).

    Args:
    - af_path: A path representing a deleted line with metadata.
    - line_add_path: List of added line paths to compare with.
    - list1_a: Code blocks for the 'before' version.
    - list1_b: Code blocks for the 'after' version.
    - num: Index to select specific code block.

    Returns:
    - The updated af_path with a label in af_path[1] indicating the modification type.
    """
    # Case 5: Completely identical source code lines
    for bf_path in line_add_path:
        if af_path[0].split("-", 1)[1].replace("\t", "") == bf_path[0].split("+", 1)[1].replace("\t", ""):
            af_path[1] = "M.5"
            return af_path

    # Case 4: Both nodes are FuncCall with same function name but different source code
    if isinstance(af_path[2], c_ast.FuncCall):
        for bf_path in line_add_path:
            if isinstance(bf_path[2], c_ast.FuncCall):
                if compare_node_info(find_node_name(bf_path[2]), find_node_name(af_path[2])) and \
                   af_path[0].split("-", 1)[1].replace("\t", "") != bf_path[0].split("+", 1)[1].replace("\t", ""):
                    af_path[1] = "M.4"
                    return af_path

    # Case 1: Front and back paths are the same by type
    front_a, back_a = complete_path_to_type(af_path)
    for bf_path in line_add_path:
        front_b, back_b = complete_path_to_type(bf_path)
        if compare_part_path(front_a, front_b) and compare_part_path(back_a, back_b):
            af_path[1] = "M.1"
            return af_path

    # Case 2: Front and back nodes are the same (by source code)
    front_a, back_a = front_and_back_node(af_path)
    for bf_path in line_add_path:
        front_b, back_b = front_and_back_node(bf_path)
        if front_a is not None and front_b is not None and back_a is not None and back_b is not None:
            if compare_front_and_back_node(front_a, front_b, list1_a, list1_b, num) and \
               compare_front_and_back_node(back_a, back_b, list1_a, list1_b, num):
                af_path[1] = "M.2"
                return af_path
        if front_a is None and front_b is None and back_a is not None and back_b is not None:
            if compare_front_and_back_node(back_a, back_b, list1_a, list1_b, num):
                af_path[1] = "M.2"
                return af_path
        if front_a is not None and front_b is not None and back_a is None and back_b is None:
            if compare_front_and_back_node(front_a, front_b, list1_a, list1_b, num):
                af_path[1] = "M.2"
                return af_path

    # Case 3: One of the front/back nodes matches, and node types are the same
    front_a, back_a = front_and_back_node(af_path)
    for bf_path in line_add_path:
        front_b, back_b = front_and_back_node(bf_path)
        if front_a is not None and front_b is not None:
            if compare_front_and_back_node(front_a, front_b, list1_a, list1_b, num):
                if type(af_path[2]) == type(bf_path[2]):
                    af_path[1] = "M.3"
                    return af_path
        if back_a is not None and back_b is not None:
            if compare_front_and_back_node(back_a, back_b, list1_a, list1_b, num):
                if type(af_path[2]) == type(bf_path[2]):
                    af_path[1] = "M.3"
                    return af_path

    # If none of the above cases match, return original path without label change
    return af_path


def label_bf_node(bf_path, line_del_path, list1_a, list1_b, num):
    """
    Label an addition path (bf_path) based on comparison with deleted paths (line_del_path).

    Args:
    - bf_path: A path representing an added line with metadata.
    - line_del_path: List of deleted line paths to compare with.
    - list1_a: Code blocks for the 'before' version.
    - list1_b: Code blocks for the 'after' version.
    - num: Index to select specific code block.

    Returns:
    - The updated bf_path with a label in bf_path[1] indicating the modification type.
    """
    # Case 5: Completely identical source code lines
    for af_path in line_del_path:
        if af_path[0].split("-", 1)[1].replace("\t", "") == bf_path[0].split("+", 1)[1].replace("\t", ""):
            bf_path[1] = "M.5"
            return bf_path

    # Case 4: Both nodes are FuncCall with same function name but different source code
    if isinstance(bf_path[2], c_ast.FuncCall):
        for af_path in line_del_path:
            if isinstance(af_path[2], c_ast.FuncCall):
                if compare_node_info(find_node_name(bf_path[2]), find_node_name(af_path[2])) and \
                   af_path[0].split("-", 1)[1].replace("\t", "") != bf_path[0].split("+", 1)[1].replace("\t", ""):
                    bf_path[1] = "M.4"
                    return bf_path

    # Case 1: Front and back paths are the same by type
    front_b, back_b = complete_path_to_type(bf_path)
    for af_path in line_del_path:
        front_a, back_a = complete_path_to_type(af_path)
        if compare_part_path(front_a, front_b) and compare_part_path(back_a, back_b):
            bf_path[1] = "M.1"
            return bf_path

    # Case 2: Front and back nodes are the same (by source code)
    front_b, back_b = front_and_back_node(bf_path)
    for af_path in line_del_path:
        front_a, back_a = front_and_back_node(af_path)
        if front_a is not None and front_b is not None and back_a is not None and back_b is not None:
            if compare_front_and_back_node(front_a, front_b, list1_a, list1_b, num) and \
               compare_front_and_back_node(back_a, back_b, list1_a, list1_b, num):
                bf_path[1] = "M.2"
                return bf_path
        if front_a is None and front_b is None and back_a is not None and back_b is not None:
            if compare_front_and_back_node(back_a, back_b, list1_a, list1_b, num):
                bf_path[1] = "M.2"
                return bf_path
        if front_a is not None and front_b is not None and back_a is None and back_b is None:
            if compare_front_and_back_node(front_a, front_b, list1_a, list1_b, num):
                bf_path[1] = "M.2"
                return bf_path

    # Case 3: One of the front/back nodes matches, and node types are the same
    front_b, back_b = front_and_back_node(bf_path)
    for af_path in line_del_path:
        front_a, back_a = front_and_back_node(af_path)
        if front_a is not None and front_b is not None:
            if compare_front_and_back_node(front_a, front_b, list1_a, list1_b, num):
                if type(af_path[2]) == type(bf_path[2]):
                    bf_path[1] = "M.3"
                    return bf_path
        if back_a is not None and back_b is not None and back_a != [] and back_b != []:
            if compare_front_and_back_node(back_a, back_b, list1_a, list1_b, num):
                if type(af_path[2]) == type(bf_path[2]):
                    bf_path[1] = "M.3"
                    return bf_path

    # If none of the above cases match, return original path without label change
    return bf_path


def patch_label(line_del_path, line_add_path, list1_a, list1_b, num):
    """
    Label all patch lines (deletions and additions) based on their comparison.

    Args:
    - line_del_path: List of paths for deleted lines.
    - line_add_path: List of paths for added lines.
    - list1_a: Code blocks for the 'before' version.
    - list1_b: Code blocks for the 'after' version.
    - num: Index to select specific code block.

    Returns:
    - Tuple of two lists: labeled deleted paths and labeled added paths.
    """
    new_line_del_path = []
    new_line_add_path = []

    # Label all deleted lines
    for af_path in line_del_path:
        af_path = label_af_node(af_path, line_add_path, list1_a, list1_b, num)
        new_line_del_path.append(af_path)

    # Label all added lines
    for bf_path in line_add_path:
        bf_path = label_bf_node(bf_path, line_del_path, list1_a, list1_b, num)
        new_line_add_path.append(bf_path)

    return new_line_del_path, new_line_add_path


def main(CVE_id):
    """
    Main function to analyze the patch for the given CVE ID.
    It reads code before and after patch, extracts paths and nodes,
    compares them, and labels changes according to defined categories.

    Args:
    - CVE_id: The identifier string for the CVE patch.

    Returns:
    - A list of deletion and addition paths with assigned labels.
    """
    # Code blocks before the patch (a version)
    list1_a, count_a = af_code.main(CVE_id)
    # Code blocks after the patch (b version)
    list1_b, count_b = bf_code.main(CVE_id)

    # Filtered patch content
    list2 = filter.main(CVE_id)

    # Get all paths for before and after patch
    af_paths, count_a = af_cfg.main(CVE_id)
    bf_paths, count_b = bf_cfg.main(CVE_id)

    # Storage and CFG graphs for before and after patch
    storage_a, Gs_a, count_a = af_ast.main(CVE_id)
    storage_b, Gs_b, count_b = bf_ast.main(CVE_id)

    num = 0
    del_and_add_path = []

    # Process each diff block
    for diff in list2:
        path = []

        # Find deletion and addition paths for this diff block
        line_del_path, line_add_path = include_path(diff, list1_a, Gs_a, af_paths, list1_b, Gs_b, bf_paths, CVE_id, count_a, count_b)

        func_name = find_func_name(diff)
        num = find_code_in_list1(list1_a, func_name)

        # Label patch lines
        new_line_del_path, new_line_add_path = patch_label(line_del_path, line_add_path, list1_a, list1_b, num)
        path.append(new_line_del_path)
        path.append(new_line_add_path)

        del_and_add_path.append(path)
        num += 1

    # Adjust labels for specific cases across diff blocks
    for i in range(len(list2)):
        path = del_and_add_path[i]
        del_path = path[0]
        for af_path in del_path:
            if af_path[1] == "D":
                for j in range(len(list2)):
                    if af_code.remove_location_info(list2[j][0]) == af_code.remove_location_info(list2[i][0]) and i != j:
                        for bf_path in del_and_add_path[j][1]:
                            if bf_path[1] == "A":
                                if af_path[0].split("-", 1)[1].replace("\t", "") == bf_path[0].split("+", 1)[1].replace("\t", ""):
                                    af_path[1] = "M.5"
                                    bf_path[1] = "M.5"
                                if isinstance(af_path[2], c_ast.FuncCall) and isinstance(bf_path[2], c_ast.FuncCall):
                                    if compare_node_info(find_node_name(bf_path[2]), find_node_name(af_path[2])) and \
                                       af_path[0].split("-", 1)[1].replace("\t", "") != bf_path[0].split("+", 1)[1].replace("\t", ""):
                                        af_path[1] = "M.4"
                                        bf_path[1] = "M.4"
            print(af_path[0])
            print(af_path[1])

    return del_and_add_path

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)

