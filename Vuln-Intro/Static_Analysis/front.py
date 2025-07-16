import re

def find_impacting_lines(code, target_line):
    """
    Find lines in the code before the target line that impact the target line by
    defining or affecting variables used in the target line.

    Args:
        code (str): The source code as a multiline string.
        target_line (int): The line number of the target line (1-indexed).

    Returns:
        dict: Ordered dictionary of impacting lines {line_number: code_line}.
    """
    lines = code.strip().splitlines()
    dependencies = set()
    impacting_lines = {}

    # Extract variables used in the target line as dependencies
    target_code = lines[target_line - 1].strip()
    dependencies = extract_variables(target_code)
    print("target_code:", target_code)
    print("dependencies:", dependencies)

    # Traverse backwards from the line before the target line to the top
    for lineno in range(target_line - 1, 0, -1):
        line = lines[lineno - 1].strip()

        # Check if the line contains an assignment
        if "=" in line:
            var_name, expression = extract_assignment(line)
            var_name = var_name.strip()
            flag_dep = False
            var = []
            for dep in dependencies:
                if var_name == dep.split("->", 1)[0]:
                    flag_dep = True
                    var.append(dep)
            if flag_dep and var:
                impacting_lines[lineno] = line
                for v in var:
                    dependencies.discard(v)  # Remove handled dependencies

            # Also check if the assigned variable itself is in dependencies
            if var_name in dependencies:
                impacting_lines[lineno] = line
                dependencies.discard(var_name)

        # Check if the line is a function call and uses dependencies
        if is_function_call(line):
            func_call_vars = extract_variables(line)
            flag_dep = False
            var = []
            for dep in dependencies:
                for v in func_call_vars:
                    if v == dep.split("->", 1)[0]:
                        flag_dep = True
                        var.append(dep)
            if flag_dep and var:
                impacting_lines[lineno] = line
                for v in var:
                    dependencies.discard(v)

            if dependencies.intersection(func_call_vars):
                intersec = dependencies.intersection(func_call_vars)
                impacting_lines[lineno] = line
                for v in intersec:
                    dependencies.discard(v)

    # Sort impacting lines by line number ascending
    impacting_lines_sorted = dict(sorted(impacting_lines.items()))
    return impacting_lines_sorted


def extract_variables(expression):
    """
    Extract variable names (including pointer or struct member access) from an expression.

    Args:
        expression (str): Code expression string.

    Returns:
        set: Set of variable names found in the expression.
    """
    expression = expression.strip().rstrip(';')

    # Remove function names, keep only contents inside parentheses
    expression = re.sub(r'\b\w+\s*\(', '(', expression)

    # Handle return statements separately
    if expression.startswith("return "):
        return set(re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', expression[len("return "):]))

    # Extract content inside parentheses (function call arguments)
    variables_str = re.findall(r'\((.*?)\)', expression)
    if variables_str:
        return {var.strip() for var in re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', variables_str[0])}

    # Extract variables on right side of assignment
    if "=" in expression:
        _, expression_right = expression.split("=", 1)
        return set(re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', expression_right))

    # Default: extract all matching variable patterns
    return set()


def extract_assignment(line):
    """
    Extract the variable being assigned and the assigned expression from a line.

    Args:
        line (str): Code line.

    Returns:
        tuple: (variable_name, assigned_expression)
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
    Check if a line is a function call (excluding control structures).

    Args:
        line (str): Code line.

    Returns:
        bool: True if line looks like a function call, False otherwise.
    """
    line = re.sub(r'\s*//.*$', '', line).strip()
    pattern = r'^\s*\w+\s*\([^)]*\)\s*(?:;|\s*$)'
    if re.search(pattern, line):
        return not any(keyword in line for keyword in ['while', 'if', 'for', 'switch', 'case', 'default', 'do'])
    return False


# Example usage:
code = """
struct nft_set_elem_catchall *catchall, *next;
const struct nft_set *set = gc->set;
struct nft_elem_priv *elem_priv;
struct nft_set_ext *ext;
while(catchall, next, &set->catchall_list, list)
{
    ext = nft_set_elem_ext(set, catchall->elem);
    if (!nft_set_elem_expired(ext))
        continue;
    if (nft_set_elem_is_dead(ext))
        goto dead_elem;
    nft_set_elem_dead(ext);
dead_elem:
    if (sync)
        gc = nft_trans_gc_queue_sync(gc, GFP_ATOMIC);
    else
        gc = nft_trans_gc_queue_async(gc, gc_seq, GFP_ATOMIC);
    if (!gc)
        return NULL;
    elem_priv = catchall->elem;
    if (sync) {
        nft_setelem_data_deactivate(gc->net, gc->set, elem_priv);
        nft_setelem_catchall_destroy(catchall);
    }
    nft_trans_gc_elem_add(gc, elem_priv);
}
return gc;
"""
target_line = 27

impacting_lines = find_impacting_lines(code, target_line)
print("Impacting lines:")
for lineno, code_line in impacting_lines.items():
    print(f"Line {lineno}: {code_line}")
