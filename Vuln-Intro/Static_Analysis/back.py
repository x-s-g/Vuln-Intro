import re

def find_impacting_lines_back(code, target_line):
    """
    Find lines after the target line that depend on variables used in the target line.

    Args:
        code (str): Multiline string of code.
        target_line (int): Line number (1-based) in the code to analyze.

    Returns:
        dict: Mapping of line numbers to code lines that impact the target line variables.
    """
    lines = code.strip().splitlines()
    impacting_lines = {}

    # Extract variables used in the target line
    target_code = lines[target_line - 1].strip()
    dependencies = extract_variables_back(target_code)
    print("target_code:", target_code)
    print("dependencies:", dependencies)

    # Check subsequent lines for usage of these variables
    for lineno in range(target_line + 1, len(lines) + 1):
        line = lines[lineno - 1].strip()

        current_vars = extract_variables_back(line)
        # print(f"Line {lineno}: {line}")
        # print("current_vars:", current_vars)

        flag = False
        var = []
        for i in current_vars:
            for j in dependencies:
                # Match if variables match considering pointer/struct access (like ->)
                if i == j.split("->", 1)[0] or j == i.split("->", 1)[0]:
                    flag = True
                    var.append(j)

        if flag and var:
            impacting_lines[lineno] = line
            for i in var:
                dependencies.discard(i)  # Remove processed dependencies

        # Also add if current line contains any remaining dependencies
        intersect = dependencies.intersection(current_vars)
        if intersect:
            impacting_lines[lineno] = line
            for i in intersect:
                dependencies.discard(i)

    return impacting_lines

def extract_variables_back(expression):
    """
    Extract variables from a given code expression line.

    Args:
        expression (str): A single line of code.

    Returns:
        set: Set of variable names detected.
    """
    expression = expression.strip().rstrip(';')

    # Remove function names before '(' to isolate arguments
    expression = re.sub(r'\b\w+\s*\(', '(', expression)

    # Extract variables from return statements
    if expression.startswith("return "):
        return set(re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', expression[len("return "):]))

    # Extract variables inside parentheses (function calls, etc.)
    variables_str = re.findall(r'\((.*?)\)', expression)

    if variables_str:
        # Extract variables supporting pointer and dot notation
        return {var.strip() for var in re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', variables_str[0])}

    # Handle assignment expressions, extract right side variables
    if "=" in expression:
        _, expression_right = expression.split("=", 1)
        return set(re.findall(r'\b[a-zA-Z_]\w*(?:->\w+|\.\w+)?\b', expression_right))

    # Default: extract all variable-like tokens
    return set()

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
target_line = 25  # Specified line number

impacting_lines = find_impacting_lines_back(code, target_line)
print("Impacting lines:")
for lineno, code_line in impacting_lines.items():
    print(f"Line {lineno}: {code_line}")
