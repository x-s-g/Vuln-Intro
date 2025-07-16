import re_refactor
import re
import time

def get_code_type(line):
    """
    Determine the type of a code line.

    Args:
        line (str): A line of code.

    Returns:
        str: The type of the code line. Possible values:
            - "FunctionDefinition"
            - "sign"
            - "Definition"
            - "FunctionCall"
            - "ControlStatement"
            - "VariableAssignment"
            - "Other"
    """
    # Strip line if starts with whitespace or curly braces
    if line.startswith(' ') or line.startswith('\t') or line.startswith('{') or line.startswith("}"):
        line = line.strip()
    else:
        return "FunctionDefinition"

    # Check if line consists only of operator/sign characters
    if all(char in {'+', '-', '/', '*', '=', '<', '>', '!', '%', '&', '|', '^', '~', '\t', '{', '}'} for char in line):
        return "sign"

    # Regex patterns for different code types
    variable_definition_re = re.compile(r'\b(struct|int|float|double|char|void|long|short|unsigned|signed)\b.*;')
    function_call_re = re.compile(r'\w+\s*\(.*\)\s*;')
    control_statement_re = re.compile(r'\b(if|else|while|for|do|switch|case|default|break|continue|return|goto|list_for_each_entry_safe|list_for_each_entry_rcu)\b')
    variable_assignment_re = re.compile(r'\w+\s*=\s*.*;')

    if variable_definition_re.match(line):
        return "Definition"
    elif function_call_re.match(line):
        return "FunctionCall"
    elif control_statement_re.match(line):
        return "ControlStatement"
    elif variable_assignment_re.match(line):
        return "VariableAssignment"
    else:
        return "Other"


def filter_code_type(diffs):
    """
    Filter diffs to only include lines of specific code types.

    Args:
        diffs (list of list of str): A list of diffs, each diff is a list of code lines.

    Returns:
        list of list of str: Filtered list of diffs with only relevant lines.
    """
    danger_func_list = []

    for diff in diffs:
        ev_list = []
        for line in diff:
            ori_code = line
            if line.startswith("@@"):
                ev_list.append(ori_code)
            elif line.startswith("+"):
                line = line.lstrip("+")
                type = get_code_type(line)
                if type != "sign" and type != "Definition":
                    ev_list.append(ori_code)
            elif line.startswith("-"):
                line = line.lstrip("-")
                type = get_code_type(line)
                if type != "sign" and type != "Definition":
                    ev_list.append(ori_code)
        danger_func_list.append(ev_list)

    real_list = []
    for diff in danger_func_list:
        if re_refactor.clean_and_check_list(diff):
            real_list.append(diff)

    return real_list


def main(CVE_id):
    """
    Main function entry point.

    Args:
        CVE_id (str): The CVE identifier to analyze.

    Returns:
        list of list of str: Filtered diffs matching criteria.
    """
    diffs = re_refactor.main(CVE_id)
    filtered_diffs = filter_code_type(diffs)

    for diff in filtered_diffs:
        for line in diff:
            print(line)

    return filtered_diffs

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
