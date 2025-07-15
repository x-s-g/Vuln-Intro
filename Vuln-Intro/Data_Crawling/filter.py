import re
import re_refactor

class PatchFilter:
    def __init__(self):
        pass

    def get_code_type(self, line: str) -> str:
        """
        Determine the code type of a given line.

        :param line: A single line of code from a patch.
        :return: A string indicating the type of code line.
        """
        # Strip line if it starts with space, tab, or braces
        if line.startswith((' ', '\t', '{', '}')):
            line = line.strip()
        else:
            return "FunctionDefinition"

        # Check if line only contains certain symbols (signs)
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

    def filter_code_type(self, diffs: list) -> list:
        """
        Filter patch diff blocks by code type, ignoring signs and variable definitions.

        :param diffs: List of diff blocks (list of lists of lines).
        :return: Filtered list of diff blocks.
        """
        filtered_diffs = []

        for diff in diffs:
            filtered_block = []
            for line in diff:
                if line.startswith("@@"):
                    filtered_block.append(line)
                elif line.startswith("+") or line.startswith("-"):
                    code_line = line[1:].lstrip()
                    code_type = self.get_code_type(code_line)
                    if code_type not in ("sign", "Definition"):
                        filtered_block.append(line)
            # Use re_refactor's cleaning function to ensure block validity
            if re_refactor.clean_and_check_list(filtered_block):
                filtered_diffs.append(filtered_block)

        return filtered_diffs

    def main(self, cve_id: str) -> list:
        """
        Process a patch file for a given CVE ID, filter out unimportant patch lines,
        and print the filtered diff lines.

        :param cve_id: The CVE identifier string.
        :return: Filtered list of diff blocks after patch type filtering.
        """
        # Load initial diff blocks via re_refactor.main
        diffs = re_refactor.main(cve_id)

        # Filter patch by code types
        filtered_diffs = self.filter_code_type(diffs)

        # Print filtered lines
        for diff in filtered_diffs:
            for line in diff:
                print(line)

        return filtered_diffs

# ====================== Program Entry ======================

if __name__ == "__main__":
    cve_id = "CVE-2023-6111"
    patch_filter = PatchFilter()
    patch_filter.main(cve_id)
