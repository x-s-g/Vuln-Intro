import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Data_Crawling')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Static_Analysis')))
import filter
import patch_label
import os
import traver
import af_code
import time

# Due to the website's anti-scraping mechanism, this module is currently unavailable
def match_sequence_in_file(sequence_lines, file_lines):
    """
    Search for the presence of `sequence_lines` (with exact order) in `file_lines`.
    Whitespace and tab characters are ignored during matching.

    :param sequence_lines: The sequence of statements to match (list of str)
    :param file_lines: The target file content to be matched (list of str)
    :return: bool, indicating whether the match is successful
    """

    def normalize(line):
        return ''.join(line.split())  # Remove all whitespace characters

    seq_idx = 0
    file_len = len(file_lines)
    i = 0

    while i < file_len and seq_idx < len(sequence_lines):
        file_line_norm = normalize(file_lines[i])
        seq_line_norm = normalize(sequence_lines[seq_idx])
        if seq_line_norm == file_line_norm:
            seq_idx += 1  # Match successful, proceed to next line in sequence
        i += 1  # Continue searching regardless of match result

    return seq_idx == len(sequence_lines)


def sort_by_second_element(data):
    # Sort the list by the second element of each sublist
    sorted_data = sorted(data, key=lambda x: x[1])
    return sorted_data

def main(cve_id):
    # Get filtered patch content list
    list2 = filter.main(CVE_id)
    # Find functions changed in the patch
    func_name_list = af_code.find_patch_func(list2)
    # Get vulnerable links from patch_label
    vuln_links = patch_label.main(cve_id)
    result = []
    for i in range(len(list2)):
        diff_line = vuln_links[i]
        # Sort the diff lines by second element (line number)
        sorted_data = sort_by_second_element(diff_line)
        for data in sorted_data:
            print(data[2])
        if sorted_data:
            func_name = sorted_data[0][0]
        else:
            continue
        print(func_name)
        name = traver.extract_function_name(func_name)
        # print(name)

        # Iterate over files in change_low_version directory
        for filename in os.listdir("../" + cve_id + "/change_low_version"):
            # print(extract_id(filename))
            # inurl="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/"+"s_a_name"+"extract_id(filename)"
            # response = requests.get(inurl)
            # root = etree.HTML(response.content)
            # items = root.xpath(
            #     "//div[@id='vulnHyperlinksPanel']//table[@class='table table-striped table-condensed table-bordered detail-table']/tbody/tr")
            #
            # result = match_sequence_in_file(sequence, item)
            # Build full file path
            file_path = os.path.join("../" + cve_id + "/change_low_version", filename)
            # print(file_path)
            with open(file_path, "r") as file1:
                patchs = file1.readlines()
            file1.close()
            diffs = []
            diff = []
            # Split patches by @@ lines
            for patch in patchs:
                if "@@" in patch:
                    # print(patch)
                    if diff == []:
                        diff.append(patch)
                    else:
                        diffs.append(diff)
                        diff = []
                        diff.append(patch)
                else:
                    diff.append(patch)
            diffs.append(diff)
            # print(diffs)
            # Search added lines (+) for matching changed lines in sorted_data
            for diff in diffs:
                for line in diff:
                    line = line.strip()
                    if line.startswith("+"):
                        # print(line)
                        for data in sorted_data:
                            ev_line = line.split("+", 1)[1]
                            ev_line.strip()
                            # print(ev_line)
                            if data[2] in ev_line:
                                print(file_path)
                                result.append(file_path)

    # If no results, try searching by function names only
    if result == []:
        for name in func_name_list:
            name = traver.extract_function_name(name)
            # print(name)
            for filename in os.listdir("../" + cve_id + "/change_low_version"):
                # Build full file path
                file_path = os.path.join("../" + cve_id + "/change_low_version", filename)
                # print(file_path)
                with open(file_path, "r") as file1:
                    patchs = file1.readlines()
                file1.close()
                diffs = []
                diff = []
                # Split patches by @@ lines
                for patch in patchs:
                    if "@@" in patch:
                        # print(patch)
                        if diff == []:
                            diff.append(patch)
                        else:
                            diffs.append(diff)
                            diff = []
                            diff.append(patch)
                    else:
                        diff.append(patch)
                diffs.append(diff)
                # print(diffs)

                # Search added lines (+) for function name
                for diff in diffs:
                    for line in diff:
                        line = line.strip()
                        if line.startswith("+"):
                            if name in line:
                                print(file_path)


# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
