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
