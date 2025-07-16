import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Data_Crawling')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Static_Analysis')))
import os.path

import requests
from lxml import etree
import af_code
import filter
import re
import load_file
import re_refactor

# Common C language types and keywords for function detection
types = [
    'static ', 'struct ', 'int ', 'short ', 'long ', 'long long ', 'unsigned int ',
    'unsigned short ', 'unsigned long ', 'unsigned long long ', 'signed int ',
    'signed short ', 'signed long ', 'signed long long ', 'float ', 'double ',
    'long double ', 'char ', 'unsigned char ', 'signed char ', 'void ', 'enum ', 'union ','__cold'
]

import os
import requests
from lxml import etree


def load_patch(patch_list, cve_id):
    """
    Download patches from URLs in patch_list and save commit diffs locally.

    Args:
        patch_list (list): List of patch URLs.
        cve_id (str): CVE identifier for folder structure.
    """
    for patch in patch_list:
        commit_id = patch.split("id=", 1)[1]
        response = requests.get(patch)
        root = etree.HTML(response.content)
        diffs = root.xpath("//table[@class='diff']/tr/td//div")
        for diff in diffs:
            text_list = diff.xpath("text()")
            if text_list:  # Check text_list is not empty
                text = text_list[0]
                if diff.xpath("@class") in [['hunk'], ['add'], ['del'], ['ctx']]:
                    # Ensure directory exists
                    os.makedirs(f"CVE/{cve_id}/commit", exist_ok=True)
                    # Write patch text with utf-8 encoding, ignore encoding errors
                    with open(f"../{cve_id}/commit/{commit_id}.txt", "a", encoding="utf-8", errors="ignore") as file:
                        file.write(text)
                        file.write("\n")


def find_new_func(diffs):
    """
    Identify new function definitions in a list of diffs.

    Args:
        diffs (list): List of diffs, each diff is a list of lines.

    Returns:
        list: List of new function definition lines detected.
    """
    new_name_list = []
    for diff in diffs:
        for line in diff:
            if not line.strip():
                continue
            # Lines starting with '+' indicate additions
            if line.startswith('+'):
                stripped_line = line[1:]
                # Check if line looks like function definition start
                if any(stripped_line.startswith(t) for t in types) and '(' in stripped_line:
                    new_name_list.append(stripped_line)
    return new_name_list


def patch_to_list(diffs):
    """
    Convert raw diff lines into grouped chunks by '@@' hunk headers.

    Args:
        diffs (list): Raw diff lines.

    Returns:
        list: List of chunks (each chunk is list of lines).
    """
    list = []
    list1 = []
    for line in diffs:
        line = line.rstrip()
        if line.startswith('@@'):
            if list1 == []:
                list1.append(line)
                continue
            else:
                list.append(list1)
                list1 = []
                list1.append(line)
                continue
        list1.append(line)
    list.append(list1)
    return list


def find_old_name(new_name, diffs):
    """
    Find the old name of a function given its new name by analyzing diffs.

    Args:
        new_name (str): New function name.
        diffs (list): List of diffs split into chunks.

    Returns:
        str or None: Old function name if found, else None.
    """
    pre_line = None
    for diff in diffs:
        for line in diff:
            if new_name == line[1:]:
                if pre_line and pre_line.startswith("-"):
                    return pre_line[1:]
                else:
                    return None
            else:
                pre_line = line


def is_last_element(lst, element):
    """
    Check if the specified element is the last element in a list.

    Args:
        lst (list): List to check.
        element (any): Element to verify.

    Returns:
        bool: True if element is last in list, else False.
    """
    if not lst:
        return False
    return lst[-1] == element


def name_to_commit(cve_id, new_name, new_func_list, storage):
    """
    Recursively map new function names to their commits and old names.

    Args:
        cve_id (str): CVE identifier.
        new_name (str): Function name to search.
        new_func_list (list): List of (commit_id, func_names) tuples.
        storage (list): Accumulates (commit_id, func_name) tuples.
    """
    flag = False
    for commit_id, func_names in new_func_list:
        for patch in func_names:
            if patch == new_name and not flag:
                flag = True
                with open(f"../{cve_id}/commit/{commit_id}.txt", "r") as file:
                    diffs = file.readlines()
                list1 = patch_to_list(diffs)
                old_name = find_old_name(patch, list1)
                if old_name is not None:
                    storage.append((commit_id, new_name))
                    name_to_commit(cve_id, old_name, new_func_list, storage)
                else:
                    storage.append((commit_id, new_name))


def rename(cve_id, patch_list, patch_func_name):
    """
    Find all new functions in patches and map their commit history recursively.

    Args:
        cve_id (str): CVE identifier.
        patch_list (list): List of patch URLs.
        patch_func_name (list): List of function names patched.

    Returns:
        list: List of tuples (func_name, list of (commit_id, func_name) tuples).
    """
    new_func = []
    for patch in patch_list:
        with open(f"../{cve_id}/commit/{patch.split('id=',1)[1]}.txt", "r") as file:
            diffs = file.readlines()
        list1 = patch_to_list(diffs)
        list2 = find_new_func(list1)
        if list2:
            new_func.append((patch.split("id=",1)[1], list2))

    storages = []
    for name in patch_func_name:
        storage = []
        name_to_commit(cve_id, name, new_func, storage)
        storages.append((name, storage))
    return storages


def compare_name(commit, commits, patch_list):
    """
    Compare commit positions and select the function name that appears later.

    Args:
        commit (str): Commit id.
        commits (list): List of (commit_id, func_name) tuples.
        patch_list (list): List of patch URLs.

    Returns:
        str or None: Selected function name based on commit order.
    """
    a = commit
    flag = 0
    flag1 = 0

    for i in patch_list:
        flag += 1
        i = i.split("id=", 1)[1]
        if i == a:
            flag1 = flag

    for patch_id, patch_name in commits:
        b = patch_id
        flag = 0
        for i in patch_list:
            flag += 1
            i = i.split("id=", 1)[1]
            if i == b:
                if flag >= flag1:
                    return patch_name
    return None


def load_b_file(cve_id, file_name):
    """
    Download and save the lower version file corresponding to a patch.

    Args:
        cve_id (str): CVE identifier.
        file_name (str): Commit id or patch identifier.
    """
    print(file_name)
    with open(f"../{cve_id}/patch_list.txt", "r") as file:
        diffs = file.readlines()
    for diff in diffs:
        diff = diff.strip()
        if file_name in diff:
            print(diff)
            response = requests.get(diff)
            root = etree.HTML(response.content)
            file_ab = root.xpath("//table[@class='diff']/tr/td//div[@class='head']")
            for i in file_ab:
                # Find modified file after patch
                s_b = i.xpath("./a[2]/@href")
                if s_b:
                    response1 = requests.get("https://git.kernel.org" + s_b[0])
                    root1 = etree.HTML(response1.content)
                    plain = root1.xpath("//div[@class='content']/a/@href")
                    response2 = requests.get("https://git.kernel.org" + plain[0])
                    path = f"CVE/{cve_id}/change_low_version/{file_name}.txt"
                    if not os.path.exists(path):
                        with open(f"../{path}", "w") as file:
                            file.write(response2.text)
                else:
                    s_b = i.xpath("./a[1]/@href")
                    response1 = requests.get("https://git.kernel.org" + s_b[0])
                    root1 = etree.HTML(response1.content)
                    plain = root1.xpath("//div[@class='content']/a/@href")
                    response2 = requests.get("https://git.kernel.org" + plain[0])
                    path = f"CVE/{cve_id}/change_low_version/{file_name}.txt"
                    if not os.path.exists(path):
                        with open(f"../{path}", "w") as file:
                            file.write(response2.text)


def change_commit(cve_id, patch_list, fun_name, commits):
    """
    Download corresponding b-version files for commits related to function names.

    Args:
        cve_id (str): CVE identifier.
        patch_list (list): List of patch URLs.
        fun_name (str): Function name.
        commits (list): List of (commit_id, func_name) tuples.
    """
    for patch in patch_list[1:]:
        # Read and preprocess patch file
        list1 = re_refactor.refactor_detect_extracted(f"../{cve_id}/commit/{patch.split('id=',1)[1]}.txt")
        list2 = re_refactor.delete_comment(list1)
        comp_name = compare_name(patch.split('id=',1)[1], commits, patch_list)
        if comp_name is not None:
            for diff in list2:
                if comp_name in diff[0]:
                    load_b_file(cve_id, patch.split("id=", 1)[1])

        for commit in commits:
            if patch.split("id=",1)[1] == commit[0]:
                load_b_file(cve_id, patch.split("id=", 1)[1])


def change(cve_id, patch_list, patch_func_name, storages):
    """
    Trigger downloading of low version files for patched functions.

    Args:
        cve_id (str): CVE identifier.
        patch_list (list): List of patch URLs.
        patch_func_name (list): List of patched function names.
        storages (list): List of (func_name, list of commits) tuples.
    """
    for i in patch_func_name:
        for storage in storages:
            if storage[0] == i:
                change_commit(cve_id, patch_list, storage[0], storage[1])


def main(cve_id):
    """
    Main entry function to coordinate patch downloading, function renaming tracking and file retrieval.

    Args:
        cve_id (str): CVE identifier.
    """
    with open(f"../{cve_id}/patch_list.txt", "r") as file:
        patch_list = file.readlines()
    patch_list = [line.strip() for line in patch_list]

    # Uncomment if needed to create directories and download patches
    # load_file.create_folder(f"../{cve_id}/commit")
    # load_patch(patch_list, cve_id)

    # Get list of patched function names
    list1 = filter.main(cve_id)
    func_name_list = af_code.find_patch_func(list1)

    # Generate storage mapping for function renaming
    storages_names = rename(cve_id, patch_list, func_name_list)

    # Print out mapping results
    for storage_name in storages_names:
        print(storage_name[0])
        for i in storage_name[1]:
            print(i)

    # Uncomment to create folders and download lower version files
    # load_file.create_folder(f"CVE/{cve_id}/change_low_version")
    # change(cve_id, patch_list, func_name_list, storages_names)

# ==============================
# Main Entry Point
# ==============================

if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
