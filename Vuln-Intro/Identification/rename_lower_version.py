"""
===========================

Steps:
1. Downloads all historical diffs from a CVE patch list.
2. Detects newly added function definitions.
3. Tracks function renaming backward through commits.
4. Extracts and saves changed `b` files for matched functions.

"""

import os
import re
import requests
from lxml import etree

import af_code
import filter
import load_file
import re_refactor

TYPES = [
    'static ', 'struct ', 'int ', 'short ', 'long ', 'long long ', 'unsigned int ',
    'unsigned short ', 'unsigned long ', 'unsigned long long ', 'signed int ',
    'signed short ', 'signed long ', 'signed long long ', 'float ', 'double ',
    'long double ', 'char ', 'unsigned char ', 'signed char ', 'void ', 'enum ', 'union ','__cold'
]


def load_patch(patch_list, cve_id):
    for patch in patch_list:
        commit_id = patch.split("id=", 1)[1]
        response = requests.get(patch)
        root = etree.HTML(response.content)
        diffs = root.xpath("//table[@class='diff']/tr/td//div")
        os.makedirs(f"CVE/{cve_id}/commit", exist_ok=True)
        with open(f"CVE/{cve_id}/commit/{commit_id}.txt", "a", encoding="utf-8", errors="ignore") as file:
            for diff in diffs:
                text_list = diff.xpath("text()")
                if text_list and diff.xpath("@class") in [['hunk'], ['add'], ['del'], ['ctx']]:
                    file.write(text_list[0] + "\n")


def patch_to_list(diffs):
    chunks, chunk = [], []
    for line in diffs:
        line = line.rstrip()
        if line.startswith('@@'):
            if chunk:
                chunks.append(chunk)
            chunk = [line]
        else:
            chunk.append(line)
    if chunk:
        chunks.append(chunk)
    return chunks


def find_new_func(diffs):
    new_funcs = []
    for diff in diffs:
        for line in diff:
            if line.startswith('+'):
                body = line[1:]
                if any(body.startswith(t) for t in TYPES) and '(' in body:
                    new_funcs.append(body)
    return new_funcs


def find_old_name(new_line, diffs):
    prev = None
    for diff in diffs:
        for line in diff:
            if new_line == line[1:] and prev and prev.startswith('-'):
                return prev[1:]
            prev = line


def name_to_commit(cve_id, new_name, new_func_list, storage):
    for commit_id, func_names in new_func_list:
        if new_name in func_names:
            with open(f"CVE/{cve_id}/commit/{commit_id}.txt", "r") as f:
                diffs = f.readlines()
            chunks = patch_to_list(diffs)
            old = find_old_name(new_name, chunks)
            storage.append((commit_id, new_name))
            if old:
                name_to_commit(cve_id, old, new_func_list, storage)


def rename(cve_id, patch_list, patch_func_names):
    new_funcs = []
    for patch in patch_list:
        cid = patch.split("id=", 1)[1]
        with open(f"CVE/{cve_id}/commit/{cid}.txt", "r") as f:
            diffs = f.readlines()
        chunks = patch_to_list(diffs)
        names = find_new_func(chunks)
        if names:
            new_funcs.append((cid, names))

    storages = []
    for name in patch_func_names:
        storage = []
        name_to_commit(cve_id, name, new_funcs, storage)
        storages.append((name, storage))
    return storages


def compare_name(commit, commits, patch_list):
    idx = [i.split("id=", 1)[1] for i in patch_list].index(commit)
    for patch_id, patch_name in commits:
        if patch_list.index(f"id={patch_id}") >= idx:
            return patch_name


def load_b_file(cve_id, file_name):
    with open(f"CVE/{cve_id}/patch_list.txt", "r") as f:
        lines = [x.strip() for x in f.readlines()]
    for url in lines:
        if file_name in url:
            response = requests.get(url)
            root = etree.HTML(response.content)
            for head in root.xpath("//table[@class='diff']/tr/td//div[@class='head']"):
                hrefs = head.xpath("./a[2]/@href") or head.xpath("./a[1]/@href")
                if hrefs:
                    href = hrefs[0]
                    content_url = etree.HTML(requests.get("https://git.kernel.org" + href).content)
                    raw_link = content_url.xpath("//div[@class='content']/a/@href")[0]
                    content = requests.get("https://git.kernel.org" + raw_link).text
                    out_path = f"CVE/{cve_id}/change_low_version/{file_name}.txt"
                    if not os.path.exists(out_path):
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        with open(out_path, "w") as f:
                            f.write(content)


def change_commit(cve_id, patch_list, func_name, commits):
    for patch in patch_list[1:]:
        chunks = re_refactor.delete_comment(re_refactor.refactor_detect_extracted(f"CVE/{cve_id}/commit/{patch.split('id=',1)[1]}.txt"))
        comp = compare_name(patch.split("id=",1)[1], commits, patch_list)
        if comp:
            for chunk in chunks:
                if comp in chunk[0]:
                    load_b_file(cve_id, patch.split("id=", 1)[1])
        for commit in commits:
            if patch.split("id=",1)[1] == commit[0]:
                load_b_file(cve_id, patch.split("id=", 1)[1])


def change(cve_id, patch_list, patch_func_names, storages):
    for name in patch_func_names:
        for storage in storages:
            if storage[0] == name:
                change_commit(cve_id, patch_list, name, storage[1])


def main(cve_id):
    with open(f"CVE/{cve_id}/patch_list.txt", "r") as f:
        patch_list = [x.strip() for x in f.readlines()]

    load_file.create_folder(f"CVE/{cve_id}/commit")
    load_patch(patch_list, cve_id)
    filtered = filter.main(cve_id)
    func_names = af_code.find_patch_func(filtered)
    renamings = rename(cve_id, patch_list, func_names)
    for r in renamings:
        print(r[0])
        for pair in r[1]:
            print(pair)
    # Uncomment to extract final b files
    # load_file.create_folder(f"CVE/{cve_id}/change_low_version")
    # change(cve_id, patch_list, func_names, renamings)

# ====================== Program Entry ======================
if __name__ == "__main__":
    CVE_id = "CVE-2023-4459"
    main(CVE_id)
