import re
import requests
from lxml import etree
import os

# ==============================
# Function: extract_commit_hash
# Description: Extracts the commit hash from a given URL using regular expressions.
# ==============================
def extract_commit_hash(url):
    pattern = r'/commit(?:/\?id=|/)([0-9a-fA-F]{40})'
    match = re.search(pattern, url)
    if match is None:
        pattern = r'id=([a-f0-9]+)$'
        match = re.search(pattern, url)
    if match is None:
        match = re.search(r'/([0-9a-fA-F]+)$', url)
    if match is None:
        match = re.search(r'[^/]+$', url)
    if match:
        return match.group(1)
    else:
        return None

# ==============================
# Function: find_link
# Description: Retrieves the GitHub or Kernel.org commit hash linked to a CVE ID from NVD.
# ==============================
def find_link(CVE_id):
    cve_link = "https://nvd.nist.gov/vuln/detail/" + CVE_id
    response = requests.get(cve_link)
    root = etree.HTML(response.content)
    items = root.xpath("//div[@id='vulnHyperlinksPanel']//table[@class='table table-striped table-condensed table-bordered detail-table']/tbody/tr")
    for i in items:
        s = i.xpath('./td/a/@href')
        if "https://git.kernel.org" in s[0] or "https://github.com" in s[0]:
            commit = extract_commit_hash(s[0])
            return commit

# ==============================
# Function: create_folder
# Description: Creates a directory if it doesn't already exist.
# ==============================
def create_folder(path):
    try:
        os.makedirs(path, exist_ok=True)
        print(f"Folder '{path}' created successfully.")
    except Exception as e:
        print(f"Error creating folder: {e}")

# ==============================
# Function: ab_file
# Description: Downloads and saves the before and after source files from a kernel.org commit.
# ==============================
def ab_file(hyper_link, CVE_id):
    response = requests.get(hyper_link)
    root = etree.HTML(response.content)
    file_ab = root.xpath("//table[@class='diff']/tr/td//div[@class='head']")
    for i in file_ab:
        # Before patch
        s_a_name = i.xpath("./a[1]/text()")[0].replace('/', '#')
        s_a = i.xpath("./a[1]/@href")[0]
        response1 = requests.get("https://git.kernel.org" + s_a)
        root1 = etree.HTML(response1.content)
        plain = root1.xpath("//div[@class='content']/a/@href")[0]
        response2 = requests.get("https://git.kernel.org" + plain)
        with open(f"../{CVE_id}/af#{s_a_name}", "w") as file:
            file.write(response2.text)

        # After patch
        s_b_name = i.xpath("./a[2]/text()")[0].replace('/', '#')
        s_b = i.xpath("./a[2]/@href")[0]
        response1 = requests.get("https://git.kernel.org" + s_b)
        root1 = etree.HTML(response1.content)
        plain = root1.xpath("//div[@class='content']/a/@href")[0]
        response2 = requests.get("https://git.kernel.org" + plain)
        with open(f"../{CVE_id}/bf#{s_b_name}", "w") as file:
            file.write(response2.text)

# ==============================
# Function: get_patch
# Description: Extracts and writes the patch diff contents (hunks, additions, deletions, context) to a file.
# ==============================
def get_patch(link, cve_id):
    response = requests.get(link)
    root = etree.HTML(response.content)
    diffs = root.xpath("//table[@class='diff']/tr/td//div")
    for diff in diffs:
        diff_class = diff.xpath("@class")
        if diff_class in [['hunk'], ['add'], ['del'], ['ctx']]:
            with open(f"../{cve_id}/patch.txt", "a") as file:
                file.write(diff.xpath("text()")[0] + "\n")

# ==============================
# Function: load_file
# Description: Main logic to fetch patch information and source files for a given CVE ID.
# ==============================
def load_file(cve_id):
    # Step 1: Find patch commit link
    link = find_link(cve_id)
    if not link:
        print(f"No commit link found for {cve_id}")
        return

    hyper_link = f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={link}"

    # Step 2: Create folder
    # create_folder(f"CVE/{cve_id}")
    #
    # # Step 3: Download before/after source files
    # ab_file(hyper_link, cve_id)
    #
    # # Step 4: Download patch diff
    # get_patch(hyper_link, cve_id)

# ==============================
# Main Entry Point
# ==============================
def main():
    CVE_id = "CVE-2023-6176"  # Replace this with any other CVE ID to test
    load_file(CVE_id)
    # To test a specific patch manually:
    # get_patch("https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/netfilter/nf_tables_api.c?id=4a9e12ea7e70223555ec010bec9f711089ce96f6", "test")

if __name__ == "__main__":
    main()
