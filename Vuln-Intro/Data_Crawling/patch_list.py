import load_file
import requests
from lxml import etree

# ==============================
# Function: find_file_path
# Description: Given a commit link, this function extracts the paths of affected files,
# then traces their full commit history using the Linux kernel's web interface.
# ==============================
def find_file_path(link):
    link_list = []
    response = requests.get(link)
    root = etree.HTML(response.content)

    # Get list of changed files from the diffstat table
    filename = root.xpath("//table[@class='diffstat']/tr")
    for i in filename:
        # Try to get file path from different change types
        s1 = i.xpath("./td[@class='upd']/a/text()")
        s2 = i.xpath("./td[@class='del']/a/text()")
        s3 = i.xpath("./td[@class='add']/a/text()")
        s4 = i.xpath("./td[@class='mov']/a/text()")

        if s1 == [] and (s2 != [] or s3 != [] or s4 != []):
            if s2 == [] and s3 == []:
                s = s4
            elif s3 == [] and s4 == []:
                s = s2
            else:
                s = s3
        else:
            s = s1

        # Traverse commit history for this file path
        if not s:
            continue
        link_list += collect_commits_for_path(s[0])

    return link_list

# ==============================
# Function: collect_commits_for_path
# Description: Collects commit links for a given file path with pagination handling.
# ==============================
def collect_commits_for_path(path_component):
    collected_links = []
    base_url = f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/{path_component}"
    offset = 0

    while True:
        url = base_url + (f"?ofs={offset}" if offset else "")
        response = requests.get(url)
        root = etree.HTML(response.content)

        # Extract commit links from the log table
        commits = root.xpath("//div[@class='content']//table[@class='list nowrap']/tr")
        for row in commits:
            commit = row.xpath("./td[2]/a/@href")
            if commit:
                collected_links.append("https://git.kernel.org" + commit[0])

        # Check if there's a [next] page
        next_btn = root.xpath("//div[@class='content']//ul[@class='pager']/li/a[text()='[next]']")
        if not next_btn:
            break
        offset += 200

    return collected_links

# ==============================
# Function: filter_patch
# Description: Filters out commits from a list that are older (lower) than the given patch commit.
# ==============================
def filter_patch(file_path, link):
    link_list = []
    flag = False
    for path in file_path:
        if link in path:
            flag = True
        if flag:
            link_list.append(path)
    return link_list

# ==============================
# Function: main
# Description: Main function to retrieve related historical commit links for a CVE.
# ==============================
def main(CVE_id):
    # Step 1: Get main patch commit link from CVE ID
    link = load_file.find_link(CVE_id)
    print("Main commit:", link)

    # Step 2: Build full commit URL
    hyper_link = f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={link}"

    # Step 3: Find all file-related commit paths
    file_path = find_file_path(hyper_link)

    # Step 4: Filter out historical commits introduced before the main patch
    low_version = filter_patch(file_path, link)

    # Optional: Write patch list to file (uncomment to use)
    # for i in low_version:
    #     with open(f"../{CVE_id}/patch_list.txt", "a") as file:
    #         file.write(i + "\n")

# ==============================
# Entry Point
# ==============================
if __name__ == "__main__":
    CVE_id = "CVE-2023-6176"
    main(CVE_id)
