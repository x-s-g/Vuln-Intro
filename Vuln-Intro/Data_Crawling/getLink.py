import os
from bs4 import BeautifulSoup

def extract_commit_links(htmls_dir, output_file):
    """
    从指定目录下的 HTML 文件中提取包含 "/commit/" 的链接，并保存到文件中。

    参数:
        htmls_dir (str): 包含 HTML 文件的目录路径。
        output_file (str): 输出链接的文件路径。
    """
    # 汇总所有链接
    all_links = set()

    # 遍历 htmls 文件夹下所有 html 文件
    for filename in os.listdir(htmls_dir):
        if filename.endswith(".html"):
            file_path = os.path.join(htmls_dir, filename)
            with open(file_path, "r", encoding="utf-8") as f:
                soup = BeautifulSoup(f, "html.parser")
            for td in soup.find_all("td"):
                a_tag = td.find("a")
                if a_tag and "href" in a_tag.attrs and "/commit/" in a_tag["href"]:
                    href = a_tag["href"]
                    if href.startswith("http"):
                        full_url = href
                    else:
                        full_url = "https://git.kernel.org" + href
                    all_links.add(full_url)

    # 保存到文件
    with open(output_file, "w", encoding="utf-8") as f:
        for link in all_links:
            f.write(link + "\n")

    print(f"提取到的链接个数: {len(all_links)}")
    return len(all_links)

def main():
    """
    主函数，用于调用 extract_commit_links 函数。
    """
    htmls_dir = "../"
    cve_id="CVE-2023-6176"
    output_file = "patch_list.txt"
    htmls_path = os.path.join(htmls_dir, f"{cve_id}", "htmls")
    output_path = os.path.join(htmls_dir, output_file)
    extract_commit_links(htmls_path, output_path)

if __name__ == "__main__":
    main()
