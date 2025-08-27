import os
from bs4 import BeautifulSoup

# htmls 文件夹路径 读取本地保存的 HTML 文件（由浏览器另存为）
htmls_dir = "htmls"

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
with open("patch_list.txt", "w", encoding="utf-8") as f:
    for link in all_links:
        f.write(link + "\n")

print(f"提取到的链接个数: {len(all_links)}")
