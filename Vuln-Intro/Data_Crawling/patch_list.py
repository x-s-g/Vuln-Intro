import requests
from lxml import etree
import load_file  # Assumes `load_file.find_link(cve_id)` returns the commit hash


class PatchHistoryFetcher:
    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        self.base_log_url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/"
        self.base_commit_url = "https://git.kernel.org"
        self.commit_hash = load_file.find_link(cve_id)
        self.target_commit_url = f"{self.base_commit_url}/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={self.commit_hash}"
        self.output_path = f"CVE/{cve_id}/patch_list.txt"

    def run(self):
        """Main entry: download commit list and save filtered results."""
        print(f"🔍 Target CVE: {self.cve_id}, commit: {self.commit_hash}")
        file_log_links = self._find_file_log_links()
        filtered_commits = self._filter_commits(file_log_links)
        self._save_results(filtered_commits)

    def _find_file_log_links(self) -> list[str]:
        """Extracts file path from the diff page, then crawls all its historical commits."""
        link_list = []
        response = requests.get(self.target_commit_url)
        root = etree.HTML(response.content)

        rows = root.xpath("//table[@class='diffstat']/tr")
        for row in rows:
            # Try multiple diff types to extract file path
            path_candidates = (
                row.xpath("./td[@class='upd']/a/text()")
                or row.xpath("./td[@class='del']/a/text()")
                or row.xpath("./td[@class='add']/a/text()")
                or row.xpath("./td[@class='mov']/a/text()")
            )
            if not path_candidates:
                continue
            file_path = path_candidates[0]
            link_list.extend(self._crawl_commit_history(file_path))
        return link_list

    def _crawl_commit_history(self, file_path: str) -> list[str]:
        """Recursively crawls all pages of commit history for a file."""
        all_links = []
        offset = 0
        while True:
            url = f"{self.base_log_url}{file_path}?ofs={offset}" if offset else f"{self.base_log_url}{file_path}"
            response = requests.get(url)
            root = etree.HTML(response.content)

            rows = root.xpath("//div[@class='content']//table[@class='list nowrap']/tr")
            for row in rows:
                commit = row.xpath("./td[2]/a/@href")
                if commit:
                    all_links.append(self.base_commit_url + commit[0])

            next_page = root.xpath("//div[@class='content']//ul[@class='pager']/li/a[text()='[next]']")
            if not next_page:
                break
            offset += 200
        return all_links

    def _filter_commits(self, all_links: list[str]) -> list[str]:
        """Filters out commits newer than the current CVE commit."""
        result = []
        found = False
        for link in all_links:
            if self.commit_hash in link:
                found = True
            if found:
                result.append(link)
        return result

    def _save_results(self, commit_links: list[str]):
        """Writes the filtered commits to patch_list.txt."""
        with open(self.output_path, "a", encoding="utf-8") as f:
            for link in commit_links:
                f.write(link + "\n")
        print(f"✅ Saved {len(commit_links)} commit(s) to {self.output_path}")


def main():
    cve_id = "CVE-2020-25284"
    fetcher = PatchHistoryFetcher(cve_id)
    fetcher.run()

# ====================== Program Entry ======================

if __name__ == "__main__":
    main()
