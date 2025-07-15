import requests
from lxml import etree
from pathlib import Path
from typing import List


def substring_from_position(input_string: str, start_position: int) -> str:
    """Returns the substring starting from the given position."""
    return input_string[start_position:]


def extract_commit_links(
    input_file: str = "nvd_links.txt",
    output_file: str = "url.txt",
    match_prefix: str = "https://github.com/uclouvain/openjpeg/commit/",
    filename_offset: int = 33,
) -> List[tuple[str, str]]:
    """
    Parse NVD CVE detail pages to extract GitHub commit links.

    Parameters
    ----------
    input_file : str
        A file containing a list of CVE detail page URLs (one per line).
    output_file : str
        Path to write extracted filename and commit URL pairs.
    match_prefix : str
        The GitHub commit link prefix to match.
    filename_offset : int
        The character offset to extract the "filename" from the CVE URL.

    Returns
    -------
    List[tuple[str, str]]
        A list of (filename, commit_link) tuples that matched and were saved.
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    output_path.unlink(missing_ok=True)  # Remove old output if exists

    extracted_links = []

    with input_path.open("r", encoding="utf-8") as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        filename = substring_from_position(line, filename_offset)
        print(f"Filename: {filename}")

        try:
            response = requests.get(line, timeout=10)
            if response.status_code != 200:
                print(f"Failed to fetch: {line}")
                continue
        except requests.RequestException as e:
            print(f"Error fetching {line}: {e}")
            continue

        root = etree.HTML(response.content)
        rows = root.xpath(
            "//div[@id='vulnHyperlinksPanel']//table[contains(@class,'detail-table')]/tbody/tr"
        )

        for row in rows:
            hrefs = row.xpath("./td/a/@href")
            if not hrefs:
                continue
            href = hrefs[0]
            if href.startswith(match_prefix):
                print(f"Matched Commit URL: {href}")
                extracted_links.append((filename, href))
                with output_path.open("a", encoding="utf-8") as out:
                    out.write(filename + "\n")
                    out.write(href + "\n")
                break  # Only save the first match per CVE

    print(f"\n Finished. {len(extracted_links)} commit links extracted.")
    return extracted_links


# ========== Program Entry ==========
if __name__ == "__main__":
    extract_commit_links()
