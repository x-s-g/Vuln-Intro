import re
import json
from main import fetch_cep

def read_failed_cveids(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def build_cveid_url_map(out1_file):
    cveid_url = {}
    pattern = re.compile(r'(CVE-\d{4}-\d+)')
    with open(out1_file, 'r', encoding='utf-8') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                cveid_url[match.group()] = line.strip()
    return cveid_url

if __name__ == "__main__":
    failed_cveids = read_failed_cveids('failed_cve_ids.txt')
    cveid_url_map = build_cveid_url_map('out1.txt')
    results = []
    failed = []
    for idx, cveid in enumerate(failed_cveids, 1):
        url = cveid_url_map.get(cveid)
        print(f"[{idx}/{len(failed_cveids)}] 处理 {cveid} : {url if url else '未找到URL'}")
        if not url:
            failed.append(cveid)
            continue
        info = fetch_cep(cveid, api_key=None)
        if info:
            results.append(info)
        else:
            failed.append(cveid)
    with open('retry_cve_data.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    with open('retry_failed_cve_ids.txt', 'w', encoding='utf-8') as f:
        for cveid in failed:
            f.write(cveid + '\n')
    print(f"重试完成，成功 {len(results)} 个，失败 {len(failed)} 个。") 