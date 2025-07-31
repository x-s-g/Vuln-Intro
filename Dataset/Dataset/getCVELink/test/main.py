import requests
import json
import re
import time
from requests.exceptions import HTTPError
#获取全部数据
def fetch_cve_full(cve_id, api_key=None):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    # 设置 Clash HTTP 代理
    proxies = {
        "http": "http://127.0.0.1:7890",
        "https": "http://127.0.0.1:7890"
    }

    resp = requests.get(url, params=params, headers=headers, timeout=10, proxies=proxies)
    resp.raise_for_status()
    data = resp.json()

    if data.get("totalResults", 0) == 0:
        return None

    vuln = data["vulnerabilities"][0]["cve"]
    result = {
        "id": vuln.get("id"),
        "published": vuln.get("published"),
        "lastModified": vuln.get("lastModified"),
        "description": next((d["value"] for d in vuln.get("descriptions", []) if d.get("lang") == "en"), ""),
        "metrics": vuln.get("metrics", {}),
        "weaknesses": vuln.get("weaknesses", []),
        "references": vuln.get("references", []),
        "configurations": vuln.get("configurations", []),
        "vendorComments": vuln.get("vendorComments", [])
    }
    return result
#获取configurations.nodes.cpeMatch
def fetch_cep(cve_id, api_key=None, max_retries=3):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    # 设置 Clash HTTP 代理
    proxies = {
        "http": "http://127.0.0.1:7890",
        "https": "http://127.0.0.1:7890"
    }

    for attempt in range(max_retries):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=10, proxies=proxies)
            resp.raise_for_status()
            data = resp.json()
            if data.get("totalResults", 0) == 0:
                return None
            vuln = data["vulnerabilities"][0]["cve"]
            cve_id = data["vulnerabilities"][0]["cve"]["id"]
            configurations = data["vulnerabilities"][0]["cve"].get("configurations", [])
            cpeMatches = []
            for config in configurations:
                for node in config.get("nodes", []):
                    cpeMatches.extend(node.get("cpeMatch", []))
            return {
                "cve_id": cve_id,
                "cpeMatches": cpeMatches
            }
        except HTTPError as e:
            if resp.status_code == 429:
                print(f"[警告] 429 Too Many Requests: {cve_id}，等待 6 秒后重试（第{attempt+1}次）")
                time.sleep(6)
            else:
                print(f"[错误] 获取 {cve_id} 时发生 HTTP 错误: {e}")
                break
        except Exception as e:
            print(f"[错误] 获取 {cve_id} 时发生异常: {e}")
            break
    return None
def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"数据已保存到 {filename}")
def extract_cve_ids_from_file(filename):
    cve_ids = []
    pattern = re.compile(r"CVE-\d{4}-\d+")
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                cve_ids.append(match.group())
    return cve_ids
if __name__ == "__main__":
    cve_ids = extract_cve_ids_from_file("out1.txt")
    print(f"共找到 {len(cve_ids)} 个 CVE ID")
    all_results = []
    failed_cve_ids = []
    for idx, cve_id in enumerate(cve_ids, 1):
        print(f"正在处理第 {idx}/{len(cve_ids)} 个：{cve_id}")
        info = fetch_cep(cve_id, api_key=None)
        if info:
            all_results.append(info)
        else:
            print(f"未获取到 {cve_id} 的数据")
            failed_cve_ids.append(cve_id)
        time.sleep(1)
    save_to_json(all_results, "all_cve_data.json")
    if failed_cve_ids:
        with open("failed_cve_ids.txt", "w", encoding="utf-8") as f:
            for cve_id in failed_cve_ids:
                f.write(cve_id + "\n")
        print(f"未获取到数据的 CVE ID 已保存到 failed_cve_ids.txt")
