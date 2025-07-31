import requests
import json
import re
import time
from requests.exceptions import HTTPError

# CVE information

# Fetch full CVE data
def fetch_cve_full(cve_id, api_key=None):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    # Set Clash HTTP proxy
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

# Fetch configurations.nodes.cpeMatch
def fetch_cep(cve_id, api_key=None, max_retries=3):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    # Set Clash HTTP proxy
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
                print(f"[Warning] 429 Too Many Requests: {cve_id}, retrying after 6 seconds (attempt {attempt+1})")
                time.sleep(6)
            else:
                print(f"[Error] HTTP error while fetching {cve_id}: {e}, retrying after 10 seconds (attempt {attempt+1})")
                time.sleep(10)
        except (requests.ConnectionError, requests.Timeout) as e:
            print(f"[Warning] Connection error for {cve_id}, retrying after 10 seconds (attempt {attempt+1}): {e}")
            time.sleep(10)
        except Exception as e:
            print(f"[Error] Unknown error while fetching {cve_id}: {e}, retrying after 10 seconds (attempt {attempt+1})")
            time.sleep(10)
    return None

# Save data to JSON file
def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Data saved to {filename}")

# Extract CVE IDs from file
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
    print(f"Found {len(cve_ids)} CVE IDs")
    all_results = []
    failed_cve_ids = []
    for idx, cve_id in enumerate(cve_ids, 1):
        print(f"Processing {idx}/{len(cve_ids)}: {cve_id}")
        info = fetch_cep(cve_id, api_key=None)
        if info:
            all_results.append(info)
        else:
            print(f"No data fetched for {cve_id}")
            failed_cve_ids.append(cve_id)
        time.sleep(1)
    save_to_json(all_results, "all_cve_data.json")
    if failed_cve_ids:
        with open("failed_cve_ids.txt", "w", encoding="utf-8") as f:
            for cve_id in failed_cve_ids:
                f.write(cve_id + "\n")
        print(f"Failed CVE IDs saved to failed_cve_ids.txt")
