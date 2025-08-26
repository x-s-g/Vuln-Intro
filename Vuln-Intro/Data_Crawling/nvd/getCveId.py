import requests
import time

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
headers = {}

def get_all_cve_ids(keyword="linux kernel", output_file="cve_ids.txt", max_results=20000):
    """
    获取CVE ID并保存到文件，支持分页
    
    Args:
        keyword (str): 搜索关键词
        output_file (str): 输出文件名
        max_results (int): 最大结果数量
    """
    all_cve_ids = []
    start_index = 0
    results_per_page = 2000  # NVD API最大支持2000
    
    print(f"Searching for CVE IDs containing keyword '{keyword}'...")
    print(f"Output file: {output_file}")
    
    while len(all_cve_ids) < max_results:
        params = {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": min(results_per_page, max_results - len(all_cve_ids))
        }
        
        print(f"Requesting page: startIndex={start_index}, resultsPerPage={params['resultsPerPage']}")
        
        try:
            response = requests.get(API_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)
            
            if not vulnerabilities:
                print("No more results found")
                break
            
            # 收集当前页的CVE ID
            page_cve_ids = []
            for item in vulnerabilities:
                cve_id = item["cve"]["id"]
                page_cve_ids.append(cve_id)
            
            all_cve_ids.extend(page_cve_ids)
            
            print(f"Found {len(page_cve_ids)} CVE IDs. Total collected: {len(all_cve_ids)}/{total_results}")
            
            # 如果获取的结果数少于请求数，说明已经到最后一页
            if len(vulnerabilities) < params['resultsPerPage']:
                print("Reached last page")
                break
            
            # 更新起始索引
            start_index += results_per_page
            
            # API速率限制延迟
            print("Waiting 0.6 seconds for rate limiting...")
            time.sleep(0.6)
            
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            break
        except Exception as e:
            print(f"Error: {e}")
            break
    
    # 保存到文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for cve_id in all_cve_ids:
                f.write(f"{cve_id}\n")
        
        print(f"\nCompleted! Saved {len(all_cve_ids)} CVE IDs to {output_file}")
        
    except Exception as e:
        print(f"Error saving to file: {e}")
    
    return all_cve_ids

if __name__ == "__main__":
    keyword = "linux kernel"
    output_file = "linux_kernel_cve_ids.txt"
    max_results = 20000
    
    cve_ids = get_all_cve_ids(keyword, output_file, max_results)
    
    if cve_ids:
        print(f"\nFirst 10 CVE IDs:")
        for i, cve_id in enumerate(cve_ids[:10]):
            print(f"{i+1}. {cve_id}")
        
        if len(cve_ids) > 10:
            print(f"... and {len(cve_ids) - 10} more CVE IDs")
