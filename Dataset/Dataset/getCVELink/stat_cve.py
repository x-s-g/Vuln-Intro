import json
import os

# 统计模式：'all' 只统计 all_cve_data.json，'all+retry' 统计 all_cve_data.json + retry_cve_data.json
mode = 'all+retry'  # 可选 'all' 或 'all+retry'

if mode == 'all':
    files = ['all_cve_data.json']
elif mode == 'all+retry':
    files = ['all_cve_data.json', 'retry_cve_data.json']
else:
    raise ValueError('mode 只能为 all 或 all+retry')

def load_json_files(file_list):
    data = []
    for file in file_list:
        if os.path.exists(file):
            with open(file, 'r', encoding='utf-8') as f:
                data.extend(json.load(f))
        else:
            print(f"警告：文件 {file} 不存在，已跳过。")
    return data

data = load_json_files(files)

has_version = {}
no_version = []
no_cpe = []

for item in data:
    cve_id = item.get('cve_id')
    cpeMatches = item.get('cpeMatches', [])
    version_list = []
    if not cpeMatches:
        no_cpe.append(cve_id)
    for cpe in cpeMatches:
        v = cpe.get('versionStartIncluding')
        if v is not None:
            version_list.append(v)
    if version_list:
        has_version[cve_id] = version_list
    elif cpeMatches:
        no_version.append(cve_id)

os.makedirs('./statistics', exist_ok=True)
with open('./statistics/has_versionStartIncluding.txt', 'w', encoding='utf-8') as f:
    for cve_id, versions in has_version.items():
        f.write(cve_id + '\n')
        for v in versions:
            f.write(v + '\n')
print("has_versionStartIncluding.txt 写入完成")
print(f"has_versionStartIncluding.txt 共 {len(has_version)} 个 cveid")
with open('./statistics/no_versionStartIncluding.txt', 'w', encoding='utf-8') as f:
    for cve_id in no_version:
        f.write(cve_id + '\n')
print("no_versionStartIncluding.txt 写入完成")
print(f"no_versionStartIncluding.txt 共 {len(no_version)} 个 cveid")
with open('./statistics/no_cpeMatch.txt', 'w', encoding='utf-8') as f:
    for cve_id in no_cpe:
        f.write(cve_id + '\n')
print("no_cpeMatch.txt 写入完成")
print(f"no_cpeMatch.txt 共 {len(no_cpe)} 个 cveid")
# 统计总唯一 cveid 数
all_cveid = set(has_version.keys()) | set(no_version) | set(no_cpe)
print(f"总共统计了 {len(all_cveid)} 个唯一 cveid")