import json

with open('all_cve_data.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

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

# 写入 has_versionStartIncluding.txt
with open('./statistics/has_versionStartIncluding.txt', 'w', encoding='utf-8') as f:
    for cve_id, versions in has_version.items():
        f.write(cve_id + '\n')
        for v in versions:
            f.write(v + '\n')
print("has_versionStartIncluding.txt 写入完成")
# 写入 no_versionStartIncluding.txt
with open('./statistics/no_versionStartIncluding.txt', 'w', encoding='utf-8') as f:
    for cve_id in no_version:
        f.write(cve_id + '\n')
print("no_versionStartIncluding.txt 写入完成")

# 写入 no_cpeMatch.txt
with open('./statistics/no_cpeMatch.txt', 'w', encoding='utf-8') as f:
    for cve_id in no_cpe:
        f.write(cve_id + '\n')
print("no_cpeMatch.txt 写入完成")