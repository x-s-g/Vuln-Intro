# getCVELink Project Description

## Project Overview

This project is designed for batch crawling of CVE (Common Vulnerabilities and Exposures) configuration information (`cpeMatch`) and performing multi-dimensional statistics on the results. It supports automatic extraction of CVE IDs from a list of URLs, handles API rate limits automatically, and outputs detailed statistical results.

## Directory Structure



```
getCVELink/
├── statistics/ # Directory for storing statistical data
│ ├── has_versionStartIncluding.txt # List of CVE IDs that include versionStartIncluding
│ ├── no_versionStartIncluding.txt # List of CVE IDs that do not include versionStartIncluding
│ └── no_cpeMatch.txt # List of CVE IDs without any cpeMatch entries
├── main.py # Main program for batch crawling CVE data
├── stat_cve.py # Script for statistical analysis
├── out1.txt # List of CVE URLs to be crawled
├── all_cve_data.json # Full CVE data after batch crawling
├── cve_data.json # Sample data for a single CVE
├── fulldata.json # Sample data for other purposes
├── test/
│ ├── all_cve_data.json # Test batch data
│ ├── out1.txt # Test CVE URL list
│ └── ...
└── ...
```


## Usage

### 1. Batch Crawling CVE Data

1. Put the list of CVE URLs into `out1.txt`, one URL per line. Example:

   ```
   https://nvd.nist.gov/vuln/detail/CVE-2023-52916
   ``` 
2. Run the main program:
：
   ```
   python main.py
   ```
- The program will automatically extract CVE IDs, crawl each one, and handle API rate limits (automatic retries for 429 errors).
- Successful results are saved in `all_cve_data.json`, and failed CVE IDs are saved in `failed_cve_ids.txt`.

### 2. Statistical Analysis

1. Ensure that `all_cve_data.json` has been generated.
2. Run the statistics script:

   ```
   python stat_cve.py
   ```
3. The statistical results will be saved under the `test/` directory:
- `has_versionStartIncluding.txt`  
  - Each block corresponds to a CVE ID; the first line is the CVE ID, followed by all `versionStartIncluding` values.
- `no_versionStartIncluding.txt`  
  - CVE IDs without any `versionStartIncluding` field, one per line.
- `no_cpeMatch.txt`  
  - CVE IDs without any `cpeMatch`, one per line.

## Environment Requirements

- Python 3.7+
- `requests` library

Install dependencies:

```
pip install requests
```

## Notes

- The script uses the local Clash proxy by default (`127.0.0.1:7890`). To change it, modify the proxy settings in `main.py`.
- The NVD API has request rate limits. This script includes automatic retry and delay mechanisms. It's recommended to control the batch request volume.
- The output directory for the statistics script can be modified as needed.

## Result Examples

- Example of `has_versionStartIncluding.txt`:


- `has_versionStartIncluding.txt` 示例：
  ```
  CVE-2023-52915
  4.15
  4.20
  5.5
  ...
  ```

- `no_cpeMatch.txt` 示例：
  ```
  CVE-2023-52916
  CVE-2024-45008
  ...
  ``` 