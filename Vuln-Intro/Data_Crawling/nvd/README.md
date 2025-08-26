# CVE ID Collection Tool

An efficient data collection tool that uses the official NIST NVD API to directly collect CVE IDs and save them to files, with full pagination support.



## Requirements

- Python 3.6+
- requests library

## Quick Start

### 1. Install Dependencies

```bash
pip install requests
```

### 2. Configure API Key

Set your NVD API key in the `getCveId.py` file:

```python
headers = {"apiKey": "your-api-key-here"}
```

Apply for a free API key: https://nvd.nist.gov/developers/request-an-api-key

### 3. Run the Tool

```bash
python getCveId.py
```

## Usage Examples

### Basic Usage

The tool searches for CVEs containing the "linux kernel" keyword by default:

```python
from getCveId import get_all_cve_ids

# Collect CVE IDs
cve_ids = get_all_cve_ids(
    keyword="linux kernel",
    output_file="linux_kernel_cve_ids.txt",
    max_results=20000
)

print(f"Found {len(cve_ids)} CVE ID")
```

### Custom Search

```python
# Search for Windows-related CVEs
cve_ids = get_all_cve_ids(
    keyword="microsoft windows",
    output_file="windows_cve_ids.txt",
    max_results=10000
)

# Search for Apache-related CVEs
cve_ids = get_all_cve_ids(
    keyword="apache",
    output_file="apache_cve_ids.txt",
    max_results=5000
)
```

## Output Example

```
Searching for CVE IDs containing keyword 'linux kernel'...
Output file: linux_kernel_cve_ids.txt
Requesting page: startIndex=0, resultsPerPage=2000
Found 2000 CVE IDs. Total collected: 2000/11331
Waiting 0.6 seconds for rate limiting...
Requesting page: startIndex=2000, resultsPerPage=2000
Found 2000 CVE IDs. Total collected: 4000/11331
...
Completed! Saved 11331 CVE IDs to linux_kernel_cve_ids.txt
```

## How It Works

1. **Official NVD API**: Direct calls to `https://services.nvd.nist.gov/rest/json/cves/2.0/`
2. **True Pagination**: Complete pagination traversal using the `startIndex` parameter
3. **Rate Limiting**: Adheres to API rate limits, 0.6-second intervals with API key
4. **Auto Save**: Real-time saving of results to specified files

## Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `keyword` | Search keyword | "linux kernel" |
| `output_file` | Output filename | "cve_ids.txt" |
| `max_results` | Maximum collection count | 20000 |
| `results_per_page` | Requests per page | 2000 (API maximum) |

## API Parameters

The tool uses the following NVD API parameters:

- `keywordSearch`: Keyword search
- `startIndex`: Pagination start index
- `resultsPerPage`: Number of results per page (maximum 2000)

## Error Handling

The tool includes comprehensive error handling:

- HTTP request error auto-retry
- Save collected data when network exceptions occur
- Display detailed information when API limits are triggered
- File write error handling

## File Structure

```
nvd/
├── getCveId.py           # Main program file
├── README.md            # Documentation
└── *.txt               # Output CVE ID files
```

## API Limitations

- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds
- **Single Request Maximum**: 2000 records
- **Recommended Interval**: 0.6 seconds (with API key)

---

> 💡 **Tip**: Strongly recommend using an API key for optimal performance! 