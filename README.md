# Python Security Scanner

This is an automated security scanner designed to gather information about a target domain using various open-source tools and generate a comprehensive PDF report.

## Features

*   **Multithreaded Scanning**: Runs multiple reconnaissance tools concurrently for faster results.
*   **Data Aggregation**: Collects and categorizes output from different tools.
*   **PDF Report Generation**: Creates a dashboard-style PDF report summarizing the findings.

## Prerequisites

Before running the scanner, you need to have the following installed on your system:

*   **Python 3.x**
*   **pip** (Python package installer)

You also need to install the following external security tools and ensure they are in your system's PATH:

*   **Nmap**: Network scanner (e.g., `sudo apt-get install nmap` on Debian/Ubuntu)
*   **WhatWeb**: Web technology detector (e.g., `sudo apt-get install whatweb` on Debian/Ubuntu)
*   **Dnsenum**: DNS enumeration tool (e.g., `sudo apt-get install dnsenum` on Debian/Ubuntu)
*   **theHarvester**: Email, subdomain, and host OSINT tool (e.g., `sudo apt-get install theharvester` on Debian/Ubuntu)
*   **httpx**: HTTP toolkit (Install via `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` after installing Go)

## Setup

1.  **Clone the repository (if you haven't already):**

    ```bash
    git clone <repository_url>
    cd python-security-scanner
    ```

2.  **Create and activate a Python virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Python dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the scanner, use the `scanner.py` script with the `-d` or `--domain` flag followed by the target domain name:

```bash
source venv/bin/activate
python3 scanner.py -d example.com
```

Replace `example.com` with the domain you want to scan.

## Output

The scanner will create the following directories and files:

*   `results/`: Contains the raw output files from each scanning tool.
*   `reports/`: Contains the generated output files:
    *   `results_example.com.json`: Aggregated JSON results from all tools
    *   `data_dictionary_example.com.md`: Auto-generated data dictionary describing the scan results structure
    *   `report_example.com.pdf`: Comprehensive PDF report

## Troubleshooting

*   **`ModuleNotFoundError: No module named 'reportlab'`**: Ensure you have activated your virtual environment (`source venv/bin/activate`) and installed the Python dependencies (`pip install -r requirements.txt`).
*   **`[Tool Name] is not installed or not in PATH.`**: Make sure the external security tools (Nmap, WhatWeb, Dnsenum, theHarvester, httpx) are installed on your system and their executables are accessible via your system's PATH.
*   **Empty PDF Report**: This usually means the external security tools were not found or did not produce any output. Verify their installation and check the `results/` directory for any generated files.
