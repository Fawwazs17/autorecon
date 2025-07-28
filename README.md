# Autorecon

This project is a Python-based security scanner that automates the process of running various reconnaissance tools against a target domain. It collects the results, parses them, and generates a comprehensive security report in PDF format, along with a structured data dictionary in JSON format.

## How It Works

The `scanner.py` script orchestrates the entire process:

1.  **Scanner Execution:** It imports and runs various individual scanner modules (e.g., `dnsdumpster_scanner.py`, `nmap_scanner.py`, `httpx_scanner.py`) against the specified target domain. Each scanner saves its raw output to a file.
2.  **Data Parsing:** After each scan, the corresponding parser module (e.g., `dnsdumpster_parser.py`, `nmap_parser.py`) reads the raw output and extracts relevant information, transforming it into a structured JSON dictionary.
3.  **Data Aggregation:** All structured data from different scanners is aggregated into a single, comprehensive dictionary.
4.  **Data Dictionary Generation:** The aggregated data is then processed by `data_dictionary_generator.py` to create a categorized JSON data dictionary, providing a clear and organized overview of all collected information.
5.  **Report Generation:** Finally, `report_generator.py` takes the categorized data dictionary and generates a professional, human-readable PDF report, summarizing key findings and providing detailed analysis.

## Features

*   **Automated Reconnaissance:** Automates the execution of multiple open-source intelligence (OSINT) and network scanning tools.
*   **Structured Data Output:** Generates a well-organized JSON data dictionary for programmatic access and further analysis.
*   **Comprehensive PDF Reports:** Produces detailed and professional PDF reports summarizing scan results, including network information, subdomains, emails, web technologies, and live hosts.

### Integrated Scanners

*   **DNSDumpster:** Gathers DNS information (A, MX, NS, CNAME records).
*   **DNSEnum:** Enumerates DNS records and subdomains.
*   **HTTPX:** Probes for running HTTP/HTTPS services and extracts HTTP headers.
*   **Nmap:** Performs network scanning to identify open ports and services.
*   **Sublist3r:** Enumerates subdomains using various search engines.
*   **TheHarvester:** Gathers emails, subdomains, hosts, and other OSINT data.
*   **WhatWeb:** Identifies web technologies, content management systems (CMS), and other web-related information.

## Requirements

*   Python 3.x
*   The external tools used by the scanners (e.g., `curl` for DNSDumpster, `nmap`, `httpx`, `sublist3r`, `theharvester`, `whatweb`, `dnsenum`) must be installed on your system and accessible via your system's PATH.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Fawwazs17/autorecon 
    cd autorecon
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the scanner, simply execute the `scanner.py` script:

```bash
python scanner.py
```

Upon execution, the program will interactively prompt you to enter the author's name and the target domain to scan.

### Example

```bash
┌──(venv)─(abuluqmanng㉿kali)-[~/Desktop/autorecon]
└─$ python scanner.py


    ▄▄▄       █    ██ ▄▄▄█████▓ ▒█████   ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █ 
  ▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ 
  ▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒
  ░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒
   ▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░
   ▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
    ▒   ▒▒ ░░░▒░ ░ ░     ░      ░ ▒ ▒░   ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░
    ░   ▒    ░░░ ░ ░   ░      ░ ░ ░ ▒    ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░ 
        ░  ░   ░                  ░ ░     ░        ░  ░░ ░          ░ ░           ░ 
                                                       ░                 
  ═══════════════════════════════════════════════════════════════════════════════════                  
  ║                      🔍 AUTOMATED RECONNAISSANCE SUITE 🔍                       ║
  ═══════════════════════════════════════════════════════════════════════════════════
  ║                                                                                 ║
  ║  ┌─────────────────────────────────────────────────────────────────────────┐    ║
  ║  │  🚀 7-IN-1 CONCURRENT SCANNING ENGINE                                   │    ║
  ║  │  ⚡ AUTOMATED ENUMERATION & DISCOVERY                                    │    ║
  ║  │  📊 COMPREHENSIVE PDF REPORTING                                         │    ║
  ║  └─────────────────────────────────────────────────────────────────────────┘    ║
  ║                                                                                 ║
  ║   🔧 INTEGRATED TOOLS: NMAP • WHATWEB • DNSENUM • THEHARVESTER                  ║
  ║                            HTTPX • SUBLIST3R • DNSDUMPSTER                      ║
  ║                                                                                 ║
  ║   💻 Author :                                Version: 1.0.0                     ║
  ║   📧 Contact:                                Build  : 2025.07                   ║
  ║                                                                                 ║
  ═══════════════════════════════════════════════════════════════════════════════════

           [!] LEGAL: For authorized penetration testing only
           [!] OUTPUT: Results saved to ./reports/report_<target>.pdf

═══════════════════════════════════════════════════════════════════════════════════════
                                               
                              
Enter the author of the scan:
Enter the domain name to scan: 

```
(Then the user would be prompted for input)

All raw scanner outputs will be logged to a file in the `logs/` directory, and the generated data dictionary (JSON) and reconnaissance report (PDF) will be saved in the `reports/` directory.

At the beginning of the script execution, you will be prompted to enter your name, which will be included as the author in the PDF report.

## Project Structure

```
.
├── README.md
├── requirements.txt
├── scanner.py
├── data_dictionary_generator.py
├── report_generator.py
├── parsers/
│   ├── dnsdumpster_parser.py
│   ├── dnsenum_parser.py
│   ├── httpx_parser.py
│   ├── nmap_parser.py
│   ├── sublist3r_parser.py
│   ├── theharvester_parser.py
│   └── whatweb_parser.py
├── scanners/
│   ├── dnsdumpster_scanner.py
│   ├── dnsenum_scanner.py
│   ├── httpx_scanner.py
│   ├── nmap_scanner.py
│   ├── sublist3r_scanner.py
│   ├── theharvester_scanner.py
│   └── whatweb_scanner.py
├── reports/                 # Generated JSON data dictionaries and PDF reports
├──results/                  # Raw scanner outputs
└── logs/                    # Raw scanner logs
```
