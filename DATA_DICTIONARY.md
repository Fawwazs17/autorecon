# Data Dictionary - Python Security Scanner

## Overview
This document provides a comprehensive mapping of all data structures used in the Python Security Scanner project, including input formats, parser outputs, aggregated results, and report categorization.

## Table of Contents
1. [Input Data Structures](#input-data-structures)
2. [Parser Output Structures](#parser-output-structures)
3. [Aggregated Results Structure](#aggregated-results-structure)
4. [Report Categorization Schema](#report-categorization-schema)
5. [Data Flow Diagram](#data-flow-diagram)

---

## Input Data Structures

### Command Line Arguments
| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| domain | string | Yes | Target domain to scan | `example.com` |
| log_file | string | No | Path to log file for output | `scan_output.log` |

### Scanner Configuration
| Field | Type | Description |
|-------|------|-------------|
| scans | list | List of scanner functions to execute |
| threads | list | List of threading objects for concurrent execution |

---

## Parser Output Structures

### 1. Nmap Parser (`parse_nmap`)
**Source File**: `results/nmap_{domain}.xml`
**Output Structure**:
```json
[
  {
    "ip": "string",           // IP address of the host
    "ports": [
      {
        "portid": "string",   // Port number
        "protocol": "string", // Protocol (tcp/udp)
        "state": "string",    // Port state (open/closed/filtered)
        "service": "string"   // Service name running on port
      }
    ]
  }
]
```

### 2. WhatWeb Parser (`parse_whatweb`)
**Source File**: `results/whatweb_{domain}.txt`
**Output Structure**:
```json
{
  "url": "string",           // Target URL scanned
  "status": "string",        // HTTP status code and message
  "Country": "string",       // Country information
  "IP": "string",           // IP address
  "Title": "string",        // Page title
  "HTTPServer": "string",   // Web server information
  "X-Powered-By": "string", // Technology stack info
  "HTML5": "boolean",       // HTML5 detection
  // Additional technology detection fields...
}
```

### 3. DNSEnum Parser (`parse_dnsenum`)
**Source File**: `results/dnsenum_{domain}.xml`
**Output Structure**: 
```json
{
  // Structure varies based on XML content
  // Typically contains DNS record information
}
```

### 4. theHarvester Parser (`parse_theharvester`)
**Source File**: `results/theharvester_{domain}.json`
**Output Structure**:
```json
{
  "emails": ["string"],     // Array of discovered email addresses
  "hosts": ["string"],      // Array of discovered hostnames
  "ips": ["string"],        // Array of discovered IP addresses
  // Additional fields based on theHarvester output
}
```

### 5. Httpx Parser (`parse_httpx`)
**Source File**: `results/httpx_headers_{domain}.txt`
**Output Structure**:
```json
{
  // Simple structure - implementation varies
  // Typically contains HTTP header information
}
```

### 6. Sublist3r Parser (`parse_sublist3r`)
**Source File**: `results/sublist3r_{domain}.txt`
**Output Structure**:
```json
["string"]  // Array of discovered subdomains
```

### 7. DNSDumpster Parser (`parse_dnsdumpster`)
**Source File**: `results/dnsdumpster_{domain}.json`
**Output Structure**:
```json
{
  "a": ["string"],          // A record results
  "cname": ["string"],      // CNAME record results
  // Additional DNS record types...
}
```

---

## Aggregated Results Structure

The `aggregate_results()` function combines all parser outputs into a unified structure:

```json
{
  "nmap": [/* nmap parser output */],
  "whatweb": {/* whatweb parser output */},
  "dnsenum": {/* dnsenum parser output */},
  "theharvester": {/* theharvester parser output */},
  "httpx": {/* httpx parser output */},
  "sublist3r": [/* sublist3r parser output */],
  "dnsdumpster": {/* dnsdumpster parser output */}
}
```

**File Output**: `reports/results_{domain}.json`

---

## Report Categorization Schema

The `categorize_results()` function in `report_generator.py` reorganizes the aggregated data into logical categories for reporting:

### 1. Network & DNS Information
```json
{
  "network_dns_info": {
    "nmap": [/* nmap results */],
    "dnsenum": {/* dnsenum results */},
    "dnsdumpster": {/* dnsdumpster results */}
  }
}
```

### 2. Subdomains & Hosts
```json
{
  "subdomains_hosts": {
    "sublist3r": [/* subdomain list */],
    "theharvester_hosts": [/* host list from theharvester */],
    "dnsdumpster": {
      "a": [/* A records */],
      "cname": [/* CNAME records */]
    }
  }
}
```

### 3. Email Addresses
```json
{
  "emails": {
    "theharvester_emails": [/* email list */]
  }
}
```

### 4. Web Technologies
```json
{
  "web_technologies": {
    "whatweb": {/* technology detection results */}
  }
}
```

### 5. HTTP Headers
```json
{
  "http_headers": {
    "httpx": {/* HTTP header analysis */}
  }
}
```

---

## Data Flow Diagram

```
Input (Domain) 
    ↓
[Concurrent Scanners]
    ├── nmap_scan → results/nmap_{domain}.xml
    ├── whatweb_scan → results/whatweb_{domain}.txt
    ├── dnsenum_scan → results/dnsenum_{domain}.xml
    ├── theharvester_scan → results/theharvester_{domain}.json
    ├── httpx_scan → results/httpx_headers_{domain}.txt
    ├── sublist3r_scan → results/sublist3r_{domain}.txt
    └── dnsdumpster_scan → results/dnsdumpster_{domain}.json
    ↓
[Parser Functions]
    ├── parse_nmap()
    ├── parse_whatweb()
    ├── parse_dnsenum()
    ├── parse_theharvester()
    ├── parse_httpx()
    ├── parse_sublist3r()
    └── parse_dnsdumpster()
    ↓
[Aggregate Results] → reports/results_{domain}.json
    ↓
[Categorize Results] → categorized_data structure
    ↓
[Generate PDF Report] → reports/report_{domain}.pdf
```

---

## File Naming Conventions

### Input Files (Scanner Outputs)
- Nmap: `results/nmap_{domain}.xml`
- WhatWeb: `results/whatweb_{domain}.txt`
- DNSEnum: `results/dnsenum_{domain}.xml`
- theHarvester: `results/theharvester_{domain}.json`
- Httpx: `results/httpx_headers_{domain}.txt`
- Sublist3r: `results/sublist3r_{domain}.txt`
- DNSDumpster: `results/dnsdumpster_{domain}.json`

### Output Files
- Aggregated JSON: `reports/results_{domain}.json`
- PDF Report: `reports/report_{domain}.pdf`

---

## Error Handling

### Parser Error Handling
- Missing files return empty structures (`{}` or `[]`)
- Parse errors are logged and return empty structures
- File not found errors are caught and logged

### Data Validation
- Each parser includes try/catch blocks for robust error handling
- Missing data fields are handled gracefully with default values
- Invalid data formats are logged but don't stop execution

---

## Notes

1. **Threading**: All scanners run concurrently using Python threading
2. **File Dependencies**: Parsers only run if their corresponding result files exist
3. **JSON Serialization**: All data structures are JSON-serializable for storage and transmission
4. **Extensibility**: New scanners can be added by:
   - Creating a scanner function in `scanners/`
   - Creating a parser function in `parsers/`
   - Adding both to the appropriate lists in `scanner.py`
   - Updating the categorization logic in `report_generator.py`