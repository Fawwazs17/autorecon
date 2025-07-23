# Security Scan Workflow - Text Representation

## Input Stage
- **Domain Name Input** → Multithreaded Scan Manager

## Scanning Tools Stage
**Multithreaded Scan Manager** coordinates multiple scanning tools:
- whatweb (web technology detection)
- dnsenum (DNS enumeration)
- nmap (network mapping)
- sublist3r (subdomain enumeration)
- theharvester (email/host harvesting)
- httpx (HTTP probing)
- DNSDumpster (DNS reconnaissance)

## Data Collection Stage
All scanning tools feed into:
- **Scan Result Collector** → **Data Aggregator & Sorter**

## Data Categorization Stage
**Categorized Data Buckets** organize results into:

1. **Network & DNS Info**
   - Sources: nmap, dnsenum, DNSDumpster

2. **Subdomains & Hosts**
   - Sources: sublist3r, theharvester, DNSDumpster

3. **Emails**
   - Source: theharvester

4. **Web Technologies**
   - Source: whatweb

5. **HTTP Headers**
   - Source: httpx

## Report Generation Stage
**PDF Report Generator Engine** processes all categorized data

## Final Output Stage
**Final Report Output (Dashboard Style)** includes:
- Donut chart by Severity
- Color-Coded Summary Table
- Severity Overview
- Categorized Findings & Visuals

## Workflow Summary
```
Domain Input 
    ↓
Multithreaded Scan Manager 
    ↓ (parallel execution)
7 Scanning Tools 
    ↓
Scan Result Collector 
    ↓
Data Aggregator & Sorter 
    ↓
Categorized Data Buckets (5 categories)
    ↓
PDF Report Generator Engine 
    ↓
Final Dashboard-Style Report
```

## Tool Categories
- **Reconnaissance Tools**: whatweb, dnsenum, nmap, sublist3r, theharvester, httpx, DNSDumpster
- **Data Processing**: Scan Result Collector, Data Aggregator & Sorter
- **Output Generation**: PDF Report Generator Engine, Final Report Output