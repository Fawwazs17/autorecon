import argparse
import threading
import os
import sys
import datetime
import json
import re
from scanners.nmap_scanner import nmap_scan
from scanners.whatweb_scanner import whatweb_scan
from scanners.dnsenum_scanner import dnsenum_scan
from scanners.theharvester_scanner import theharvester_scan
from scanners.httpx_scanner import httpx_scan
from scanners.sublist3r_scanner import sublist3r_scan
from scanners.dnsdumpster_scanner import dnsdumpster_scan

def extract_emails_from_whatweb(whatweb_data):
    """Extract emails from whatweb output"""
    emails = []
    if isinstance(whatweb_data, str):
        email_pattern = r'Email\[([^\]]+)\]'
        matches = re.findall(email_pattern, whatweb_data)
        emails.extend(matches)
    return list(set(emails))

def extract_technologies_from_whatweb(whatweb_data):
    """Extract web technologies from whatweb output"""
    technologies = []
    if isinstance(whatweb_data, str):
        tech_patterns = {
            'server': r'HTTPServer\[([^\]]+)\]',
            'php_version': r'PHP\[([^\]]+)\]',
            'framework': r'(?:HTML5|Script)',
            'security_headers': r'X-[A-Z][^,\]]*',
            'title': r'Title\[([^\]]+)\]'
        }
        
        for tech_type, pattern in tech_patterns.items():
            matches = re.findall(pattern, whatweb_data)
            if matches:
                technologies.extend(matches)
            elif tech_type == 'framework' and re.search(pattern, whatweb_data):
                technologies.append(pattern.replace('(?:', '').replace(')', ''))
    
    return list(set(technologies))

def extract_http_headers_from_whatweb(whatweb_data):
    """Extract HTTP headers from whatweb output"""
    headers = []
    if isinstance(whatweb_data, str):
        header_patterns = [
            r'Strict-Transport-Security\[([^\]]+)\]',
            r'X-Frame-Options\[([^\]]+)\]',
            r'X-XSS-Protection\[([^\]]+)\]',
            r'UncommonHeaders\[([^\]]+)\]',
            r'X-Powered-By\[([^\]]+)\]'
        ]
        
        for pattern in header_patterns:
            matches = re.findall(pattern, whatweb_data)
            headers.extend(matches)
    
    return list(set(headers))

def create_data_dictionary_from_results(domain, results):
    """Create a data dictionary from aggregated results"""
    
    # Initialize data dictionary structure
    data_dictionary = {
        "metadata": {
            "description": "Data Dictionary for Security Reconnaissance Tools",
            "domain": domain,
            "created_at": datetime.datetime.now().isoformat(),
            "categories": 5
        },
        "categories": {
            "1_network_dns_info": {
                "title": "Network & DNS Info",
                "sources": ["nmap", "dnsenum", "dnsdumpster"],
                "description": "Network services, open ports, DNS resolution, and infrastructure information",
                "data": {
                    "open_ports": [],
                    "services": [],
                    "ip_addresses": [],
                    "dns_records": [],
                    "nameservers": [],
                    "mx_records": [],
                    "txt_records": [],
                    "asn_info": []
                }
            },
            "2_subdomains_hosts": {
                "title": "Subdomains & Hosts", 
                "sources": ["sublist3r", "theharvester", "dnsdumpster"],
                "description": "Discovered subdomains, hostnames, and related domains",
                "data": {
                    "subdomains": [],
                    "hosts": [],
                    "a_records": [],
                    "cname_records": []
                }
            },
            "3_emails": {
                "title": "Emails",
                "sources": ["theharvester", "whatweb"],
                "description": "Email addresses discovered during reconnaissance",
                "data": {
                    "email_addresses": []
                }
            },
            "4_web_technologies": {
                "title": "Web Technologies",
                "sources": ["whatweb"],
                "description": "Web server technologies, frameworks, and software versions",
                "data": {
                    "technologies": [],
                    "server_info": [],
                    "cms_frameworks": [],
                    "programming_languages": []
                }
            },
            "5_http_headers": {
                "title": "HTTP Headers",
                "sources": ["httpx", "whatweb"],
                "description": "HTTP response headers and security configurations",
                "data": {
                    "security_headers": [],
                    "server_headers": [],
                    "custom_headers": []
                }
            }
        }
    }
    
    # Process NMAP data
    if 'nmap' in results and results['nmap']:
        for nmap_entry in results['nmap']:
            if 'ip' in nmap_entry:
                data_dictionary["categories"]["1_network_dns_info"]["data"]["ip_addresses"].append(nmap_entry['ip'])
            
            if 'ports' in nmap_entry:
                for port in nmap_entry['ports']:
                    port_info = f"{port.get('portid', '')}/{port.get('protocol', '')} ({port.get('service', '')})"
                    data_dictionary["categories"]["1_network_dns_info"]["data"]["open_ports"].append(port_info)
                    data_dictionary["categories"]["1_network_dns_info"]["data"]["services"].append(port.get('service', ''))
    
    # Process DNSEnum data
    if 'dnsenum' in results and results['dnsenum']:
        data_dictionary["categories"]["1_network_dns_info"]["data"]["ip_addresses"].extend(results['dnsenum'])
    
    # Process DNSDumpster data
    if 'dnsdumpster' in results:
        dd_data = results['dnsdumpster']
        
        # A records
        if 'a' in dd_data:
            for a_record in dd_data['a']:
                data_dictionary["categories"]["2_subdomains_hosts"]["data"]["a_records"].append(a_record['host'])
                data_dictionary["categories"]["2_subdomains_hosts"]["data"]["subdomains"].append(a_record['host'])
                
                for ip_info in a_record.get('ips', []):
                    data_dictionary["categories"]["1_network_dns_info"]["data"]["ip_addresses"].append(ip_info['ip'])
                    asn_info = f"AS{ip_info.get('asn', '')} - {ip_info.get('asn_name', '')} ({ip_info.get('country', '')})"
                    data_dictionary["categories"]["1_network_dns_info"]["data"]["asn_info"].append(asn_info)
        
        # CNAME records
        if 'cname' in dd_data:
            data_dictionary["categories"]["2_subdomains_hosts"]["data"]["cname_records"].extend(dd_data['cname'])
        
        # MX records
        if 'mx' in dd_data:
            for mx_record in dd_data['mx']:
                data_dictionary["categories"]["1_network_dns_info"]["data"]["mx_records"].append(mx_record['host'])
        
        # NS records
        if 'ns' in dd_data:
            for ns_record in dd_data['ns']:
                data_dictionary["categories"]["1_network_dns_info"]["data"]["nameservers"].append(ns_record['host'])
        
        # TXT records
        if 'txt' in dd_data:
            data_dictionary["categories"]["1_network_dns_info"]["data"]["txt_records"].extend(dd_data['txt'])
    
    # Process TheHarvester data
    if 'theharvester' in results:
        th_data = results['theharvester']
        
        # Emails
        if 'emails' in th_data:
            data_dictionary["categories"]["3_emails"]["data"]["email_addresses"].extend(th_data['emails'])
        
        # Hosts
        if 'hosts' in th_data:
            data_dictionary["categories"]["2_subdomains_hosts"]["data"]["hosts"].extend(th_data['hosts'])
    
    # Process Sublist3r data
    if 'sublist3r' in results:
        data_dictionary["categories"]["2_subdomains_hosts"]["data"]["subdomains"].extend(results['sublist3r'])
    
    # Process WhatWeb data
    if 'whatweb' in results:
        # Extract emails from whatweb
        whatweb_emails = extract_emails_from_whatweb(results['whatweb'])
        data_dictionary["categories"]["3_emails"]["data"]["email_addresses"].extend(whatweb_emails)
        
        # Extract technologies
        technologies = extract_technologies_from_whatweb(results['whatweb'])
        data_dictionary["categories"]["4_web_technologies"]["data"]["technologies"].extend(technologies)
        
        # Extract HTTP headers
        headers = extract_http_headers_from_whatweb(results['whatweb'])
        data_dictionary["categories"]["5_http_headers"]["data"]["security_headers"].extend(headers)
    
    # Process HTTPX data if available
    if 'httpx' in results and results['httpx']:
        # Add any httpx specific headers processing here
        pass
    
    # Remove duplicates and empty values
    for category in data_dictionary["categories"].values():
        for data_type in category["data"]:
            category["data"][data_type] = list(set(filter(None, category["data"][data_type])))
    
    return data_dictionary

def main():
    parser = argparse.ArgumentParser(description='Automated security scanner.')
    parser.add_argument('-d', '--domain', required=True, help='The domain name to scan.')
    parser.add_argument('--log-file', help='Path to a file to log all terminal output.')
    args = parser.parse_args()

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    log_file_handle = None

    try:
        if args.log_file:
            try:
                log_file_handle = open(args.log_file, 'a') # 'a' for append mode
                sys.stdout = log_file_handle
                sys.stderr = log_file_handle
                print(f"\n--- Scan started at {datetime.datetime.now()} ---")
            except Exception as e:
                print(f"Error opening log file {args.log_file}: {e}", file=original_stderr)
                sys.stdout = original_stdout
                sys.stderr = original_stderr

        domain = args.domain
        print(f"Scanning domain: {domain}")

        scans = [
            nmap_scan,
            whatweb_scan,
            dnsenum_scan,
            theharvester_scan,
            httpx_scan,
            sublist3r_scan,
            dnsdumpster_scan
        ]

        threads = []
        for scan_func in scans:
            thread = threading.Thread(target=scan_func, args=(domain,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        print("All scans completed.")

        # Add a call to the data aggregation function here
        results = aggregate_results(domain)

        # Save results to JSON file
        json_output_path = os.path.join("reports", f"results_{domain}.json")
        with open(json_output_path, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Aggregated results saved to {json_output_path}")

        # Create data dictionary from aggregated results
        data_dictionary = create_data_dictionary_from_results(domain, results)
        
        # Save data dictionary
        dict_output_path = os.path.join("reports", f"data_dictionary_{domain}.json")
        with open(dict_output_path, 'w') as f:
            json.dump(data_dictionary, f, indent=4, sort_keys=True)
        print(f"Data dictionary created: {dict_output_path}")
        
        # Print data dictionary summary
        print("\n=== DATA DICTIONARY SUMMARY ===")
        for category_key, category in data_dictionary["categories"].items():
            print(f"\n{category['title']}:")
            print(f"  Sources: {', '.join(category['sources'])}")
            total_items = sum(len(data_list) for data_list in category['data'].values())
            print(f"  Total items: {total_items}")
            for data_type, data_list in category['data'].items():
                if data_list:
                    print(f"    - {data_type}: {len(data_list)} items")

        from report_generator import generate_report
        generate_report(domain, results)

    finally:
        if log_file_handle:
            print(f"\n--- Scan finished at {datetime.datetime.now()} ---")
            log_file_handle.close()
            sys.stdout = original_stdout
            sys.stderr = original_stderr

def aggregate_results(domain):
    from parsers.nmap_parser import parse_nmap
    from parsers.whatweb_parser import parse_whatweb
    from parsers.dnsenum_parser import parse_dnsenum
    from parsers.theharvester_parser import parse_theharvester
    from parsers.httpx_parser import parse_httpx
    from parsers.sublist3r_parser import parse_sublist3r
    from parsers.dnsdumpster_parser import parse_dnsdumpster

    results = {}
    if os.path.exists(f"results/nmap_{domain}.xml"):
        results['nmap'] = parse_nmap(f"results/nmap_{domain}.xml")
    if os.path.exists(f"results/whatweb_{domain}.txt"):
        results['whatweb'] = parse_whatweb(f"results/whatweb_{domain}.txt")
    if os.path.exists(f"results/dnsenum_{domain}.xml"):
        results['dnsenum'] = parse_dnsenum(f"results/dnsenum_{domain}.xml")
    if os.path.exists(f"results/theharvester_{domain}.txt"):
        results['theharvester'] = parse_theharvester(f"results/theharvester_{domain}.txt")
    if os.path.exists(f"results/httpx_headers_{domain}.txt"):
        results['httpx'] = parse_httpx(f"results/httpx_headers_{domain}.txt")
    if os.path.exists(f"results/sublist3r_{domain}.txt"):
        results['sublist3r'] = parse_sublist3r(f"results/sublist3r_{domain}.txt")
    if os.path.exists(f"results/dnsdumpster_{domain}.json"):
        results['dnsdumpster'] = parse_dnsdumpster(f"results/dnsdumpster_{domain}.json")

    print("\n--- Aggregated Results ---")
    import json
    print(json.dumps(results, indent=4))

    return results

if __name__ == '__main__':
    main()