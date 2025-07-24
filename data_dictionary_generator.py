import json
import os
from datetime import datetime
from typing import Dict, Any

def categorize_scan_results(aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
    """Reorganize aggregated scan results into categorized structure."""
    
    categorized_data = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_sources": len([k for k, v in aggregated_data.items() if v]),
            "available_sources": [k for k, v in aggregated_data.items() if v]
        },
        "network_dns_info": {},
        "subdomains_hosts": {},
        "emails": {},
        "web_technologies": {},
        "http_headers": {}
    }

    # 1. Network & DNS Info - Sources: nmap, dnsenum, dnsdumpster
    if 'nmap' in aggregated_data and aggregated_data['nmap']:
        categorized_data["network_dns_info"]["nmap"] = aggregated_data['nmap']
    
    if 'dnsenum' in aggregated_data and aggregated_data['dnsenum']:
        categorized_data["network_dns_info"]["dnsenum"] = aggregated_data['dnsenum']
    
    # For dnsdumpster, separate network info from subdomain info
    if 'dnsdumpster' in aggregated_data and aggregated_data['dnsdumpster']:
        dnsdumpster_data = aggregated_data['dnsdumpster']
        
        # Network/DNS info from dnsdumpster (MX, NS records, total counts)
        network_info = {}
        if 'mx' in dnsdumpster_data:
            network_info['mx_records'] = dnsdumpster_data['mx']
        if 'ns' in dnsdumpster_data:
            network_info['ns_records'] = dnsdumpster_data['ns']
        if 'total_a_recs' in dnsdumpster_data:
            network_info['total_a_records'] = dnsdumpster_data['total_a_recs']
        
        if network_info:
            categorized_data["network_dns_info"]["dnsdumpster"] = network_info

    # 2. Subdomains & Hosts - Sources: sublist3r, theharvester, dnsdumpster
    if 'sublist3r' in aggregated_data and aggregated_data['sublist3r']:
        categorized_data["subdomains_hosts"]["sublist3r"] = aggregated_data['sublist3r']
    
    if 'theharvester' in aggregated_data and aggregated_data['theharvester']:
        theharvester_data = aggregated_data['theharvester']
        
        # Extract hosts/subdomains from theharvester
        hosts_data = {}
        if 'hosts' in theharvester_data and theharvester_data['hosts']:
            hosts_data['discovered_hosts'] = theharvester_data['hosts']
        if 'ips' in theharvester_data and theharvester_data['ips']:
            hosts_data['discovered_ips'] = theharvester_data['ips']
        
        if hosts_data:
            categorized_data["subdomains_hosts"]["theharvester"] = hosts_data
    
    # Subdomain/host info from dnsdumpster (A records, CNAME records)
    if 'dnsdumpster' in aggregated_data and aggregated_data['dnsdumpster']:
        dnsdumpster_data = aggregated_data['dnsdumpster']
        
        subdomain_info = {}
        if 'a' in dnsdumpster_data and dnsdumpster_data['a']:
            subdomain_info['a_records'] = dnsdumpster_data['a']
        if 'cname' in dnsdumpster_data and dnsdumpster_data['cname']:
            subdomain_info['cname_records'] = dnsdumpster_data['cname']
        
        if subdomain_info:
            categorized_data["subdomains_hosts"]["dnsdumpster"] = subdomain_info

    # 3. Emails - Source: theharvester and others
    if 'theharvester' in aggregated_data and aggregated_data['theharvester']:
        theharvester_data = aggregated_data['theharvester']
        
        if 'emails' in theharvester_data:
            categorized_data["emails"]["theharvester"] = {
                "discovered_emails": theharvester_data['emails']
            }
    
    # Check if whatweb has email information
    if 'whatweb' in aggregated_data and aggregated_data['whatweb']:
        whatweb_data = aggregated_data['whatweb']
        if 'Email' in whatweb_data:
            if 'whatweb' not in categorized_data["emails"]:
                categorized_data["emails"]["whatweb"] = {}
            categorized_data["emails"]["whatweb"]["contact_email"] = whatweb_data['Email']

    # 4. Web Technologies - Source: whatweb
    if 'whatweb' in aggregated_data and aggregated_data['whatweb']:
        # Create a clean copy without email (since that goes to emails category)
        whatweb_clean = {k: v for k, v in aggregated_data['whatweb'].items() if k != 'Email'}
        if whatweb_clean:
            categorized_data["web_technologies"]["whatweb"] = whatweb_clean

    # 5. HTTP Headers - Source: httpx
    if 'httpx' in aggregated_data and aggregated_data['httpx']:
        categorized_data["http_headers"]["httpx"] = aggregated_data['httpx']

    # Remove empty categories
    categories_to_remove = []
    for category, data in categorized_data.items():
        if category != "scan_metadata" and not data:
            categories_to_remove.append(category)
    
    for category in categories_to_remove:
        del categorized_data[category]

    return categorized_data

def create_data_dictionary_file(domain: str, aggregated_data: Dict[str, Any], output_dir: str = "reports") -> str:
    """Create and save the categorized data dictionary JSON file."""
    
    # Generate the categorized data structure
    categorized_data = categorize_scan_results(aggregated_data)
    
    # Add domain info to metadata
    categorized_data["scan_metadata"]["domain"] = domain
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Save to file
    filename = f"data_dictionary_{domain}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(categorized_data, f, indent=2)
    
    print(f"Data dictionary JSON generated: {filepath}")
    return filepath

def generate_data_dictionary_from_json(json_file_path: str) -> str:
    """Generate categorized data dictionary from an existing aggregated JSON file."""
    
    # Extract domain from filename
    filename = os.path.basename(json_file_path)
    if filename.startswith("results_") and filename.endswith(".json"):
        domain = filename[8:-5]  # Remove "results_" prefix and ".json" suffix
    else:
        domain = "unknown"
    
    # Load the JSON data
    with open(json_file_path, 'r', encoding='utf-8') as f:
        aggregated_data = json.load(f)
    
    # Generate and save the categorized data dictionary
    output_dir = os.path.dirname(json_file_path)
    return create_data_dictionary_file(domain, aggregated_data, output_dir)

if __name__ == "__main__":
    # For testing - can be run standalone on a JSON file
    import sys
    if len(sys.argv) > 1:
        json_file = sys.argv[1]
        generate_data_dictionary_from_json(json_file)
    else:
        print("Usage: python3 data_dictionary_generator.py <path_to_results_json>")