import threading
import os
import sys
import datetime
import time
from scanners.nmap_scanner import nmap_scan
from scanners.whatweb_scanner import whatweb_scan
from scanners.dnsenum_scanner import dnsenum_scan
from scanners.theharvester_scanner import theharvester_scan
from scanners.httpx_scanner import httpx_scan
from scanners.sublist3r_scanner import sublist3r_scan
from scanners.dnsdumpster_scanner import dnsdumpster_scan

def print_ascii_art():
    try:
        with open('autorecon_ascii_art.txt', 'r') as f:
            print(f.read())
    except FileNotFoundError:
        print("ASCII art file not found.")

def get_user_input():
    author = input("Enter the author of the scan: ")
    while True:
        domain = input("Enter the domain name to scan: ")
        if domain and '.' in domain:
            return domain, author
        else:
            print("Invalid domain name. Please enter a valid domain.")

def run_scan(scan_func, domain, results_dict, tool_name):
    results_dict[tool_name] = scan_func(domain)

def main():
    print_ascii_art()
    domain, author = get_user_input()
    log_file = f"scan_log_{domain}.txt"

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    log_file_handle = None

    try:
        log_file_handle = open(log_file, 'a')
        # Redirect stdout and stderr to the log file
        sys.stdout = log_file_handle
        sys.stderr = log_file_handle

        print(f"\n--- Scan started at {datetime.datetime.now()} by {author} ---", file=original_stdout)

        start_time = time.time()

        scans = {
            "Nmap": nmap_scan,
            "WhatWeb": whatweb_scan,
            "DNSEnum": dnsenum_scan,
            "theHarvester": theharvester_scan,
            "HTTPX": httpx_scan,
            "Sublist3r": sublist3r_scan,
            "DNSDumpster": dnsdumpster_scan
        }

        threads = []
        results = {}
        print("\n--- Starting Scans ---", file=original_stdout)
        for name, scan_func in scans.items():
            print(f"[+] Starting {name} scan...", file=original_stdout)
            thread = threading.Thread(target=run_scan, args=(scan_func, domain, results, name.lower()))
            threads.append((name, thread))
            thread.start()

        for name, thread in threads:
            thread.join()
            print(f"[+] {name} scan finished.", file=original_stdout)

        end_time = time.time()
        duration = end_time - start_time
        scan_duration = time.strftime("%H:%M:%S", time.gmtime(duration))
        print(f"\nAll scans completed in {duration:.2f} seconds.", file=original_stdout)

        # Restore stdout and stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        log_file_handle.close()

        # Now print to the actual terminal
        print("\n--- Aggregating Results ---")
        aggregated_results = aggregate_results(domain)

        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)
        json_output_path = os.path.join(reports_dir, f"results_{domain}.json")
        with open(json_output_path, 'w') as f:
            import json
            json.dump(aggregated_results, f, indent=4)
        print(f"Aggregated results saved to {json_output_path}")

        print("Generating data dictionary...")
        from data_dictionary_generator import create_data_dictionary_file
        data_dict_path = create_data_dictionary_file(domain, aggregated_results, reports_dir)
        print(f"Data dictionary generated: {data_dict_path}")

        print("Generating PDF report...")
        from report_generator import generate_report
        generate_report(domain, aggregated_results, author, scan_duration)
        print(f"PDF report generated: reports/report_{domain}.pdf")

    except Exception as e:
        # Ensure stdout and stderr are restored on error
        if log_file_handle:
            log_file_handle.close()
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        print(f"An error occurred: {e}")

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
    if os.path.exists(f"results/theharvester_{domain}.json"):
        results['theharvester'] = parse_theharvester(f"results/theharvester_{domain}.json")
    if os.path.exists(f"results/httpx_headers_{domain}.txt"):
        results['httpx'] = parse_httpx(f"results/httpx_headers_{domain}.txt")
    if os.path.exists(f"results/sublist3r_{domain}.txt"):
        results['sublist3r'] = parse_sublist3r(f"results/sublist3r_{domain}.txt")
    if os.path.exists(f"results/dnsdumpster_{domain}.json"):
        results['dnsdumpster'] = parse_dnsdumpster(f"results/dnsdumpster_{domain}.json")

    return results

if __name__ == '__main__':
    main()
