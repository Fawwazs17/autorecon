
import argparse
import threading
import os
from scanners.nmap_scanner import nmap_scan
from scanners.whatweb_scanner import whatweb_scan
from scanners.dnsenum_scanner import dnsenum_scan
from scanners.theharvester_scanner import theharvester_scan
from scanners.httpx_scanner import httpx_scan

def main():
    parser = argparse.ArgumentParser(description='Automated security scanner.')
    parser.add_argument('-d', '--domain', required=True, help='The domain name to scan.')
    args = parser.parse_args()

    domain = args.domain
    print(f"Scanning domain: {domain}")

    scans = [
        nmap_scan,
        whatweb_scan,
        dnsenum_scan,
        theharvester_scan,
        httpx_scan
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
        import json
        json.dump(results, f, indent=4)
    print(f"Aggregated results saved to {json_output_path}")

    from report_generator import generate_report
    generate_report(domain, results)

import os

def aggregate_results(domain):
    from parsers.nmap_parser import parse_nmap
    from parsers.whatweb_parser import parse_whatweb
    from parsers.dnsenum_parser import parse_dnsenum
    from parsers.theharvester_parser import parse_theharvester
    from parsers.httpx_parser import parse_httpx

    results = {}
    if os.path.exists(f"results/nmap_{domain}.xml"):
        results['nmap'] = parse_nmap(f"results/nmap_{domain}.xml")
    if os.path.exists(f"results/whatweb_{domain}.txt"):
        results['whatweb'] = parse_whatweb(f"results/whatweb_{domain}.txt")
    if os.path.exists(f"results/dnsenum_{domain}.xml"):
        results['dnsenum'] = parse_dnsenum(f"results/dnsenum_{domain}.xml")
    if os.path.exists(f"results/theharvester_{domain}.xml"):
        results['theharvester'] = parse_theharvester(f"results/theharvester_{domain}.xml")
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

    finally:
        if log_file_handle:
            print(f"\n--- Scan finished at {datetime.datetime.now()} ---")
            log_file_handle.close()
            sys.stdout = original_stdout
            sys.stderr = original_stderr

if __name__ == '__main__':
    main()
