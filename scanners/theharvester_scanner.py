
import subprocess
import os

def theharvester_scan(domain):
    print(f"Running theHarvester scan on {domain}...")
    output_file = f"results/theharvester_{domain}.json"
    command = [
        "/usr/bin/theHarvester",
        "-d", domain,
        "-b", "crtsh,bing,duckduckgo,otx",
        "-f", f"results/theharvester_{domain}" # Revert to -f for XML/HTML output
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"theHarvester scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"theHarvester scan failed for {domain}: {e.stderr}")
    except FileNotFoundError:
        print("theHarvester is not installed or not in PATH. Please ensure 'theHarvester' is in your system's PATH.")
