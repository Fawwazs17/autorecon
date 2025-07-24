
import subprocess
import os

def theharvester_scan(domain):
    print(f"Running theHarvester scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_json_file = f"results/theharvester_{domain}.json"
    command = [
        "/usr/bin/theHarvester",
        "-d", domain,
        "-b", "crtsh,bing,duckduckgo,otx",
        "-f", output_json_file # Explicitly set the JSON output file
    ]
    try:
        subprocess.run(command, check=True)
        print(f"theHarvester scan for {domain} completed. Results saved to {output_json_file} and .xml")
    except subprocess.CalledProcessError as e:
        print(f"theHarvester scan failed for {domain}: {e.stderr}")
    except FileNotFoundError:
        print("theHarvester is not installed or not in PATH. Please ensure 'theHarvester' is in your system's PATH.")
