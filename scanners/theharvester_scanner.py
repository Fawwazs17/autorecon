
import subprocess
import os

def theharvester_scan(domain):
    print(f"Running theHarvester scan on {domain}...")
    # Using the alternative command from cmd.txt
    command = [
        "theHarvester",
        "-d", domain,
        "-b", "crtsh,bing,duckduckgo,otx",
        "-f", f"results/theharvester_{domain}"
    ]
    try:
        subprocess.run(command, check=True)
        print(f"theHarvester scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"theHarvester scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("theHarvester is not installed or not in PATH. Please ensure 'theHarvester' is in your system's PATH.")
