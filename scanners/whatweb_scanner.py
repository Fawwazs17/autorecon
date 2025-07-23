
import subprocess
import os

def whatweb_scan(domain):
    print(f"Running whatweb scan on {domain}...")
    # Try the more robust command first
    command = [
        "whatweb",
        f"https://{domain}",
        "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "--header", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "--header", "Accept-Language: en-US,en;q=0.5",
        f"--log-brief=results/whatweb_{domain}.txt"
    ]
    try:
        subprocess.run(command, check=True)
        print(f"WhatWeb scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"WhatWeb scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("WhatWeb is not installed or not in PATH. Please ensure 'whatweb' is in your system's PATH.")

