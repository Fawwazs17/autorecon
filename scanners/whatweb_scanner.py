
import subprocess
import os

def whatweb_scan(domain):
    # print(f"Running whatweb scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/whatweb_{domain}.txt"
    command = [
        "whatweb",
        f"https://{domain}",
        "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "--header", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "--header", "Accept-Language: en-US,en;q=0.5"
    ]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(command, check=True, stdout=f, stderr=subprocess.DEVNULL)
        # print(f"WhatWeb scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        # print(f"WhatWeb scan failed for {domain}: {e}")
        pass
    except FileNotFoundError:
        # print("WhatWeb is not installed or not in PATH. Please ensure 'whatweb' is in your system's PATH.")
        pass

