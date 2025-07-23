
import subprocess
import os

def httpx_scan(domain):
    print(f"Running httpx scan on {domain}...")
    command = ["httpx", domain, "-o", f"results/httpx_headers_{domain}.txt"]
    try:
        process = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"Httpx scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"Httpx scan failed for {domain}: {e.stderr}")
    except FileNotFoundError:
        print("httpx is not installed or not in PATH. Please ensure 'httpx' is in your system's PATH.")
