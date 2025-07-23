
import subprocess
import os

def httpx_scan(domain):
    print(f"Running httpx scan on {domain}...")
    # It's better to have a list of subdomains to check, but for now, we'll just check the main domain.
    with open(f"results/httpx_{domain}.txt", "w") as outfile:
        subprocess.run(["echo", domain], stdout=outfile)

    command = ["httpx", "-list", f"results/httpx_{domain}.txt", "-H", "-o", f"results/httpx_headers_{domain}.txt"]
    try:
        subprocess.run(command, check=True)
        print(f"Httpx scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"Httpx scan failed for {domain}: {e}")
