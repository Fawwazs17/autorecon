
import subprocess
import os

def httpx_scan(domain, log_handle):
    # print(f"Running httpx scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/httpx_headers_{domain}.txt"
    command = ["/usr/bin/httpx", f"https://{domain}"]
    try:
        subprocess.run(command, check=True, stdout=f, stderr=log_handle)
        return output_file
        # print(f"Httpx scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        # print(f"Httpx scan failed for {domain}: {e.stderr}")
        pass
    except FileNotFoundError:
        # print("httpx is not installed or not in PATH. Please ensure 'httpx' is in your system's PATH.")
        pass
