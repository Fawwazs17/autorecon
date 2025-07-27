import subprocess
import os

def sublist3r_scan(domain, log_handle):
    # print(f"Running sublist3r scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/sublist3r_{domain}.txt"
    command = ["/home/kali/Desktop/python-security-scanner/venv/bin/python", "/home/kali/Desktop/python-security-scanner/venv/lib/python3.13/site-packages/sublist3r.py", "-d", domain, "-o", output_file]
    try:
        subprocess.run(command, check=True, stdout=log_handle, stderr=log_handle)
        return output_file
        # print(f"sublist3r scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        # print(f"sublist3r scan failed for {domain}: {e.stderr}")
        pass
    except FileNotFoundError:
        # print("sublist3r is not installed or not in PATH. Please ensure 'sublist3r' is in your system's PATH.")
        pass
