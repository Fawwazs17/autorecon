import subprocess
import os

def sublist3r_scan(domain):
    # print(f"Running sublist3r scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/sublist3r_{domain}.txt"
    command = ["/usr/bin/sublist3r", "-d", domain, "-o", output_file]
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.run(command, check=True, stdout=devnull, stderr=devnull)
        # print(f"sublist3r scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        # print(f"sublist3r scan failed for {domain}: {e.stderr}")
        pass
    except FileNotFoundError:
        # print("sublist3r is not installed or not in PATH. Please ensure 'sublist3r' is in your system's PATH.")
        pass
