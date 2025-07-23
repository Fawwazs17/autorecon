import subprocess
import os

def sublist3r_scan(domain):
    print(f"Running sublist3r scan on {domain}...")
    output_file = f"results/sublist3r_{domain}.txt"
    command = ["sublist3r", "-d", domain, "-o", output_file]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"sublist3r scan for {domain} completed.")
        if result.stdout:
            print(f"sublist3r stdout: {result.stdout}")
        if result.stderr:
            print(f"sublist3r stderr: {result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"sublist3r scan failed for {domain}: {e.stderr}")
    except FileNotFoundError:
        print("sublist3r is not installed or not in PATH. Please ensure 'sublist3r' is in your system's PATH.")
