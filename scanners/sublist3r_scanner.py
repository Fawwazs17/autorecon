import subprocess
import os

def sublist3r_scan(domain, log_handle):
    # print(f"Running sublist3r scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/sublist3r_{domain}.txt"
    command = ["/usr/bin/sublist3r", "-d", domain, "-o", output_file]
    try:
        subprocess.run(command, check=True, stdout=log_handle, stderr=log_handle, timeout=300) # 5 minutes timeout
        return output_file
    except subprocess.CalledProcessError as e:
        log_handle.write(f"Sublist3r scan failed for {domain} with exit code {e.returncode}: {e.stderr.decode() if e.stderr else 'No stderr output'}\n")
        return None
    except FileNotFoundError:
        log_handle.write(f"Sublist3r executable not found. Please ensure 'sublist3r' is in your system's PATH or the venv path is correct.\n")
        return None
    except subprocess.TimeoutExpired:
        log_handle.write(f"Sublist3r scan for {domain} timed out after 5 minutes.\n")
        return None
    except Exception as e:
        log_handle.write(f"An unexpected error occurred during Sublist3r scan for {domain}: {e}\n")
        return None
