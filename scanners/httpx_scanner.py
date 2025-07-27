
import subprocess
import os

def httpx_scan(domain, log_handle):
    # print(f"Running httpx scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/httpx_headers_{domain}.txt"
    command = ["/usr/bin/httpx", f"https://{domain}"]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(command, check=True, stdout=f, stderr=log_handle, timeout=60) # 1 minute timeout
        return output_file
    except subprocess.CalledProcessError as e:
        log_handle.write(f"HTTPX scan failed for {domain} with exit code {e.returncode}: {e.stderr.decode() if e.stderr else 'No stderr output'}\n")
        return None
    except FileNotFoundError:
        log_handle.write(f"HTTPX executable not found. Please ensure 'httpx' is in your system's PATH.\n")
        return None
    except subprocess.TimeoutExpired:
        log_handle.write(f"HTTPX scan for {domain} timed out after 1 minute.\n")
        return None
    except Exception as e:
        log_handle.write(f"An unexpected error occurred during HTTPX scan for {domain}: {e}\n")
        return None
