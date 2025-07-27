
import subprocess
import os

def dnsenum_scan(domain, log_handle):
    # print(f"Running dnsenum scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/dnsenum_{domain}.xml"
    command = ["/usr/bin/perl", "/usr/bin/dnsenum", domain, "--noreverse", "--output", output_file]
    try:
        subprocess.run(command, check=True, stdout=log_handle, stderr=log_handle)
        return output_file
        # print(f"Dnsenum scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        # print(f"Dnsenum scan failed for {domain}: {e}")
        pass
    except FileNotFoundError:
        # print("Dnsenum is not installed or not in PATH.")
        pass
