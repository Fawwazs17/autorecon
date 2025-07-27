
import subprocess
import os

def nmap_scan(domain, log_handle):
    # print(f"Running nmap scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/nmap_{domain}.xml"
    command = ["/usr/bin/nmap", domain, "-T4", "-sV", "-oX", output_file]
    try:
        subprocess.run(command, check=True, stdout=log_handle, stderr=log_handle)
        return output_file
        # print(f"Nmap scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        # print(f"Nmap scan failed for {domain}: {e}")
        pass
    except FileNotFoundError:
        # print("Nmap is not installed or not in PATH.")
        pass

