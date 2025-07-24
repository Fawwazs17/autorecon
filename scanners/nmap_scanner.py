
import subprocess
import os

def nmap_scan(domain):
    print(f"Running nmap scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    command = ["/usr/bin/nmap", domain, "-T4", "-sV", "-oX", f"results/nmap_{domain}.xml"]
    try:
        # Redirect stderr to /dev/null to prevent non-XML output from polluting the XML file
        with open(os.devnull, 'w') as devnull:
            subprocess.run(command, check=True, stderr=devnull)
        print(f"Nmap scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("Nmap is not installed or not in PATH.")

