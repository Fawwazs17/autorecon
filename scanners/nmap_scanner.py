
import subprocess
import os

def nmap_scan(domain):
    print(f"Running nmap scan on {domain}...")
    command = ["/usr/bin/nmap", domain, "-T4", "-sV", "-oX", f"results/nmap_{domain}.xml"]
    try:
        subprocess.run(command, check=True)
        print(f"Nmap scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("Nmap is not installed or not in PATH.")

