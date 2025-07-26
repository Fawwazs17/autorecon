
import subprocess
import os

def dnsenum_scan(domain):
    # print(f"Running dnsenum scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    command = ["/usr/bin/perl", "/usr/bin/dnsenum", domain, "--output", f"results/dnsenum_{domain}.xml"]
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.run(command, check=True, stdout=devnull, stderr=devnull)
        # print(f"Dnsenum scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        # print(f"Dnsenum scan failed for {domain}: {e}")
        pass
    except FileNotFoundError:
        # print("Dnsenum is not installed or not in PATH.")
        pass
