
import subprocess
import os

def theharvester_scan(domain):
    print(f"Running theHarvester scan on {domain}...")
    # theHarvester is a Python script, so we explicitly call python3
    command = ["/usr/bin/python3", "/usr/bin/theharvester", "-d", domain, "-b", "all", "-f", f"results/theharvester_{domain}"]
    try:
        subprocess.run(command, check=True)
        print(f"theHarvester scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"theHarvester scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("theHarvester is not installed or not in PATH.")
