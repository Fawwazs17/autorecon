
import subprocess
import os

def dnsenum_scan(domain):
    print(f"Running dnsenum scan on {domain}...")
    # Dnsenum is a Perl script, so we explicitly call perl
    command = ["/usr/bin/perl", "/usr/bin/dnsenum", domain, "--output", f"results/dnsenum_{domain}.xml"]
    try:
        subprocess.run(command, check=True)
        print(f"Dnsenum scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"Dnsenum scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("Dnsenum is not installed or not in PATH.")
