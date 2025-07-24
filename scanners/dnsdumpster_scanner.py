import subprocess
import os

def dnsdumpster_scan(domain):
    print(f"Running DNSDumpster scan on {domain}...")
    os.makedirs("results", exist_ok=True)
    output_file = f"results/dnsdumpster_{domain}.json"
    # IMPORTANT: Using a hardcoded API key from cmd.txt. For production, use environment variables or config files.
    api_key = "eb35c0dd2f46ef0d0788a26c12439d0f86ca1f28bc97d5fa748a5cb81203ed96"
    command = [
        "curl",
        "-H", f"X-API-Key: {api_key}",
        f"https://api.dnsdumpster.com/domain/{domain}",
        "-o", output_file
    ]
    try:
        subprocess.run(command, check=True)
        print(f"DNSDumpster scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"DNSDumpster scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("curl is not installed or not in PATH. Please ensure 'curl' is in your system's PATH.")
