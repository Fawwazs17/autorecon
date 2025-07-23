
import subprocess
import os

def whatweb_scan(domain):
    print(f"Running whatweb scan on {domain}...")
    # WhatWeb is a Ruby script, so we explicitly call ruby
    command = ["/usr/bin/ruby", "/usr/bin/whatweb", f"https://{domain}", "--log-brief=results/whatweb_{domain}.txt"]
    try:
        subprocess.run(command, check=True)
        print(f"WhatWeb scan for {domain} completed.")
    except subprocess.CalledProcessError as e:
        print(f"WhatWeb scan failed for {domain}: {e}")
    except FileNotFoundError:
        print("WhatWeb is not installed or not in PATH.")
