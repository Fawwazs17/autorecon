import json

def parse_theharvester(json_file):
    emails = set()
    hosts = set()
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        # Extract emails
    if 'emails' in data:
        for email_entry in data['emails']:
            emails.add(email_entry)

    # Extract hosts (subdomains and IPs)
    if 'hosts' in data:
        for host_entry in data['hosts']:
            hosts.add(host_entry)
    if 'ips' in data: # Add IPs from the 'ips' key
        for ip_entry in data['ips']:
            hosts.add(ip_entry)

    except FileNotFoundError:
        return {'emails': [], 'hosts': []}
    except json.JSONDecodeError:
        print(f"Error decoding JSON from {json_file}")
        return {'emails': [], 'hosts': []}

    return {'emails': list(emails), 'hosts': list(hosts)}
