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
                if 'email' in email_entry:
                    emails.add(email_entry['email'])

        # Extract hosts (subdomains and IPs)
        if 'hosts' in data:
            for host_entry in data['hosts']:
                if 'hostname' in host_entry:
                    hosts.add(host_entry['hostname'])
                if 'ip' in host_entry:
                    hosts.add(host_entry['ip'])

    except FileNotFoundError:
        return {'emails': [], 'hosts': []}
    except json.JSONDecodeError:
        print(f"Error decoding JSON from {json_file}")
        return {'emails': [], 'hosts': []}

    return {'emails': list(emails), 'hosts': list(hosts)}
