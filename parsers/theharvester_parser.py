import json

def parse_theharvester(json_file):
    emails = set()
    hosts = set()
    ips = set()
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        print(f"Parsing theHarvester JSON: {data}") # Debugging line

        emails = set(data.get('emails', []))
        hosts = set(data.get('hosts', []))
        ips = set(data.get('ips', [])) # Extract IPs

    except FileNotFoundError:
        print(f"theHarvester JSON file not found: {json_file}")
        return {'emails': [], 'hosts': [], 'ips': []}
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from theHarvester file {json_file}: {e}")
        return {'emails': [], 'hosts': [], 'ips': []}
    except Exception as e:
        print(f"Error parsing theHarvester JSON file {json_file}: {e}")
        return {'emails': [], 'hosts': [], 'ips': []}

    return {'emails': list(emails), 'hosts': list(hosts), 'ips': list(ips)}
