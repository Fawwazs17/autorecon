import re

def parse_theharvester(text_file):
    emails = set()
    hosts = set()
    try:
        with open(text_file, 'r') as f:
            content = f.read()

        # Regex to find emails
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        found_emails = email_pattern.findall(content)
        for email in found_emails:
            emails.add(email)

        # Regex to find hosts/subdomains (simplified, may need refinement)
        # This pattern looks for lines that might contain hostnames
        host_pattern = re.compile(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b')
        found_hosts = host_pattern.findall(content)
        for host in found_hosts:
            # Filter out common non-host strings that might match the pattern
            if not any(ext in host for ext in ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.pdf']):
                hosts.add(host)

    except FileNotFoundError:
        return {'emails': [], 'hosts': []}
    except Exception as e:
        print(f"Error parsing theHarvester text file {text_file}: {e}")
        return {'emails': [], 'hosts': []}

    return {'emails': list(emails), 'hosts': list(hosts)}

    return {'emails': list(emails), 'hosts': list(hosts)}
