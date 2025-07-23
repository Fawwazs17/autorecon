import xml.etree.ElementTree as ET

def parse_theharvester(xml_file):
    emails = set()
    hosts = set()
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for email in root.findall('.//email'):
            emails.add(email.text)
        for host in root.findall('.//host'):
            hosts.add(host.text)
    except ET.ParseError:
        print(f"Error parsing XML from {xml_file}. It might be malformed or empty.")
    except FileNotFoundError:
        pass

    return {'emails': list(emails), 'hosts': list(hosts)}