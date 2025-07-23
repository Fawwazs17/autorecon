
import xml.etree.ElementTree as ET

def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []
    for host in root.findall('host'):
        host_info = {
            'ip': host.find('address').get('addr'),
            'ports': []
        }
        for port in host.findall('.//port'):
            port_info = {
                'portid': port.get('portid'),
                'protocol': port.get('protocol'),
                'state': port.find('state').get('state'),
                'service': port.find('service').get('name') if port.find('service') is not None else ''
            }
            host_info['ports'].append(port_info)
        hosts.append(host_info)
    return hosts
