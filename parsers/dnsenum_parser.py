
import xml.etree.ElementTree as ET

def parse_dnsenum(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        # This is a simplified parser. Dnsenum XML can be complex.
        # We will just extract hostnames for now.
        hostnames = []
        for host in root.findall('.//host'):
            hostnames.append(host.text)
        return hostnames
    except ET.ParseError:
        return [] # Return empty list if XML is malformed
