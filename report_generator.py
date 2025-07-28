import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.colors import HexColor, black, white, red, orange, yellow, green
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from datetime import datetime
from reportlab.lib.units import inch


def _create_detailed_table(data):
    table_data = [['Category', 'Details']]
    table_data.extend(data)

    table = Table(table_data, colWidths=[1.8*inch, 5.2*inch]) # Adjust column widths as needed
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495E')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, black),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'), # Align content to top for multi-line details
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#F8F9FA'), white])
    ]))
    return table



def get_category_data_counts(data_dictionary):
    """Extract actual data counts from the JSON structure"""
    counts = {}
    
    # Network & DNS Info
    dns_count = 0
    network_dns = data_dictionary.get("network_dns_info", {})
    
    if network_dns.get("dnsdumpster", {}).get("ns_records"):
        dns_count += len(network_dns["dnsdumpster"]["ns_records"])
    if network_dns.get("dnsdumpster", {}).get("mx_records"):
        dns_count += len(network_dns["dnsdumpster"]["mx_records"])
    
    # Open Ports
    ports_count = 0
    if network_dns.get("nmap"):
        for host in network_dns["nmap"]:
            ports_count += len(host.get("ports", []))
    
    # Subdomains & Hosts
    subdomains_count = 0
    subdomains_hosts = data_dictionary.get("subdomains_hosts", {})
    if subdomains_hosts.get("sublist3r"):
        subdomains_count += len(subdomains_hosts["sublist3r"])
    if subdomains_hosts.get("theharvester", {}).get("discovered_hosts"):
        subdomains_count += len(subdomains_hosts["theharvester"]["discovered_hosts"])
    if subdomains_hosts.get("dnsdumpster", {}).get("a_records"):
        subdomains_count += len(subdomains_hosts["dnsdumpster"]["a_records"])
    
    # Remove duplicates 
    unique_subdomains = set()
    if subdomains_hosts.get("sublist3r"):
        unique_subdomains.update(subdomains_hosts["sublist3r"])
    if subdomains_hosts.get("theharvester", {}).get("discovered_hosts"):
        unique_subdomains.update(subdomains_hosts["theharvester"]["discovered_hosts"])
    if subdomains_hosts.get("dnsdumpster", {}).get("a_records"):
        for record in subdomains_hosts["dnsdumpster"]["a_records"]:
            unique_subdomains.add(record.get("host", ""))
    subdomains_count = len(unique_subdomains)
    
    # Emails
    emails_count = 0
    emails = data_dictionary.get("emails", {})
    if emails.get("theharvester", {}).get("discovered_emails"):
        emails_count += len(emails["theharvester"]["discovered_emails"])
    if emails.get("whatweb", {}).get("contact_email"):
        emails_count += 1
    
    # Web Technologies
    web_tech_count = 0
    web_tech = data_dictionary.get("web_technologies", {})
    if web_tech.get("whatweb"):
        # Count meaningful web technologies (excluding basic headers)
        tech_data = web_tech["whatweb"]
        meaningful_tech = ["HTTPServer", "HTML5", "LiteSpeed", "Title"]
        web_tech_count = sum(1 for key in meaningful_tech if tech_data.get(key))
    
    # Live Hosts (from HTTP headers)
    live_hosts_count = 1 if data_dictionary.get("http_headers", {}).get("httpx") else 0
    
    # Only include categories with data
    if dns_count > 0:
        counts["DNS Records"] = dns_count
    if ports_count > 0:
        counts["Open Ports"] = ports_count
    if subdomains_count > 0:
        counts["Subdomains & Hosts"] = subdomains_count
    if emails_count > 0:
        counts["Emails"] = emails_count
    if web_tech_count > 0:
        counts["Web Technologies"] = web_tech_count
    if live_hosts_count > 0:
        counts["Live Hosts"] = live_hosts_count
    
    return counts

def get_category_severity(category_name, data_count):
    """Determine severity based on category and data count"""
    if data_count == 0:
        return "Low"
    
    severity_map = {
        "Open Ports": "Critical",
        "DNS Records": "Medium", 
        "Subdomains & Hosts": "High",
        "Emails": "Medium",
        "Web Technologies": "Low",
        "Live Hosts": "Medium"
    }
    
    return severity_map.get(category_name, "Low")

def get_category_summary(category_name, data_dictionary, data_count):
    """Generate human-readable summary for each category"""
    if data_count == 0:
        return "No data found"
    
    if category_name == "DNS Records":
        network_dns = data_dictionary.get("network_dns_info", {})
        ns_count = len(network_dns.get("dnsdumpster", {}).get("ns_records", []))
        mx_count = len(network_dns.get("dnsdumpster", {}).get("mx_records", []))
        return f"Found {ns_count} nameservers, {mx_count} MX records"
    
    elif category_name == "Open Ports":
        return f"Discovered {data_count} open ports on target"
    
    elif category_name == "Subdomains & Hosts":
        return f"Identified {data_count} unique subdomains/hosts"
    
    elif category_name == "Emails":
        return f"Found {data_count} email addresses"
    
    elif category_name == "Web Technologies":
        return f"Detected {data_count} web technologies"
    
    elif category_name == "Live Hosts":
        return f"Found {data_count} responsive hosts"
    
    return f"Found {data_count} items"

def add_footer(canvas, doc):
    """Add footer with page number and date"""
    canvas.saveState()
    canvas.setFont('Helvetica', 9)
    canvas.drawString(inch, 0.75 * inch, f"Page {doc.page}")
    canvas.drawString(doc.width - 2*inch, 0.75 * inch, datetime.now().strftime("%Y-%m-%d %H:%M"))
    canvas.restoreState()

def generate_report(domain, data_dictionary_path, output_path, author, scan_duration_str):
    """Generate the PDF reconnaissance report"""
    doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=inch, bottomMargin=inch)
    styles = getSampleStyleSheet()
    story = []

    # Custom styles
    styles.add(ParagraphStyle(
        name='ReportTitle', 
        fontSize=24, 
        leading=28, 
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        spaceAfter=20
    ))
    
    styles.add(ParagraphStyle(
        name='SectionTitle', 
        fontSize=18, 
        leading=22, 
        spaceAfter=12,
        fontName='Helvetica-Bold',
        textColor=HexColor('#2C3E50')
    ))
    
    styles.add(ParagraphStyle(
        name='SubSectionTitle', 
        fontSize=14, 
        leading=18, 
        spaceAfter=8,
        fontName='Helvetica-Bold',
        textColor=HexColor('#34495E')
    ))

    # Load data
    try:
        with open(data_dictionary_path, 'r') as f:
            data_dictionary = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        story.append(Paragraph(f"Error loading data: {str(e)}", styles['Normal']))
        doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
        return

    # Extract scan metadata
    scan_metadata = data_dictionary.get("scan_metadata", {})
    target_domain = scan_metadata.get("domain", domain)

    # === FIRST PAGE: Header and Pie Chart ===
    story.append(Paragraph(f"Reconnaissance Report", styles['ReportTitle']))
    story.append(Paragraph(f"Target Domain: {target_domain}", styles['ReportTitle']))
    story.append(Spacer(1, 0.3 * inch))
    
    story.append(Paragraph(f"<b>Prepared by:</b> {author}", styles['Normal']))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Paragraph(f"<b>Scan Duration:</b> {scan_duration_str}", styles['Normal']))
    story.append(Paragraph(f"<b>Total Sources:</b> {scan_metadata.get('total_sources', 'N/A')}", styles['Normal']))
    story.append(Spacer(1, 0.5 * inch))

    # Pie Chart
    data_counts = get_category_data_counts(data_dictionary)
    if data_counts:
        drawing = Drawing(500, 300)
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.height = 200
        pie.width = 200
        pie.data = list(data_counts.values())
        pie.labels = [f"{k}\n({v})" for k, v in data_counts.items()]
        
        # Distinct colors for each slice
        colors = [
            HexColor('#E74C3C'),  # Red
            HexColor('#F39C12'),  # Orange  
            HexColor('#F1C40F'),  # Yellow
            HexColor('#27AE60'),  # Green
            HexColor('#3498DB'),  # Blue
            HexColor('#9B59B6')   # Purple
        ]
        
        pie.slices.strokeWidth = 1
        pie.slices.strokeColor = white
        for i in range(len(pie.data)):
            pie.slices[i].fillColor = colors[i % len(colors)]
        
        drawing.add(pie)
        story.append(drawing)
    else:
        story.append(Paragraph("No data available for visualization.", styles['Normal']))

    story.append(PageBreak())

    # === PAGE 2: Summary Table ===
    story.append(Paragraph("Summary Table (Key Findings)", styles['SectionTitle']))
    story.append(Spacer(1, 0.2 * inch))

    # Create summary table
    summary_data = [['Category', 'Key Findings', 'Count', 'Severity']]
    
    category_order = ["DNS Records", "Open Ports", "Subdomains & Hosts", "Emails", "Web Technologies", "Live Hosts"]
    
    for category in category_order:
        data_count = data_counts.get(category, 0)
        severity = get_category_severity(category, data_count)
        summary = get_category_summary(category, data_dictionary, data_count)
        summary_data.append([category, summary, str(data_count), severity])

    # Create table
    table = Table(summary_data, colWidths=[1.5*inch, 3*inch, 0.8*inch, 0.8*inch])
    
    # Basic table style
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495E')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, black),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#F8F9FA'), white])
    ]))
    
    # Apply severity colors
    severity_colors = {
        'Critical': HexColor('#d6112f'),
        'High': HexColor('#d67011'), 
        'Medium': HexColor('#fff700'),
        'Low': HexColor('#1ed611')
    }
    
    for i, row in enumerate(summary_data[1:], 1):
        severity = row[3]
        if severity in severity_colors:
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, i), (-1, i), severity_colors[severity])
            ]))

    story.append(table)
    story.append(PageBreak())

    # === DETAILED SECTIONS ===
    story.append(Paragraph("Detailed Analysis", styles['SectionTitle']))
    
    # 4.1 Network & DNS Information
    story.append(Paragraph("4.1 Network & DNS Information", styles['SubSectionTitle']))
    
    network_dns = data_dictionary.get("network_dns_info", {})
    detailed_network_dns_data = []
    
    # DNS Records
    dnsdumpster_data = network_dns.get("dnsdumpster", {})
    ns_records = dnsdumpster_data.get("ns_records", [])
    mx_records = dnsdumpster_data.get("mx_records", [])
    
    if ns_records or mx_records:
        dns_details = ""
        if ns_records:
            dns_details += "Nameservers:\n" + "\n".join([f"• Host: {ns.get('host', 'N/A')}" for ns in ns_records]) + "\n"
        if mx_records:
            dns_details += "MX Records:\n" + "\n".join([f"• {mx.get('host', 'N/A')}" for mx in mx_records])
        detailed_network_dns_data.append(["DNS Records", dns_details.strip()])
    
    # Open Ports
    if network_dns.get("nmap"):
        ports_details = ""
        for host_data in network_dns["nmap"]:
            ip = host_data.get("ip", "Unknown")
            ports_details += f"Host: {ip}\n"
            for port in host_data.get("ports", []):
                ports_details += f"• {port.get('portid')}/{port.get('protocol')} - {port.get('service', 'Unknown')}\n"
        detailed_network_dns_data.append(["Open Ports", ports_details.strip()])
    else:
        detailed_network_dns_data.append(["Open Ports", "No open ports detected."])

    if detailed_network_dns_data:
        story.append(_create_detailed_table(detailed_network_dns_data))
    else:
        story.append(Paragraph("No network & DNS information available.", styles['Normal']))
    
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.2 Subdomains & Hosts  
    story.append(Paragraph("4.2 Subdomains & Hosts", styles['SubSectionTitle']))
    
    subdomains_hosts = data_dictionary.get("subdomains_hosts", {})
    all_subdomains = set()
    
    if subdomains_hosts.get("sublist3r"):
        all_subdomains.update(subdomains_hosts["sublist3r"])
    
    if subdomains_hosts.get("theharvester", {}).get("discovered_hosts"):
        all_subdomains.update(subdomains_hosts["theharvester"]["discovered_hosts"])
    
    if subdomains_hosts.get("dnsdumpster", {}).get("a_records"):
        for record in subdomains_hosts["dnsdumpster"]["a_records"]:
            all_subdomains.add(record.get("host", ""))
    
    detailed_subdomains_data = []
    if all_subdomains:
        subdomain_list = sorted(list(all_subdomains))
        subdomains_details = f"Total found: {len(subdomain_list)}\n"
        subdomains_details += "Discovered subdomains:\n"
        for subdomain in subdomain_list[:15]:  # Show first 15
            subdomains_details += f"• {subdomain}\n"
        if len(subdomain_list) > 15:
            subdomains_details += f"... and {len(subdomain_list) - 15} more"
        detailed_subdomains_data.append(["Subdomains", subdomains_details.strip()])
    else:
        detailed_subdomains_data.append(["Subdomains", "No subdomains or hosts discovered."])

    story.append(_create_detailed_table(detailed_subdomains_data))
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.3 Emails
    story.append(Paragraph("4.3 Email Addresses", styles['SubSectionTitle']))
    
    emails = data_dictionary.get("emails", {})
    found_emails = []
    
    if emails.get("theharvester", {}).get("discovered_emails"):
        found_emails.extend(emails["theharvester"]["discovered_emails"])
    
    if emails.get("whatweb", {}).get("contact_email"):
        found_emails.append(emails["whatweb"]["contact_email"])
    
    detailed_emails_data = []
    if found_emails:
        emails_details = "\n".join([f"• {email}" for email in found_emails])
        detailed_emails_data.append(["Emails", emails_details.strip()])
    else:
        detailed_emails_data.append(["Emails", "No email addresses discovered."])
    
    story.append(_create_detailed_table(detailed_emails_data))
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.4 Web Technologies
    story.append(Paragraph("4.4 Web Technologies", styles['SubSectionTitle']))
    
    web_tech = data_dictionary.get("web_technologies", {}).get("whatweb", {})
    detailed_web_tech_data = []
    if web_tech:
        web_tech_details = ""
        web_tech_details += f"Server: {web_tech.get('HTTPServer', 'Unknown')}\n"
        web_tech_details += f"IP Address: {web_tech.get('IP', 'Unknown')}\n"
        web_tech_details += f"Page Title: {web_tech.get('Title', 'Unknown')}\n"
        
        if web_tech.get('HTML5'):
            web_tech_details += "• HTML5 detected\n"
        if web_tech.get('LiteSpeed'):
            web_tech_details += "• LiteSpeed web server\n"
        if web_tech.get('Strict-Transport-Security'):
            web_tech_details += "• HSTS (HTTP Strict Transport Security) enabled\n"
        detailed_web_tech_data.append(["Web Technologies", web_tech_details.strip()])
    else:
        detailed_web_tech_data.append(["Web Technologies", "No web technologies detected."])
    
    story.append(_create_detailed_table(detailed_web_tech_data))
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.5 Live Hosts
    story.append(Paragraph("4.5 Live Hosts Analysis", styles['SubSectionTitle']))
    
    http_headers = data_dictionary.get("http_headers", {})
    detailed_live_hosts_data = []
    if http_headers.get("httpx"):
        live_hosts_details = ""
        live_hosts_details += f"Target responds to HTTP/HTTPS requests\n"
        live_hosts_details += f"• Domain: {target_domain}\n"
        live_hosts_details += f"• Protocol: HTTPS (443)\n"
        live_hosts_details += f"• Status: Live and responding\n"
        detailed_live_hosts_data.append(["Live Hosts", live_hosts_details.strip()])
    else:
        detailed_live_hosts_data.append(["Live Hosts", "No live hosts detected."])

    story.append(_create_detailed_table(detailed_live_hosts_data))

    # Build the PDF
    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    print(f"Report generated successfully: {output_path}")

if __name__ == '__main__':
    # Example usage
    domain = "zeroday-sec.com"
    data_path = f"data_dictionary_{domain}.json"
    output_path = f"reconnaissance_report_{domain}.pdf"
    author_example = "Test User"
    scan_duration_example = "00:05:30"
    
    generate_report(domain, data_path, output_path, author_example, scan_duration_example)