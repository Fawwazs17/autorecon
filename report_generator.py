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

def calculate_scan_duration(timestamp_str):
    """Calculate duration from timestamp to now (simplified for this example)"""
    try:
        # For this example, we'll just show the scan was completed
        scan_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return f"Completed at {scan_time.strftime('%H:%M:%S')}"
    except:
        return "N/A"

def get_category_data_counts(data_dictionary):
    """Extract actual data counts from the JSON structure"""
    counts = {}
    
    # Network & DNS Info
    dns_count = 0
    network_dns = data_dictionary.get("network_dns_info", {})
    if network_dns.get("nmap"):
        dns_count += len(network_dns["nmap"])
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
    
    # Remove duplicates by converting to set (simplified)
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

def generate_report(domain, data_dictionary_path, output_path):
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
    timestamp = scan_metadata.get("timestamp", "")
    scan_duration = calculate_scan_duration(timestamp)

    # === FIRST PAGE: Header and Pie Chart ===
    story.append(Paragraph(f"🔍 Reconnaissance Report", styles['ReportTitle']))
    story.append(Paragraph(f"Target Domain: {target_domain}", styles['ReportTitle']))
    story.append(Spacer(1, 0.3 * inch))
    
    story.append(Paragraph(f"<b>Prepared by:</b> Automated Recon Tool", styles['Normal']))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Paragraph(f"<b>Scan Duration:</b> {scan_duration}", styles['Normal']))
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
    story.append(Paragraph("📊 Summary Table (Key Findings)", styles['SectionTitle']))
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
        'Critical': HexColor('#FFEBEE'),
        'High': HexColor('#FFF3E0'), 
        'Medium': HexColor('#FFFDE7'),
        'Low': HexColor('#E8F5E8')
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
    story.append(Paragraph("📋 Detailed Analysis", styles['SectionTitle']))
    
    # 4.1 Network & DNS Info
    story.append(Paragraph("🔶 4.1 Network & DNS Information", styles['SubSectionTitle']))
    
    network_dns = data_dictionary.get("network_dns_info", {})
    
    # DNS Records
    story.append(Paragraph("<b>DNS Records:</b>", styles['Normal']))
    dnsdumpster_data = network_dns.get("dnsdumpster", {})
    
    if dnsdumpster_data.get("ns_records"):
        story.append(Paragraph("Nameservers:", styles['Normal']))
        for ns in dnsdumpster_data["ns_records"]:
            story.append(Paragraph(f"• Host: {ns.get('host', 'N/A')}", styles['Normal']))
    
    if dnsdumpster_data.get("mx_records"):
        story.append(Paragraph("MX Records:", styles['Normal']))
        for mx in dnsdumpster_data["mx_records"]:
            story.append(Paragraph(f"• {mx.get('host', 'N/A')}", styles['Normal']))
    
    # Open Ports
    story.append(Paragraph("<b>Open Ports:</b>", styles['Normal']))
    if network_dns.get("nmap"):
        for host_data in network_dns["nmap"]:
            ip = host_data.get("ip", "Unknown")
            story.append(Paragraph(f"Host: {ip}", styles['Normal']))
            for port in host_data.get("ports", []):
                port_info = f"• {port.get('portid')}/{port.get('protocol')} - {port.get('service', 'Unknown')}"
                story.append(Paragraph(port_info, styles['Normal']))
    else:
        story.append(Paragraph("No open ports detected.", styles['Normal']))
    
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.2 Subdomains & Hosts  
    story.append(Paragraph("🌐 4.2 Subdomains & Hosts", styles['SubSectionTitle']))
    
    subdomains_hosts = data_dictionary.get("subdomains_hosts", {})
    all_subdomains = set()
    
    if subdomains_hosts.get("sublist3r"):
        all_subdomains.update(subdomains_hosts["sublist3r"])
    
    if subdomains_hosts.get("theharvester", {}).get("discovered_hosts"):
        all_subdomains.update(subdomains_hosts["theharvester"]["discovered_hosts"])
    
    if subdomains_hosts.get("dnsdumpster", {}).get("a_records"):
        for record in subdomains_hosts["dnsdumpster"]["a_records"]:
            all_subdomains.add(record.get("host", ""))
    
    story.append(Paragraph(f"<b>Total found:</b> {len(all_subdomains)}", styles['Normal']))
    
    if all_subdomains:
        story.append(Paragraph("Discovered subdomains:", styles['Normal']))
        for subdomain in sorted(list(all_subdomains))[:15]:  # Show first 15
            story.append(Paragraph(f"• {subdomain}", styles['Normal']))
        if len(all_subdomains) > 15:
            story.append(Paragraph(f"... and {len(all_subdomains) - 15} more", styles['Normal']))
    
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.3 Emails
    story.append(Paragraph("📧 4.3 Email Addresses", styles['SubSectionTitle']))
    
    emails = data_dictionary.get("emails", {})
    found_emails = []
    
    if emails.get("theharvester", {}).get("discovered_emails"):
        found_emails.extend(emails["theharvester"]["discovered_emails"])
    
    if emails.get("whatweb", {}).get("contact_email"):
        found_emails.append(emails["whatweb"]["contact_email"])
    
    if found_emails:
        for email in found_emails:
            story.append(Paragraph(f"• {email}", styles['Normal']))
    else:
        story.append(Paragraph("No email addresses discovered.", styles['Normal']))
    
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.4 Web Technologies
    story.append(Paragraph("🧠 4.4 Web Technologies", styles['SubSectionTitle']))
    
    web_tech = data_dictionary.get("web_technologies", {}).get("whatweb", {})
    if web_tech:
        story.append(Paragraph(f"<b>Server:</b> {web_tech.get('HTTPServer', 'Unknown')}", styles['Normal']))
        story.append(Paragraph(f"<b>IP Address:</b> {web_tech.get('IP', 'Unknown')}", styles['Normal']))
        story.append(Paragraph(f"<b>Page Title:</b> {web_tech.get('Title', 'Unknown')}", styles['Normal']))
        
        if web_tech.get('HTML5'):
            story.append(Paragraph("• HTML5 detected", styles['Normal']))
        if web_tech.get('LiteSpeed'):
            story.append(Paragraph("• LiteSpeed web server", styles['Normal']))
        if web_tech.get('Strict-Transport-Security'):
            story.append(Paragraph("• HSTS (HTTP Strict Transport Security) enabled", styles['Normal']))
    else:
        story.append(Paragraph("No web technologies detected.", styles['Normal']))
    
    story.append(Spacer(1, 0.2 * inch))
    
    # 4.5 Live Hosts
    story.append(Paragraph("🔍 4.5 Live Hosts Analysis", styles['SubSectionTitle']))
    
    http_headers = data_dictionary.get("http_headers", {})
    if http_headers.get("httpx"):
        story.append(Paragraph(f"<b>Target responds to HTTP/HTTPS requests</b>", styles['Normal']))
        story.append(Paragraph(f"• Domain: {target_domain}", styles['Normal']))
        story.append(Paragraph("• Protocol: HTTPS (443)", styles['Normal']))
        story.append(Paragraph("• Status: Live and responding", styles['Normal']))
    else:
        story.append(Paragraph("No live hosts detected.", styles['Normal']))

    # Build the PDF
    doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
    print(f"Report generated successfully: {output_path}")

if __name__ == '__main__':
    # Example usage
    domain = "zeroday-sec.com"
    data_path = f"data_dictionary_{domain}.json"
    output_path = f"reconnaissance_report_{domain}.pdf"
    
    generate_report(domain, data_path, output_path)