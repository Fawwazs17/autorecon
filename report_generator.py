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


def format_web_technologies(web_tech_data):
    """Format web technologies data consistently, handling both simple and complex structures"""
    if not web_tech_data:
        return "No web technologies detected."
    
    formatted_details = ""
    
    # Handle Server information
    server_info = web_tech_data.get('HTTPServer', 'Unknown')
    if isinstance(server_info, list) and server_info:
        # Take the first item and clean it up
        server_info = server_info[0]
    elif isinstance(server_info, list):
        server_info = 'Unknown'
    
    # Clean up server info - remove extra brackets and formatting
    if isinstance(server_info, str):
        server_info = server_info.replace('][', ', ').strip('[]')
    
    formatted_details += f"Server: {server_info}\n"
    
    # Handle IP Address
    ip_info = web_tech_data.get('IP', 'Unknown')
    if isinstance(ip_info, list) and ip_info:
        # Remove duplicates and join
        unique_ips = list(set(ip_info))
        ip_info = ', '.join(unique_ips)
    elif isinstance(ip_info, list):
        ip_info = 'Unknown'
    
    formatted_details += f"IP Address: {ip_info}\n"
    
    # Handle Page Title
    title_info = web_tech_data.get('Title', 'Unknown')
    if isinstance(title_info, list) and title_info:
        # For titles, take the most relevant one (usually the last clean one)
        clean_titles = []
        for title in title_info:
            if isinstance(title, str):
                # Clean up title - remove status codes and URLs
                clean_title = title
                if '] ' in clean_title:
                    clean_title = clean_title.split('] ')[-1]
                if '[' in clean_title and ']' not in clean_title:
                    clean_title = clean_title.split('[')[0]
                if clean_title.strip() and not clean_title.startswith('http'):
                    clean_titles.append(clean_title.strip())
        
        title_info = clean_titles[-1] if clean_titles else title_info[-1]
    elif isinstance(title_info, list):
        title_info = 'Unknown'
    
    # Clean up title
    if isinstance(title_info, str):
        title_info = title_info.replace('\n', ' ').strip()
        # Remove URL patterns from title
        if 'http' in title_info.lower():
            parts = title_info.split()
            clean_parts = [part for part in parts if not part.startswith('http')]
            title_info = ' '.join(clean_parts) if clean_parts else title_info
    
    formatted_details += f"Page Title: {title_info}\n"
    
    # Add technology detection bullets
    tech_features = []
    
    if web_tech_data.get('HTML5'):
        tech_features.append("HTML5 detected")
    
    if web_tech_data.get('LiteSpeed'):
        tech_features.append("LiteSpeed web server")
    elif 'litespeed' in server_info.lower():
        tech_features.append("LiteSpeed web server")
    elif 'apache' in server_info.lower():
        tech_features.append("Apache web server")
    
    if web_tech_data.get('Strict-Transport-Security'):
        tech_features.append("HSTS (HTTP Strict Transport Security) enabled")
    
    if web_tech_data.get('WordPress'):
        tech_features.append("WordPress CMS detected")
    
    if web_tech_data.get('Bootstrap'):
        bootstrap_ver = web_tech_data['Bootstrap']
        tech_features.append(f"Bootstrap framework ({bootstrap_ver})")
    
    if web_tech_data.get('JQuery'):
        jquery_ver = web_tech_data['JQuery']
        tech_features.append(f"jQuery library ({jquery_ver})")
    
    if web_tech_data.get('OpenSSL'):
        openssl_ver = web_tech_data['OpenSSL']
        if isinstance(openssl_ver, list):
            openssl_ver = openssl_ver[0]
        tech_features.append(f"OpenSSL ({openssl_ver})")
    
    # Add bullet points for detected technologies
    for feature in tech_features:
        formatted_details += f"• {feature}\n"
    
    return formatted_details.strip()


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
        pie.labels = [str(v) for v in data_counts.values()]
        pie.slices.labelRadius = 0.7
        pie.slices.fontName = 'Helvetica-Bold'
        pie.slices.fontColor = white
        
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

        # Add legend
        legend_data = []
        for i, (category, count) in enumerate(data_counts.items()):
            color = colors[i % len(colors)]
            # Create a colored square for the legend
            legend_square = Paragraph(f'<font color="{color.hexval()}">■</font> {category}', styles['Normal'])
            legend_data.append([legend_square])
        
        legend_table = Table(legend_data)
        legend_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(legend_table)

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
                port_id = port.get('portid', 'Unknown')
                protocol = port.get('protocol', 'Unknown')
                state = port.get('state', 'Unknown')
                service = port.get('service', 'Unknown')
                ports_details += f"• {port_id}/{protocol} - {service} ({state})\n"
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
    
    if all_subdomains:
        subdomain_list = sorted(list(all_subdomains))
        total_count = len(subdomain_list)
        
        # Display summary first
        summary_details = f"Total subdomains found: {total_count}\n"
        summary_details += f"Scan sources: sublist3r, theharvester, dnsdumpster\n"
        summary_details += "All discovered subdomains are listed below:"
        
        summary_table_data = [["Subdomains Summary", summary_details]]
        story.append(_create_detailed_table(summary_table_data))
        story.append(Spacer(1, 0.1 * inch))
        
        # Split subdomains into chunks that fit on a page
        # Estimate: ~20-25 subdomains per table to stay within page limits
        chunk_size = 20
        
        for i in range(0, len(subdomain_list), chunk_size):
            chunk = subdomain_list[i:i + chunk_size]
            chunk_start = i + 1
            chunk_end = min(i + chunk_size, total_count)
            
            # Create subdomain list for this chunk
            chunk_details = f"Subdomains {chunk_start}-{chunk_end} of {total_count}:\n"
            for subdomain in chunk:
                chunk_details += f"• {subdomain}\n"
            
            chunk_table_data = [["Subdomain List", chunk_details.strip()]]
            story.append(_create_detailed_table(chunk_table_data))
            
            # Add small spacer between chunks
            story.append(Spacer(1, 0.1 * inch))
            
            # Add page break if we have more chunks and this isn't the last one
            if i + chunk_size < len(subdomain_list):
                # Check if we should add a page break (every 2-3 chunks)
                chunks_on_page = (i // chunk_size) % 3
                if chunks_on_page == 2:  # After every 3 chunks, start new page
                    story.append(PageBreak())
    else:
        detailed_subdomains_data = [["Subdomains", "No subdomains or hosts discovered."]]
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
    
    # 4.4 Web Technologies - FIXED FORMATTING
    story.append(Paragraph("4.4 Web Technologies", styles['SubSectionTitle']))
    
    web_tech = data_dictionary.get("web_technologies", {}).get("whatweb", {})
    detailed_web_tech_data = []
    
    if web_tech:
        formatted_tech_details = format_web_technologies(web_tech)
        detailed_web_tech_data.append(["Web Technologies", formatted_tech_details])
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