
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import json
import matplotlib.pyplot as plt
import io

def categorize_results(results):
    categorized_data = {
        "network_dns_info": {},
        "subdomains_hosts": {},
        "emails": {},
        "web_technologies": {},
        "http_headers": {}
    }

    # Network & DNS Info
    if 'nmap' in results:
        categorized_data["network_dns_info"]["nmap"] = results['nmap']
    if 'dnsenum' in results:
        categorized_data["network_dns_info"]["dnsenum"] = results['dnsenum']
    if 'dnsdumpster' in results:
        categorized_data["network_dns_info"]["dnsdumpster"] = results['dnsdumpster']

    # Subdomains & Hosts
    if 'sublist3r' in results:
        categorized_data["subdomains_hosts"]["sublist3r"] = results['sublist3r']
    if 'theharvester' in results and 'hosts' in results['theharvester']:
        categorized_data["subdomains_hosts"]["theharvester_hosts"] = results['theharvester']['hosts']
    if 'dnsdumpster' in results and ('a' in results['dnsdumpster'] or 'cname' in results['dnsdumpster']):
        categorized_data["subdomains_hosts"]["dnsdumpster"] = {
            "a": results['dnsdumpster'].get('a', []),
            "cname": results['dnsdumpster'].get('cname', [])
        }

    # Emails
    if 'theharvester' in results and 'emails' in results['theharvester']:
        categorized_data["emails"]["theharvester_emails"] = results['theharvester']['emails']

    # Web Technologies
    if 'whatweb' in results:
        categorized_data["web_technologies"]["whatweb"] = results['whatweb']

    # HTTP Headers
    if 'httpx' in results:
        categorized_data["http_headers"]["httpx"] = results['httpx']

    return categorized_data

def create_donut_chart(data, title):
    labels = list(data.keys())
    sizes = list(data.values())
    colors = ['red', 'orange', 'yellow', 'lightgreen'] # Corresponding to High, Medium, Low, Informational

    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, colors=colors, labels=labels, autopct='%1.1f%%', startangle=90, wedgeprops=dict(width=0.3))
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title(title)

    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig1)
    buf.seek(0)
    return Image(buf)

def determine_severity(tool_name, finding):
    # This is a simplified heuristic for demonstration purposes.
    # A real-world scanner would use vulnerability databases and more complex rules.
    if tool_name == 'nmap':
        # Assuming any open port is a potential risk, especially common ones
        if 'ports' in finding:
            for port_info in finding['ports']:
                if port_info.get('state') == 'open':
                    # Example: High for common high-risk ports, Medium for others
                    if port_info.get('portid') in ['21', '23', '3389']: # FTP, Telnet, RDP
                        return 'High'
                    elif port_info.get('portid') in ['80', '443', '22']: # HTTP, HTTPS, SSH
                        return 'Medium' # Could be High if misconfigured, but Medium by default
            return 'Informational' # No open ports found
    elif tool_name == 'httpx':
        # Check for missing security headers (simplified)
        if 'headers' in finding:
            headers = finding['headers']
            missing_headers = []
            if 'Strict-Transport-Security' not in headers:
                missing_headers.append('HSTS')
            if 'X-Frame-Options' not in headers:
                missing_headers.append('X-Frame-Options')
            if 'Content-Security-Policy' not in headers:
                missing_headers.append('CSP')
            if missing_headers:
                return 'Medium' # Missing security headers
        return 'Informational'
    elif tool_name == 'theharvester':
        if 'emails' in finding and finding['emails']:
            return 'Low' # Exposed emails
        if 'hosts' in finding and finding['hosts']:
            return 'Informational' # Discovered hosts
    elif tool_name == 'dnsdumpster':
        if 'a' in finding and len(finding['a']) > 5: # Arbitrary: many A records
            return 'Low'
        if 'txt' in finding and finding['txt']:
            return 'Informational' # TXT records
    elif tool_name == 'sublist3r':
        if finding: # Presence of subdomains
            return 'Informational'
    elif tool_name == 'whatweb':
        if finding: # Presence of web technologies
            return 'Informational'
    elif tool_name == 'dnsenum':
        if finding: # Presence of DNS enumeration results
            return 'Informational'
    return 'Informational' # Default for anything not explicitly handled

def generate_report(domain, results):
    doc = SimpleDocTemplate(f"reports/report_{domain}.pdf")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"Security Scan Report for {domain}", styles['h1']))
    story.append(Spacer(1, 12))

    categorized_data = categorize_results(results)

    # --- Severity Overview ---
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    all_findings = []
    added_tools = set() # Keep track of tools already added to the summary table

    for category_name, category_content in categorized_data.items():
        for tool_name, tool_results in category_content.items():
            # Normalize tool_name for severity determination and unique tracking
            normalized_tool_name = tool_name.replace('_theharvester', '')

            if normalized_tool_name not in added_tools:
                severity = determine_severity(normalized_tool_name, tool_results)
                severity_counts[severity] += 1
                summary_details = str(tool_results)[:200] + '...' if len(str(tool_results)) > 200 else str(tool_results)
                all_findings.append([normalized_tool_name.replace('_', ' ').title(), severity, Paragraph(summary_details, styles['Normal'])])
                added_tools.add(normalized_tool_name)

    story.append(Paragraph("Severity Overview", styles['h2']))
    for severity_level, count in severity_counts.items():
        story.append(Paragraph(f"{severity_level}: {count}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Donut Chart
    if any(severity_counts.values()): # Only create chart if there are findings
        donut_chart = create_donut_chart(severity_counts, "Severity Distribution")
        story.append(donut_chart)
        story.append(Spacer(1, 12))

    # --- Color-Coded Summary Table ---
    story.append(Paragraph("Summary of Findings", styles['h2']))
    table_data = [['Tool', 'Severity', 'Details']]
    for finding in all_findings:
        table_data.append(finding)

    table = Table(table_data, colWidths=[1.5*inch, 1*inch, 4.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    # Apply color based on severity
    for i, row in enumerate(table_data):
        if i == 0: continue # Skip header
        severity = row[1]
        if severity == 'High':
            table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.red)]))
        elif severity == 'Medium':
            table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.orange)]))
        elif severity == 'Low':
            table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.yellow)]))
        elif severity == 'Informational':
            table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.lightgreen)]))
    story.append(table)
    story.append(Spacer(1, 12))

    # --- Categorized Findings ---
    story.append(Paragraph("Detailed Categorized Findings", styles['h2']))
    for category_name, category_content in categorized_data.items():
        if category_content: # Only add section if there's content
            story.append(Paragraph(category_name.replace('_', ' ').title(), styles['h3'])) # Changed to h3 for sub-section
            story.append(Preformatted(json.dumps(category_content, indent=4), styles['Code']))
            story.append(Spacer(1, 12))

    doc.build(story)
    print(f"Report generated: reports/report_{domain}.pdf")
