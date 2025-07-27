

import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.colors import HexColor, black, white, red, orange, yellow, green
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from datetime import datetime
from reportlab.lib.units import inch

# Helper function to calculate scan duration
def calculate_scan_duration(start_time_str, end_time_str):
    try:
        start_time = datetime.fromisoformat(start_time_str)
        end_time = datetime.fromisoformat(end_time_str)
        duration = end_time - start_time
        hours, remainder = divmod(duration.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
    except ValueError:
        return "N/A"

# Helper function to get data counts for pie chart
def get_category_data_counts(data_dictionary):
    counts = {
        "DNS Records": len(data_dictionary.get("dns_records", {}).get("nameservers", [])) +
                       len(data_dictionary.get("dns_records", {}).get("mx_records", [])) +
                       len(data_dictionary.get("dns_records", {}).get("a_records", [])),
        "Open Ports": len(data_dictionary.get("open_ports", [])),
        "Subdomains & Hosts": len(data_dictionary.get("subdomains", [])),
        "Emails": len(data_dictionary.get("emails", [])),
        "Web Technologies": len(data_dictionary.get("web_technologies", [])),
        "Live Hosts": len(data_dictionary.get("live_hosts", []))
    }
    return {k: v for k, v in counts.items() if v > 0} # Only include categories with data

# Helper function to determine severity for summary table
def get_category_severity(category_name, data_count):
    if data_count == 0:
        return "Low" # No findings
    if category_name == "Open Ports":
        return "Critical" # Open ports are generally critical findings
    if category_name == "DNS Records":
        return "Medium" # Important network info
    return "Low" # Default for other categories with data

# Helper function to get a short summary for the summary table
def get_category_summary(category_name, data):
    if category_name == "DNS Records":
        ns_count = len(data.get("nameservers", []))
        mx_count = len(data.get("mx_records", []))
        a_count = len(data.get("a_records", []))
        return f"Found {ns_count} nameservers, {mx_count} MX records, {a_count} A records."
    elif category_name == "Open Ports":
        return f"Found {len(data)} open ports."
    elif category_name == "Subdomains & Hosts":
        return f"Found {len(data)} subdomains."
    elif category_name == "Emails":
        return f"Found {len(data)} email addresses."
    elif category_name == "Web Technologies":
        return f"Identified {len(data)} web technologies."
    elif category_name == "Live Hosts":
        return f"Found {len(data)} live hosts."
    return "No specific summary available."

# Page template for footer
def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 9)
    canvas.drawString(inch, 0.75 * inch, f"Page {doc.page}")
    canvas.drawString(doc.width - inch, 0.75 * inch, datetime.now().strftime("%Y-%m-%d"))
    canvas.restoreState()

def generate_report(domain, data_dictionary_path, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Custom styles
    styles.add(ParagraphStyle(name='ReportTitle', fontSize=24, leading=28, alignment=TA_CENTER,
                              fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SectionTitle', fontSize=18, leading=22, spaceAfter=12,
                              fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SubSectionTitle', fontSize=14, leading=18, spaceAfter=8,
                               fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='Normal', fontSize=10, leading=12))
    styles.add(ParagraphStyle(name='ListItem', fontSize=10, leading=12, leftIndent=20))

    try:
        with open(data_dictionary_path, 'r') as f:
            data_dictionary = json.load(f)
    except FileNotFoundError:
        story.append(Paragraph(f"Error: Data dictionary not found at {data_dictionary_path}", styles['Normal']))
        doc.build(story)
        return
    except json.JSONDecodeError:
        story.append(Paragraph(f"Error: Could not decode JSON from {data_dictionary_path}", styles['Normal']))
        doc.build(story)
        return

    scan_info = data_dictionary.get("scan_info", {})
    target_domain = scan_info.get("domain", domain)
    start_time_str = scan_info.get("start_time", "")
    end_time_str = scan_info.get("end_time", "")
    scan_duration = calculate_scan_duration(start_time_str, end_time_str)

    # --- FIRST PAGE: Main Header and Pie Chart ---
    story.append(Paragraph(f"Reconnaissance Report for {target_domain}", styles['ReportTitle']))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Prepared by: Automated Recon Tool", styles['Normal']))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']))
    story.append(Paragraph(f"Scan Duration: {scan_duration}", styles['Normal']))
    story.append(Spacer(1, 0.5 * inch))

    # Pie Chart
    data_counts = get_category_data_counts(data_dictionary)
    if data_counts:
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 50
        pie.y = 0
        pie.height = 180
        pie.width = 180
        pie.data = list(data_counts.values())
        pie.labels = [f"{k} ({v})" for k, v in data_counts.items()]
        
        # Assign distinct colors
        colors = [
            HexColor('#FF6347'), # Tomato
            HexColor('#FFD700'), # Gold
            HexColor('#ADFF2F'), # GreenYellow
            HexColor('#6495ED'), # CornflowerBlue
            HexColor('#DA70D6'), # Orchid
            HexColor('#FFA07A')  # LightSalmon
        ]
        pie.slices.strokeWidth = 0.5
        for i, color in enumerate(colors):
            if i < len(pie.slices):
                pie.slices[i].fillColor = color

        drawing.add(pie)
        story.append(drawing)
        story.append(Spacer(1, 0.2 * inch))
    else:
        story.append(Paragraph("No data available for pie chart.", styles['Normal']))

    story.append(PageBreak())

    # --- PAGE 2: Summary Table (Key Findings) ---
    story.append(Paragraph("Summary Table (Key Findings)", styles['SectionTitle']))
    story.append(Spacer(1, 0.2 * inch))

    summary_data = [['Category', 'Key Findings (short summary)', 'Data Count']]
    category_order = ["DNS Records", "Open Ports", "Subdomains & Hosts", "Emails", "Web Technologies", "Live Hosts"]

    for category in category_order:
        data_count = 0
        category_data = {}
        if category == "DNS Records":
            category_data = data_dictionary.get("dns_records", {})
            data_count = len(category_data.get("nameservers", [])) + len(category_data.get("mx_records", [])) + len(category_data.get("a_records", []))
        elif category == "Open Ports":
            category_data = data_dictionary.get("open_ports", [])
            data_count = len(category_data)
        elif category == "Subdomains & Hosts":
            category_data = data_dictionary.get("subdomains", [])
            data_count = len(category_data)
        elif category == "Emails":
            category_data = data_dictionary.get("emails", [])
            data_count = len(category_data)
        elif category == "Web Technologies":
            category_data = data_dictionary.get("web_technologies", [])
            data_count = len(category_data)
        elif category == "Live Hosts":
            category_data = data_dictionary.get("live_hosts", [])
            data_count = len(category_data)
        
        severity = get_category_severity(category, data_count)
        summary = get_category_summary(category, category_data)
        summary_data.append([category, summary, str(data_count)])

    table = Table(summary_data, colWidths=[2*inch, 4*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#D3D3D3')), # Header background
        ('TEXTCOLOR', (0, 0), (-1, 0), black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, black), # All borders
    ]))

    # Apply row colors based on severity and alternating colors
    for i, row in enumerate(summary_data[1:]): # Skip header row
        row_idx = i + 1
        category_name = row[0]
        data_count = int(row[2])
        severity = get_category_severity(category_name, data_count)
        
        bg_color = white
        if severity == "Critical":
            bg_color = red
        elif severity == "High":
            bg_color = orange
        elif severity == "Medium":
            bg_color = yellow
        elif severity == "Low":
            bg_color = green
        
        # Alternating row colors
        if row_idx % 2 == 0:
            bg_color = HexColor('#F0F0F0') # Light gray for even rows
            if severity == "Critical": bg_color = HexColor('#FFCCCC') # Lighter red
            elif severity == "High": bg_color = HexColor('#FFEBCC') # Lighter orange
            elif severity == "Medium": bg_color = HexColor('#FFFFCC') # Lighter yellow
            elif severity == "Low": bg_color = HexColor('#E6FFE6') # Lighter green
        
        table.setStyle(TableStyle([('BACKGROUND', (0, row_idx), (-1, row_idx), bg_color)]))
        table.setStyle(TableStyle([('TEXTCOLOR', (0, row_idx), (-1, row_idx), black)])) # Ensure text is black

    story.append(table)
    story.append(PageBreak())

    # --- Detailed Sections (One Per Category) ---
    story.append(Paragraph("Detailed Sections", styles['SectionTitle']))
    story.append(Spacer(1, 0.2 * inch))

    # 4.1 Network & DNS Info
    story.append(Paragraph("4.1 Network & DNS Info", styles['SubSectionTitle']))
    dns_records = data_dictionary.get("dns_records", {})
    if dns_records:
        story.append(Paragraph("DNS Records:", styles['Normal']))
        if dns_records.get("nameservers"):
            story.append(Paragraph("Nameservers:", styles['ListItem']))
            for ns in dns_records["nameservers"]:
                story.append(Paragraph(f"- {ns}", styles['ListItem']))
        if dns_records.get("mx_records"):
            story.append(Paragraph("MX Records:", styles['ListItem']))
            for mx in dns_records["mx_records"]:
                story.append(Paragraph(f"- {mx}", styles['ListItem']))
        if dns_records.get("a_records"):
            story.append(Paragraph("A Records:", styles['ListItem']))
            for a_rec in dns_records["a_records"]:
                story.append(Paragraph(f"- {a_rec}", styles['ListItem']))
    else:
        story.append(Paragraph("No DNS records found.", styles['Normal']))

    open_ports = data_dictionary.get("open_ports", [])
    if open_ports:
        story.append(Paragraph("Open Ports:", styles['Normal']))
        for port_info in open_ports:
            story.append(Paragraph(f"- {port_info.get('port')}/{port_info.get('protocol')} - {port_info.get('service')} {port_info.get('version', '')}", styles['ListItem']))
    else:
        story.append(Paragraph("No open ports found.", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # 4.2 Subdomains & Hosts
    story.append(Paragraph("4.2 Subdomains & Hosts", styles['SubSectionTitle']))
    subdomains = data_dictionary.get("subdomains", [])
    story.append(Paragraph(f"Total found: {len(subdomains)}", styles['Normal']))
    if subdomains:
        story.append(Paragraph("Sample subdomains:", styles['Normal']))
        for i, subdomain in enumerate(subdomains[:10]): # List up to 10 samples
            story.append(Paragraph(f"- {subdomain}", styles['ListItem']))
    else:
        story.append(Paragraph("No subdomains found.", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # 4.3 Emails
    story.append(Paragraph("4.3 Emails", styles['SubSectionTitle']))
    emails = data_dictionary.get("emails", [])
    if emails:
        for email in emails:
            story.append(Paragraph(f"- {email}", styles['ListItem']))
    else:
        story.append(Paragraph("No emails found.", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # 4.4 Web Technologies
    story.append(Paragraph("4.4 Web Technologies", styles['SubSectionTitle']))
    web_technologies = data_dictionary.get("web_technologies", [])
    if web_technologies:
        for tech in web_technologies:
            story.append(Paragraph(f"- Name: {tech.get('name', 'N/A')}", styles['ListItem']))
            if tech.get('version'):
                story.append(Paragraph(f"  Version: {tech.get('version')}", styles['ListItem']))
            if tech.get('categories'):
                story.append(Paragraph(f"  Categories: {', '.join(tech.get('categories'))}", styles['ListItem']))
    else:
        story.append(Paragraph("No web technologies found.", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # 4.5 Live Hosts
    story.append(Paragraph("4.5 Live Hosts", styles['SubSectionTitle']))
    live_hosts = data_dictionary.get("live_hosts", [])
    if live_hosts:
        for host in live_hosts:
            story.append(Paragraph(f"- Subdomain: {host.get('subdomain', 'N/A')}", styles['ListItem']))
            story.append(Paragraph(f"  Protocol: {host.get('protocol', 'N/A')}", styles['ListItem']))
    else:
        story.append(Paragraph("No live hosts found.", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))

    # Build the PDF
    doc.build(story, onFirstPage=footer, onLaterPages=footer)

if __name__ == '__main__':
    # Example usage (replace with actual domain and paths)
    # This part will not be executed by the agent, but is for context.
    # You would call generate_report from another script, e.g., scanner.py
    # generate_report("example.com", "reports/data_dictionary_example.com.json", "reports/report_example.com.pdf")
    pass
