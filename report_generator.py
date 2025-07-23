
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import json

def generate_report(domain, results):
    doc = SimpleDocTemplate(f"reports/report_{domain}.pdf")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"Security Scan Report for {domain}", styles['h1']))
    story.append(Spacer(1, 12))

    for key, value in results.items():
        story.append(Paragraph(key.capitalize(), styles['h2']))
        story.append(Paragraph(json.dumps(value, indent=4), styles['Code']))
        story.append(Spacer(1, 12))

    doc.build(story)
    print(f"Report generated: reports/report_{domain}.pdf")
