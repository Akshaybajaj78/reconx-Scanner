from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table


def generate_report(
    output_path: str,
    target: str,
    open_ports: list,
    vulnerabilities: list,
    discovered_paths: list,
    subdomains: list,
    possible_attacks: list,
):
    """
    Generate a professional PDF report.
    """
    doc = SimpleDocTemplate(output_path, pagesize=LETTER)
    styles = getSampleStyleSheet()

    story = []
    story.append(Paragraph("ReconX CLI Report", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"Target: {target}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Summary", styles["Heading2"]))
    summary_text = f"Open Ports: {len(open_ports)} | Vulnerabilities: {len(vulnerabilities)} | Paths: {len(discovered_paths)} | Subdomains: {len(subdomains)}"
    story.append(Paragraph(summary_text, styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Open Ports", styles["Heading2"]))
    story.append(_list_table(open_ports))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Discovered Subdomains", styles["Heading2"]))
    story.append(_list_table(subdomains))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Discovered Paths", styles["Heading2"]))
    story.append(_list_table(discovered_paths))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Vulnerabilities", styles["Heading2"]))
    story.append(_list_table(vulnerabilities))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Potential Attack Areas (Not Tested)", styles["Heading2"]))
    story.append(_list_table(possible_attacks))

    doc.build(story)


def _list_table(items: list):
    if not items:
        return Paragraph("None found.", getSampleStyleSheet()["Normal"])

    data = [[item] for item in items]
    table = Table(data, colWidths=[500])
    return table
