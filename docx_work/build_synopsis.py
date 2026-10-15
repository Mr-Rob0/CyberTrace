from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(r"C:\Users\YoursPookie\Desktop\Certifications\Smart_Traffic_Junction_Written_Synopsis (1).docx")
OUTPUT = ROOT / "Cyber_Incident_Investigation_Project_Synopsis.docx"


def set_cell_shading(cell, fill):
    props = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), fill)
    props.append(shading)


def set_cell_margins(cell, top=100, start=100, bottom=100, end=100):
    props = cell._tc.get_or_add_tcPr()
    margins = props.first_child_found_in("w:tcMar")
    if margins is None:
        margins = OxmlElement("w:tcMar")
        props.append(margins)
    for side, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = margins.find(qn(f"w:{side}"))
        if node is None:
            node = OxmlElement(f"w:{side}")
            margins.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_table_header(row):
    props = row._tr.get_or_add_trPr()
    marker = OxmlElement("w:tblHeader")
    marker.set(qn("w:val"), "true")
    props.append(marker)


def set_table_borders(table):
    props = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        border = OxmlElement(f"w:{edge}")
        border.set(qn("w:val"), "single")
        border.set(qn("w:sz"), "6")
        border.set(qn("w:space"), "0")
        border.set(qn("w:color"), "D9D9D9")
        borders.append(border)
    props.append(borders)


def add_table(doc, headers, rows, widths=None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.autofit = False
    set_table_borders(table)
    header = table.rows[0]
    set_repeat_table_header(header)
    for index, text in enumerate(headers):
        cell = header.cells[index]
        cell.text = text
        set_cell_shading(cell, "1F4E78")
        set_cell_margins(cell)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        for run in cell.paragraphs[0].runs:
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)
            run.font.size = Pt(9)
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        if widths:
            cell.width = Inches(widths[index])
    for row_index, values in enumerate(rows):
        cells = table.add_row().cells
        for index, value in enumerate(values):
            cell = cells[index]
            cell.text = str(value)
            set_cell_margins(cell)
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            if row_index % 2:
                set_cell_shading(cell, "EEF4F8")
            for para in cell.paragraphs:
                para.paragraph_format.space_after = Pt(0)
                for run in para.runs:
                    run.font.size = Pt(9)
            if index == 0 or (widths and widths[index] < 1.2):
                cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            if widths:
                cell.width = Inches(widths[index])
    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return table


def clear_document(doc):
    body = doc._element.body
    for child in list(body):
        if child.tag != qn("w:sectPr"):
            body.remove(child)


def add_heading(doc, text, level=1):
    paragraph = doc.add_paragraph(style=f"Heading {level}")
    paragraph.paragraph_format.space_before = Pt(8 if level == 1 else 5)
    paragraph.paragraph_format.space_after = Pt(6)
    paragraph.paragraph_format.keep_with_next = True
    run = paragraph.add_run(text)
    run.font.name = "Arial"
    run.font.color.rgb = RGBColor(0, 0, 0)
    run.font.bold = True
    run.font.size = Pt(14 if level == 1 else 11)
    return paragraph


def add_body(doc, text):
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.space_after = Pt(7)
    paragraph.paragraph_format.line_spacing = 1.12
    paragraph.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run = paragraph.add_run(text)
    run.font.name = "Arial"
    run.font.size = Pt(10.5)
    return paragraph


def add_bullets(doc, items):
    for item in items:
        paragraph = doc.add_paragraph()
        paragraph.paragraph_format.left_indent = Inches(0.26)
        paragraph.paragraph_format.first_line_indent = Inches(-0.16)
        paragraph.paragraph_format.space_after = Pt(3)
        paragraph.paragraph_format.line_spacing = 1.08
        run = paragraph.add_run("• " + item)
        run.font.name = "Arial"
        run.font.size = Pt(10.5)


def page_break(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def configure_document(doc):
    section = doc.sections[0]
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.7)
    section.top_margin = Inches(0.75)
    section.bottom_margin = Inches(0.7)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.text = "Cyber Incident Investigation Project Synopsis"
    for run in footer.runs:
        run.font.name = "Arial"
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor(90, 90, 90)
    styles = doc.styles
    styles["Normal"].font.name = "Arial"
    styles["Normal"].font.size = Pt(10.5)
    styles["Title"].font.name = "Arial"
    styles["Title"].font.size = Pt(20)
    styles["Title"].font.color.rgb = RGBColor(0, 0, 0)


def add_title(doc, text):
    paragraph = doc.add_paragraph(style="Title")
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_after = Pt(12)
    run = paragraph.add_run(text)
    run.font.bold = True
    run.font.color.rgb = RGBColor(0, 0, 0)


def build():
    doc = Document(REFERENCE)
    clear_document(doc)
    configure_document(doc)

    add_title(doc, "AI Assisted Cyber Incident Investigation System")
    add_body(doc, "The proposed system is a web-based cyber incident investigation platform. It reads security logs, identifies suspicious activity, connects related events, reconstructs the likely attack flow, and presents a clear investigation report for analysts.")
    add_heading(doc, "INDEX", 1)
    add_table(doc, ["S. No.", "Contents"], [
        ["1", "Notations and Nomenclature"], ["2", "Introduction"],
        ["3", "Literature Review and Feasibility Study"], ["4", "Methodology and Planning of Work"],
        ["5", "Facilities Required for Proposed Work"], ["6", "Benefits, Impact and Future Scope"],
        ["7", "References"],
    ], [0.8, 5.8])

    page_break(doc)
    add_heading(doc, "NOTATIONS AND NOMENCLATURE", 1)
    add_table(doc, ["Abbreviation", "Expansion"], [
        ["AI", "Artificial Intelligence"], ["API", "Application Programming Interface"],
        ["CSV", "Comma Separated Values"], ["IDS", "Intrusion Detection System"],
        ["IP", "Internet Protocol"], ["LLM", "Large Language Model"],
        ["ML", "Machine Learning"], ["MITRE ATT&CK", "Knowledge base of adversary tactics and techniques"],
        ["SOC", "Security Operations Center"], ["UI", "User Interface"],
    ], [1.7, 4.9])

    page_break(doc)
    add_heading(doc, "1. INTRODUCTION", 1)
    add_heading(doc, "1.1 Overview of the Project", 2)
    add_body(doc, "The proposed system helps an analyst investigate security incidents from log files. It changes raw log records into structured events, applies detection rules, finds related activity, and builds a probable attack chain. It also maps relevant activity to MITRE ATT&CK techniques, calculates an investigation priority, and produces a clear report with supporting evidence.")
    add_heading(doc, "1.2 Problem Definition", 2)
    add_body(doc, "Security logs can be large, scattered, and difficult to read. A single incident may involve repeated login failures, unusual access, privilege changes, sensitive file access, and data transfer. Manual analysis takes time and important links between events can be missed. The proposed system provides one workflow to collect, connect, and explain these findings.")
    add_heading(doc, "1.3 Objectives of the Project", 2)
    add_bullets(doc, [
        "Read and normalize security logs from CSV datasets.",
        "Detect common attack patterns using explainable security rules.",
        "Correlate related detections into incidents using time and shared entities.",
        "Reconstruct a probable attack chain with evidence event IDs.",
        "Map observed behavior to MITRE ATT&CK techniques.",
        "Provide anomaly observations, risk priority, defensive actions, and a report.",
    ])
    add_heading(doc, "1.4 Scope of the Project", 2)
    add_body(doc, "The project is a local academic prototype for studying security incident analysis. It supports selected attack scenarios such as brute-force login attempts, suspicious remote login, privilege escalation, sensitive file access, port scanning, and large outbound transfer. It does not replace a production SOC, endpoint agent, or live threat-intelligence platform.")
    add_heading(doc, "1.5 Technology to be Used", 2)
    add_bullets(doc, [
        "Python for the main analysis pipeline and supporting modules.",
        "Streamlit for the dashboard and analyst-facing interface.",
        "Pandas and NumPy for data preparation and analysis.",
        "Scikit-learn for statistical anomaly detection.",
        "NetworkX and Plotly for attack graphs and visualizations.",
        "MITRE ATT&CK mappings and structured report generation for investigation context.",
    ])

    page_break(doc)
    add_heading(doc, "2. LITERATURE REVIEW AND FEASIBILITY STUDY", 1)
    add_heading(doc, "2.1 Review of Existing Systems", 2)
    add_body(doc, "Security information and event management tools collect logs and raise alerts, while intrusion detection systems focus on suspicious behavior. Many commercial tools provide broad coverage, but they can be costly and may hide the reasoning behind a result. Academic work on log analysis, event correlation, attack graphs, and anomaly detection shows that combining these methods can improve investigation clarity when the evidence is kept traceable.")
    add_heading(doc, "2.2 Comparison of Existing Approaches", 2)
    add_table(doc, ["Approach", "Strength", "Limitation"], [
        ["Manual log review", "Flexible and analyst driven", "Slow and difficult for large datasets"],
        ["Rule based detection", "Clear and repeatable reasoning", "Can miss unknown attack patterns"],
        ["ML anomaly detection", "Finds unusual behavior", "Anomaly is not proof of an attack"],
        ["Commercial SIEM", "Wide integrations and mature features", "Often costly and complex for a small project"],
        ["Proposed system", "Combines rules, correlation, reconstruction, and evidence reports", "Designed as an academic prototype with limited input formats"],
    ], [1.55, 2.55, 2.5])
    add_heading(doc, "2.3 Feasibility Study", 2)
    add_body(doc, "Technically, the proposed system uses mature open-source Python libraries and sample security logs. The rule engine and reconstruction modules run locally, which keeps the setup simple for academic use. Economically, the project uses freely available libraries and does not require paid cloud services. Operationally, the dashboard gives users a guided investigation path from uploaded data to a report.")
    add_heading(doc, "2.4 Need and Significance of the Project", 2)
    add_body(doc, "The project demonstrates how a security analyst can move from raw logs to a supported explanation without losing event-level traceability. It is useful for learning incident response concepts, attack progression, evidence handling, and the careful use of AI-assisted reporting.")

    page_break(doc)
    add_heading(doc, "3. METHODOLOGY AND PLANNING OF WORK", 1)
    add_heading(doc, "3.1 System Architecture", 2)
    add_body(doc, "The system follows a staged pipeline. Security logs are parsed and normalized first. Deterministic rules and machine learning analyze the events. Related detections are grouped into incidents. The selected incident is then reconstructed into attack stages, mapped to MITRE ATT&CK, scored for response priority, and shown in an investigation report.")
    add_heading(doc, "3.2 Module Design", 2)
    add_bullets(doc, [
        "Log Parsing and Normalization: converts raw CSV records into a common event format.",
        "Detection Engine: identifies known patterns using rules R001 to R006.",
        "Correlation and Incident Detection: connects detections by time, IP address, user, and host.",
        "Attack Reconstruction: orders evidence into probable stages such as credential access and privilege escalation.",
        "MITRE and Anomaly Analysis: adds technique context and flags statistical outliers separately from rule detections.",
        "Response Planning and Reporting: presents priority, safeguards, what-if analysis, and an evidence-grounded report.",
    ])
    add_heading(doc, "3.3 Step by Step Approach", 2)
    add_bullets(doc, [
        "Collect sample security logs and define the normalized event schema.",
        "Implement and test the deterministic detection rules.",
        "Correlate detections and create incident objects with evidence IDs.",
        "Reconstruct attack chains and probable root-cause candidates.",
        "Add MITRE mapping, anomaly scoring, dashboard views, and report export.",
        "Validate normal and attack datasets through unit and workflow tests.",
    ])
    add_heading(doc, "3.4 Development Strategy and Timeline", 2)
    add_table(doc, ["Phase", "Activity", "Output"], [
        ["I", "Requirement analysis and dataset preparation", "Project plan and sample logs"],
        ["II", "Parsing, normalization, and rule detection", "Structured events and detections"],
        ["III", "Correlation and attack reconstruction", "Incidents and attack chains"],
        ["IV", "MITRE mapping, anomaly analysis, and reporting", "Analyst dashboard and reports"],
        ["V", "Response planning, testing, and documentation", "Final synopsis, tests, and demo"],
    ], [0.8, 3.5, 2.3])

    page_break(doc)
    add_heading(doc, "4. FACILITIES REQUIRED FOR PROPOSED WORK", 1)
    add_heading(doc, "4.1 Software Requirements", 2)
    add_table(doc, ["S. No.", "Software or Tool", "Purpose"], [
        ["1", "Python 3.10 or later", "Core development and analysis"],
        ["2", "Streamlit", "Web dashboard"],
        ["3", "Pandas, NumPy, scikit-learn", "Data handling and anomaly detection"],
        ["4", "NetworkX and Plotly", "Graph and chart visualization"],
        ["5", "Pytest", "Unit and workflow testing"],
        ["6", "Git and VS Code", "Version control and development"],
    ], [0.7, 2.4, 3.5])
    add_heading(doc, "4.2 Hardware Requirements", 2)
    add_table(doc, ["S. No.", "Item", "Specification", "Purpose"], [
        ["1", "Development system", "4 GB RAM or more", "Coding and local testing"],
        ["2", "Storage", "2 GB free space or more", "Source code, datasets, and reports"],
        ["3", "Internet connection", "Optional", "Package setup and documentation access"],
    ], [0.65, 1.6, 2.0, 2.35])
    add_heading(doc, "4.3 Other Facilities", 2)
    add_bullets(doc, [
        "Sample security log datasets for safe testing.",
        "A local Python environment with required packages.",
        "Basic knowledge of cybersecurity concepts and incident response.",
    ])

    page_break(doc)
    add_heading(doc, "5. BENEFITS IMPACT AND FUTURE SCOPE", 1)
    add_heading(doc, "5.1 Expected Benefits", 2)
    add_bullets(doc, [
        "Reduces the effort needed to review raw security logs.",
        "Keeps rule detections, attack stages, and reports connected to event evidence.",
        "Helps students understand the difference between observed facts and probable conclusions.",
        "Supports clearer investigation priority and defensive action planning.",
        "Provides a simple dashboard for demonstrating a complete incident workflow.",
    ])
    add_heading(doc, "5.2 Social and Technical Impact", 2)
    add_body(doc, "The proposed system supports cybersecurity learning by making technical incident data easier to understand. It encourages evidence-based thinking and avoids treating statistical anomalies as confirmed attacks. The project can be used as a lab demonstration for log analysis, attack reconstruction, and secure response planning.")
    add_heading(doc, "5.3 Future Scope", 2)
    add_bullets(doc, [
        "Support more log formats such as Windows Event Logs and Syslog files.",
        "Add role-based user access and case management.",
        "Integrate live log collection from selected security tools.",
        "Add more MITRE ATT&CK techniques and richer threat-intelligence context.",
        "Improve visual evidence exploration and export options.",
    ])

    page_break(doc)
    add_heading(doc, "6. REFERENCES", 1)
    add_bullets(doc, [
        "MITRE ATT&CK, Enterprise Matrix and technique documentation, https://attack.mitre.org/.",
        "Scikit-learn documentation, IsolationForest, https://scikit-learn.org/.",
        "Python Software Foundation, Python documentation, https://docs.python.org/.",
        "Streamlit documentation, https://docs.streamlit.io/.",
        "NIST Computer Security Incident Handling Guide, SP 800-61 Rev. 2.",
        "Cichonski, P. et al., Computer Security Incident Handling Guide, NIST, 2012.",
        "NetworkX documentation, https://networkx.org/.",
    ])

    doc.core_properties.title = "AI Assisted Cyber Incident Investigation System"
    doc.core_properties.subject = "Cyber incident investigation and reconstruction project synopsis"
    doc.core_properties.author = ""
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    build()
