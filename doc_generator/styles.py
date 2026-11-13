import re
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def clean_xml(text):
    if text is None:
        return ""
    return re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', str(text))

NAVY_HEX = "1B365D"
TEAL_HEX = "2B5B6E"
CHARCOAL_HEX = "222222"
MUTED_HEX = "555555"
AMBER_HEX = "D97706"
CRIMSON_HEX = "B91C1C"
EMERALD_HEX = "047857"
ICE_BLUE_HEX = "F0F4F8"
LIGHT_GREY_HEX = "F3F4F6"
BORDER_GREY_HEX = "D1D5DB"

def setup_document():
    doc = docx.Document()
    
    # Page setup
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)
        
        # Header & Footer
        header = section.header
        hp = header.paragraphs[0]
        hp.text = "ThreatLens / SentinelAI — Complete Technical Project Study & Interview Guide"
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hp.style.font.name = "Calibri"
        hp.style.font.size = Pt(8.5)
        hp.style.font.color.rgb = RGBColor(120, 120, 120)
        
        footer = section.footer
        fp = footer.paragraphs[0]
        fp.text = "Confidential & Proprietary — Cyber Security & Application Security Engineering Preparation"
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fp.style.font.name = "Calibri"
        fp.style.font.size = Pt(8.5)
        fp.style.font.color.rgb = RGBColor(140, 140, 140)

    # Base Normal style
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Calibri'
    style_normal.font.size = Pt(10.5)
    style_normal.font.color.rgb = RGBColor(34, 34, 34)
    style_normal.paragraph_format.line_spacing = 1.15
    style_normal.paragraph_format.space_after = Pt(4)
    
    return doc

def add_cover_page(doc):
    # Top spacing
    for _ in range(3):
        doc.add_paragraph()
        
    p_badge = doc.add_paragraph()
    run_badge = p_badge.add_run("CYBERSECURITY & APPLICATION SECURITY ENGINEERING MASTER STUDY GUIDE")
    run_badge.font.name = "Calibri"
    run_badge.font.size = Pt(10)
    run_badge.font.bold = True
    run_badge.font.color.rgb = RGBColor(27, 54, 93)
    p_badge.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    p_title = doc.add_paragraph()
    run_title = p_title.add_run("THREATLENS / SENTINELAI")
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(28)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(27, 54, 93)
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(8)
    
    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run("Ocular Client-Side Web Vulnerability Scanner, Browser Extension Privilege Auditor & Real-Time Security Intelligence Suite")
    run_sub.font.name = "Calibri"
    run_sub.font.size = Pt(14)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(43, 91, 110)
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(24)
    
    # Metadata Box
    tbl = doc.add_table(rows=6, cols=2)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta = [
        ("Candidate Name / Author:", "Pallavi Mahajan"),
        ("Target Roles:", "Cybersecurity Analyst, SOC Analyst (L1/L2), AppSec Engineer, Security Engineer, DevSecOps"),
        ("Project Repository:", "https://github.com/pallavimahajan369/ThreatLens_MadDoG (level-1)"),
        ("Architecture:", "Google Chrome Manifest V3, Pure ES6+ JavaScript, Google Gemini AI (REST)"),
        ("Document Version & Scope:", "Version 2.0 — Complete Technical Audit, 23-Phase Roadmap & 100+ Q&A Bank"),
        ("Classification:", "Comprehensive Technical Interview Preparation & Project Examination Master Guide")
    ]
    for i, (k, v) in enumerate(meta):
        row = tbl.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(2.2)
        c1.width = Inches(4.5)
        
        p0 = c0.paragraphs[0]
        r0 = p0.add_run(k)
        r0.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = RGBColor(27, 54, 93)
        
        p1 = c1.paragraphs[0]
        r1 = p1.add_run(v)
        r1.font.size = Pt(9.5)
        r1.font.color.rgb = RGBColor(50, 50, 50)
        
        # cell shading
        for cell in (c0, c1):
            tcPr = cell._element.get_or_add_tcPr()
            shd = parse_xml(r'<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" w:fill="F8F9FA"/>')
            tcPr.append(shd)
            borders = parse_xml(r'''
                <w:tcBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                    <w:top w:val="single" w:sz="4" w:space="0" w:color="E5E7EB"/>
                    <w:left w:val="none"/>
                    <w:bottom w:val="single" w:sz="4" w:space="0" w:color="E5E7EB"/>
                    <w:right w:val="none"/>
                </w:tcBorders>
            ''')
            tcPr.append(borders)
            
    for _ in range(4):
        doc.add_paragraph()
        
    p_foot = doc.add_paragraph()
    r_foot = p_foot.add_run("Strict Quality Standards Applied: Verified against Live Project Source Code, OWASP Top 10, CWE, MITRE ATT&CK, NIST CVSS v3.1, Chrome MV3 Security Best Practices.")
    r_foot.font.size = Pt(9)
    r_foot.font.italic = True
    r_foot.font.color.rgb = RGBColor(120, 120, 120)
    p_foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    doc.add_page_break()

def add_heading_1(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = 'Calibri'
    run.font.size = Pt(17)
    run.font.bold = True
    run.font.color.rgb = RGBColor(27, 54, 93)
    return p

def add_heading_2(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = 'Calibri'
    run.font.size = Pt(13)
    run.font.bold = True
    run.font.color.rgb = RGBColor(43, 91, 110)
    return p

def add_heading_3(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = 'Calibri'
    run.font.size = Pt(11)
    run.font.bold = True
    run.font.color.rgb = RGBColor(34, 34, 34)
    return p

def add_paragraph(doc, text, bold_prefix=None, italic=False):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.15
    if bold_prefix:
        r_pre = p.add_run(clean_xml(bold_prefix))
        r_pre.bold = True
        r_pre.font.color.rgb = RGBColor(27, 54, 93)
    run = p.add_run(clean_xml(text))
    run.italic = italic
    run.font.color.rgb = RGBColor(40, 40, 40)
    return p

def add_bullet(doc, text, bold_prefix=None):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.15
    if bold_prefix:
        r_pre = p.add_run(clean_xml(bold_prefix))
        r_pre.bold = True
        r_pre.font.color.rgb = RGBColor(27, 54, 93)
    run = p.add_run(clean_xml(text))
    run.font.color.rgb = RGBColor(40, 40, 40)
    return p

def add_callout(doc, text, title=None, alert_type="NOTE"):
    border_color = NAVY_HEX
    bg_color = ICE_BLUE_HEX
    title_color = RGBColor(27, 54, 93)
    icon = "[NOTE]"
    
    if alert_type == "IMPORTANT":
        border_color = TEAL_HEX
        bg_color = "EDF8F9"
        title_color = RGBColor(43, 91, 110)
        icon = "[IMPORTANT]"
    elif alert_type == "WARNING":
        border_color = AMBER_HEX
        bg_color = "FEF9C3"
        title_color = RGBColor(180, 83, 9)
        icon = "[WARNING]"
    elif alert_type == "CAUTION" or alert_type == "SECURITY":
        border_color = CRIMSON_HEX
        bg_color = "FEE2E2"
        title_color = RGBColor(185, 28, 28)
        icon = "[SECURITY FOCUS]"
    elif alert_type == "TIP":
        border_color = EMERALD_HEX
        bg_color = "ECFDF5"
        title_color = RGBColor(4, 120, 87)
        icon = "[PRO TIP]"
    elif alert_type == "HINGLISH":
        border_color = "7C3AED"
        bg_color = "F5F3FF"
        title_color = RGBColor(124, 58, 237)
        icon = "[HINGLISH EXPLANATION FOR EASY LEARNING]"

    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.8)
    
    tcPr = cell._element.get_or_add_tcPr()
    tcBorders = parse_xml(f'''
        <w:tcBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:top w:val="none"/>
            <w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/>
            <w:bottom w:val="none"/>
            <w:right w:val="none"/>
        </w:tcBorders>
    ''')
    tcPr.append(tcBorders)
    shd = parse_xml(f'<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" w:fill="{bg_color}"/>')
    tcPr.append(shd)
    
    # Internal margins
    tcMar = parse_xml(r'''
        <w:tcMar xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:top w:w="120" w:type="dxa"/>
            <w:left w:w="160" w:type="dxa"/>
            <w:bottom w:w="120" w:type="dxa"/>
            <w:right w:w="160" w:type="dxa"/>
        </w:tcMar>
    ''')
    tcPr.append(tcMar)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.15
    
    r_hdr = p.add_run(clean_xml(f"{icon} {title}\n" if title else f"{icon}\n"))
    r_hdr.bold = True
    r_hdr.font.size = Pt(10)
    r_hdr.font.color.rgb = title_color
    
    r_txt = p.add_run(clean_xml(text))
    r_txt.font.size = Pt(9.5)
    r_txt.font.color.rgb = RGBColor(34, 34, 34)
    
    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_after = Pt(2)

def add_code_block(doc, code, language="JavaScript"):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.8)
    
    tcPr = cell._element.get_or_add_tcPr()
    borders = parse_xml(f'''
        <w:tcBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:top w:val="single" w:sz="6" w:space="0" w:color="{BORDER_GREY_HEX}"/>
            <w:left w:val="single" w:sz="18" w:space="0" w:color="{NAVY_HEX}"/>
            <w:bottom w:val="single" w:sz="6" w:space="0" w:color="{BORDER_GREY_HEX}"/>
            <w:right w:val="single" w:sz="6" w:space="0" w:color="{BORDER_GREY_HEX}"/>
        </w:tcBorders>
    ''')
    tcPr.append(borders)
    shd = parse_xml(f'<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" w:fill="{LIGHT_GREY_HEX}"/>')
    tcPr.append(shd)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.05
    
    run_lang = p.add_run(clean_xml(f"// --- Code Snippet ({language}) ---\n"))
    run_lang.font.name = "Consolas"
    run_lang.font.size = Pt(8.5)
    run_lang.font.bold = True
    run_lang.font.color.rgb = RGBColor(100, 100, 100)
    
    run_code = p.add_run(clean_xml(code.strip()))
    run_code.font.name = "Consolas"
    run_code.font.size = Pt(8.5)
    run_code.font.color.rgb = RGBColor(20, 20, 20)
    
    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_after = Pt(2)

def create_styled_table(doc, headers, data, col_widths=None):
    rows_count = len(data) + 1
    cols_count = len(headers)
    table = doc.add_table(rows=rows_count, cols=cols_count)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    # Header Row
    header_tr = table.rows[0]
    for col_idx, h_text in enumerate(headers):
        cell = header_tr.cells[col_idx]
        if col_widths and col_idx < len(col_widths):
            cell.width = Inches(col_widths[col_idx])
            
        tcPr = cell._element.get_or_add_tcPr()
        shd = parse_xml(f'<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" w:fill="{NAVY_HEX}"/>')
        tcPr.append(shd)
        
        tcMar = parse_xml(r'''
            <w:tcMar xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                <w:top w:w="120" w:type="dxa"/>
                <w:left w:w="120" w:type="dxa"/>
                <w:bottom w:w="120" w:type="dxa"/>
                <w:right w:w="120" w:type="dxa"/>
            </w:tcMar>
        ''')
        tcPr.append(tcMar)
        
        borders = parse_xml(f'''
            <w:tcBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                <w:top w:val="single" w:sz="6" w:space="0" w:color="{NAVY_HEX}"/>
                <w:left w:val="none"/>
                <w:bottom w:val="single" w:sz="12" w:space="0" w:color="{NAVY_HEX}"/>
                <w:right w:val="none"/>
            </w:tcBorders>
        ''')
        tcPr.append(borders)
        
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run(clean_xml(h_text))
        run.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(255, 255, 255)
        
    # Data Rows
    for row_idx, row_data in enumerate(data):
        row_tr = table.rows[row_idx + 1]
        bg = "FFFFFF" if row_idx % 2 == 0 else "F9FAFB"
        for col_idx, val in enumerate(row_data):
            cell = row_tr.cells[col_idx]
            if col_widths and col_idx < len(col_widths):
                cell.width = Inches(col_widths[col_idx])
                
            tcPr = cell._element.get_or_add_tcPr()
            shd = parse_xml(f'<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" w:fill="{bg}"/>')
            tcPr.append(shd)
            
            tcMar = parse_xml(r'''
                <w:tcMar xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                    <w:top w:w="80" w:type="dxa"/>
                    <w:left w:w="100" w:type="dxa"/>
                    <w:bottom w:w="80" w:type="dxa"/>
                    <w:right w:w="100" w:type="dxa"/>
                </w:tcMar>
            ''')
            tcPr.append(tcMar)
            
            borders = parse_xml(f'''
                <w:tcBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                    <w:top w:val="single" w:sz="4" w:space="0" w:color="E5E7EB"/>
                    <w:left w:val="none"/>
                    <w:bottom w:val="single" w:sz="4" w:space="0" w:color="E5E7EB"/>
                    <w:right w:val="none"/>
                </w:tcBorders>
            ''')
            tcPr.append(borders)
            
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.line_spacing = 1.1
            run = p.add_run(clean_xml(str(val)))
            run.font.size = Pt(8.5)
            run.font.color.rgb = RGBColor(34, 34, 34)
            
    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_after = Pt(4)
    return table
