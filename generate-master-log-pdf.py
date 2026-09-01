#!/usr/bin/env python3
"""Generate PDF of MASTER-SECURITY-LOG.md using reportlab."""

import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, Preformatted, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus.flowables import BalancedColumns

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error_guard.py)
try:
    import pathlib as _pathlib, sys as _sys
    _d = _pathlib.Path(__file__).resolve().parent
    for _ in range(6):
        if (_d / "lib" / "error_guard.py").exists():
            _sys.path.insert(0, str(_d / "lib"))
            break
        _d = _d.parent
    from error_guard import guard_run, guarded, SKIP, throw, GuardError
except ImportError:
    SKIP = object()
    def guard_run(_l, fn, *a, **kw): return fn(*a, **kw)
    def guarded(_l=None):
        def deco(fn): return fn
        return deco
    class GuardError(RuntimeError): pass
    def throw(msg): raise GuardError(str(msg))

SRC = '/Users/evw/dev/security/MASTER-SECURITY-LOG.md'
OUT = '/Users/evw/dev/security/MASTER-SECURITY-LOG.pdf'

doc = SimpleDocTemplate(
    OUT,
    pagesize=letter,
    leftMargin=0.75*inch,
    rightMargin=0.75*inch,
    topMargin=0.75*inch,
    bottomMargin=0.75*inch,
    title='Master Security Log — evw MacBook Pro',
    author='evw + Claude Sonnet 4.6',
)

styles = getSampleStyleSheet()

H1  = ParagraphStyle('H1',  parent=styles['Heading1'], fontSize=18, spaceAfter=6,  spaceBefore=4,  textColor=colors.HexColor('#1a1a2e'), leading=22)
H2  = ParagraphStyle('H2',  parent=styles['Heading2'], fontSize=13, spaceAfter=4,  spaceBefore=14, textColor=colors.HexColor('#16213e'), leading=17, borderPad=2)
H3  = ParagraphStyle('H3',  parent=styles['Heading3'], fontSize=10, spaceAfter=3,  spaceBefore=8,  textColor=colors.HexColor('#0f3460'), leading=13)
BODY = ParagraphStyle('Body', parent=styles['Normal'], fontSize=8.5, spaceAfter=3, leading=12.5)
MONO = ParagraphStyle('Mono', parent=styles['Code'],   fontSize=7,   spaceAfter=2, fontName='Courier',
                      leading=10, backColor=colors.HexColor('#f5f5f5'), leftIndent=6, rightIndent=6)
BULLET = ParagraphStyle('Bullet', parent=BODY, leftIndent=14, firstLineIndent=-8, spaceAfter=2)
CAPTION = ParagraphStyle('Caption', parent=styles['Normal'], fontSize=7.5,
                          textColor=colors.grey, spaceAfter=2)
TH = ParagraphStyle('TH', parent=styles['Normal'], fontSize=7.5, fontName='Helvetica-Bold',
                    textColor=colors.white, leading=10)
TD = ParagraphStyle('TD', parent=styles['Normal'], fontSize=7.5, leading=10)
BOLD = ParagraphStyle('Bold', parent=BODY, fontName='Helvetica-Bold')

ACCENT_DARK  = colors.HexColor('#2c3e50')
ACCENT_RED   = colors.HexColor('#c0392b')
ACCENT_GREEN = colors.HexColor('#27ae60')
ACCENT_WARN  = colors.HexColor('#e67e22')
ROW_ALT      = colors.HexColor('#f7f9fa')
GRID_COLOR   = colors.HexColor('#d5d8dc')

def hr():
    return HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#bbbbbb'),
                      spaceAfter=4, spaceBefore=4)

def escape(text):
    """Escape XML special chars for reportlab Paragraph."""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def inline_fmt(text):
    """Convert inline markdown (**bold**, `code`) to reportlab XML."""
    text = escape(text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'\*(.+?)\*',     r'<i>\1</i>', text)
    text = re.sub(r'`(.+?)`',       r'<font face="Courier" size="7.5">\1</font>', text)
    return text

def make_table(header_row, data_rows, col_hint=None):
    """Render a markdown pipe table."""
    all_rows = [header_row] + data_rows
    n_cols = len(header_row)
    # Default column widths
    page_w = 7.0 * inch
    if col_hint and len(col_hint) == n_cols:
        col_widths = [c * inch for c in col_hint]
    else:
        col_widths = [page_w / n_cols] * n_cols

    table_data = []
    for i, row in enumerate(all_rows):
        cells = []
        style = TH if i == 0 else TD
        for cell in row:
            cells.append(Paragraph(inline_fmt(cell.strip()), style))
        table_data.append(cells)

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    ts = TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  ACCENT_DARK),
        ('TEXTCOLOR',    (0,0), (-1,0),  colors.white),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,-1), 7.5),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [ROW_ALT, colors.white]),
        ('GRID',         (0,0), (-1,-1), 0.4, GRID_COLOR),
        ('LEFTPADDING',  (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING',   (0,0), (-1,-1), 3),
        ('BOTTOMPADDING',(0,0), (-1,-1), 3),
        ('VALIGN',       (0,0), (-1,-1), 'TOP'),
    ])
    # Color status cells
    for i, row in enumerate(data_rows, start=1):
        for j, cell in enumerate(row):
            cell_str = cell.strip()
            if any(x in cell_str for x in ['✅', '✓', 'CLEAN', 'green', 'holds', 'Enabled', 'active', 'intact']):
                ts.add('BACKGROUND', (j,i), (j,i), colors.HexColor('#d5f5e3'))
            elif any(x in cell_str for x in ['⚠️', '⚠', 'PENDING', 'yellow', 'OPEN']):
                ts.add('BACKGROUND', (j,i), (j,i), colors.HexColor('#fef9e7'))
            elif any(x in cell_str for x in ['❌', '✗', 'MISSING', 'BROKEN', 'reset', 'REGRESSION', 'absent']):
                ts.add('BACKGROUND', (j,i), (j,i), colors.HexColor('#fadbd8'))
    t.setStyle(ts)
    return t

def parse_md(path):
    """Parse markdown into reportlab flowables."""
    story = []
    with open(path) as f:
        lines = f.readlines()

    i = 0
    in_code = False
    code_lines = []
    in_table = False
    table_header = []
    table_rows = []

    def flush_table():
        nonlocal in_table, table_header, table_rows
        if table_header:
            story.append(Spacer(1, 0.04*inch))
            story.append(make_table(table_header, table_rows))
            story.append(Spacer(1, 0.06*inch))
        in_table = False
        table_header = []
        table_rows = []

    while i < len(lines):
        raw = lines[i].rstrip('\n')
        stripped = raw.strip()

        # Code block toggle
        if stripped.startswith('```'):
            if not in_code:
                in_code = True
                code_lines = []
            else:
                in_code = False
                if in_table: flush_table()
                txt = '\n'.join(code_lines)
                # Wrap long lines
                wrapped = []
                for ln in txt.split('\n'):
                    while len(ln) > 100:
                        wrapped.append(ln[:100])
                        ln = '  ' + ln[100:]
                    wrapped.append(ln)
                story.append(Preformatted('\n'.join(wrapped), MONO))
                story.append(Spacer(1, 0.04*inch))
            i += 1
            continue

        if in_code:
            code_lines.append(raw)
            i += 1
            continue

        # Table rows
        if stripped.startswith('|'):
            cells = [c for c in stripped.split('|') if c.strip() != '']
            # Skip separator rows (--|--|--)
            if all(re.match(r'^[-: ]+$', c.strip()) for c in cells):
                i += 1
                continue
            if not in_table:
                in_table = True
                table_header = cells
                table_rows = []
            else:
                table_rows.append(cells)
            i += 1
            continue
        elif in_table:
            flush_table()

        # Blank line
        if not stripped:
            story.append(Spacer(1, 0.05*inch))
            i += 1
            continue

        # Headings
        m = re.match(r'^(#{1,3})\s+(.*)', stripped)
        if m:
            level = len(m.group(1))
            text = inline_fmt(m.group(2))
            if level == 1:
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph(text, H1))
                story.append(hr())
            elif level == 2:
                story.append(Spacer(1, 0.08*inch))
                # Shaded header bar
                t = Table([[Paragraph(text, ParagraphStyle('H2T', parent=H2,
                                     textColor=colors.white, spaceBefore=0, spaceAfter=0))]],
                          colWidths=[7.0*inch])
                t.setStyle(TableStyle([
                    ('BACKGROUND',  (0,0), (-1,-1), ACCENT_DARK),
                    ('LEFTPADDING', (0,0), (-1,-1), 8),
                    ('TOPPADDING',  (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING',(0,0),(-1,-1), 4),
                ]))
                story.append(t)
                story.append(Spacer(1, 0.04*inch))
            else:
                story.append(Paragraph(text, H3))
            i += 1
            continue

        # HR ---
        if re.match(r'^-{3,}$', stripped):
            story.append(hr())
            i += 1
            continue

        # Bullet list
        m = re.match(r'^[-*]\s+(.*)', stripped)
        if m:
            text = inline_fmt(m.group(1))
            story.append(Paragraph(f'• {text}', BULLET))
            i += 1
            continue

        # Numbered list
        m = re.match(r'^\d+\.\s+(.*)', stripped)
        if m:
            text = inline_fmt(m.group(1))
            story.append(Paragraph(f'• {text}', BULLET))
            i += 1
            continue

        # Normal paragraph
        story.append(Paragraph(inline_fmt(stripped), BODY))
        i += 1

    if in_table:
        flush_table()

    return story


# ── Build PDF ─────────────────────────────────────────────────────────────────

def main():
    story = []

    # Cover page
    story.append(Spacer(1, 0.6*inch))

    title_style = ParagraphStyle('CoverTitle', parent=styles['Normal'],
        fontSize=28, fontName='Helvetica-Bold', textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=6, leading=34)
    sub_style = ParagraphStyle('CoverSub', parent=styles['Normal'],
        fontSize=13, textColor=colors.HexColor('#555555'), spaceAfter=4, leading=18)
    meta_style = ParagraphStyle('CoverMeta', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#888888'), leading=14)

    story.append(Paragraph('Master Security Log', title_style))
    story.append(Paragraph('evw\'s MacBook Pro · macOS 26.5 (25F71)', sub_style))
    story.append(Spacer(1, 0.1*inch))
    story.append(HRFlowable(width='100%', thickness=2, color=ACCENT_DARK, spaceAfter=10))
    story.append(Paragraph('Threat model: Nation-state level · Ongoing investigation', meta_style))
    story.append(Paragraph('Period covered: 2026-05-11 through 2026-06-02', meta_style))
    story.append(Paragraph('Sessions documented: 14 scans across 16 days', meta_style))
    story.append(Paragraph('Analyst: evw + Claude Sonnet 4.6 (claude-sonnet-4-6)', meta_style))
    story.append(Spacer(1, 0.35*inch))

    # Executive summary box on cover
    summary_data = [[Paragraph(
        '<b>Pattern:</b> Over 14 scan sessions, the same set of remote-management services '
        '(RemoteManagementAgent, sharingd, studentd, identityservicesd, replicatord, privatecloudcomputed) '
        'were disabled via launchctl, then silently reset on the next reboot — for 4 consecutive sessions. '
        'The reset targeted exactly the services that enable remote access and telemetry, while leaving '
        'unrelated services untouched. This specificity is inconsistent with random system behavior. '
        'All binary hashes have remained clean. LS deny rules have prevented any external network '
        'connections from affected services throughout.',
        ParagraphStyle('SumBody', parent=BODY, fontSize=9, leading=14))]]
    t = Table(summary_data, colWidths=[6.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,-1), colors.HexColor('#eaf0fb')),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING',(0,0), (-1,-1), 12),
        ('TOPPADDING',  (0,0), (-1,-1), 10),
        ('BOTTOMPADDING',(0,0),(-1,-1), 10),
        ('LINEBEFORE',  (0,0), (0,-1), 4, colors.HexColor('#2980b9')),
    ]))
    story.append(t)

    story.append(PageBreak())

    # Main content from markdown
    md_story = guard_run('parse_md', parse_md, SRC)
    if md_story is None or md_story is SKIP:
        throw(f'parse_md failed: {SRC}')
    story.extend(md_story)

    # Footer note
    story.append(Spacer(1, 0.3*inch))
    story.append(hr())
    story.append(Paragraph(
        f'Generated 2026-06-02  ·  Source: MASTER-SECURITY-LOG.md  ·  '
        f'SHA-256 of source: see MANIFEST.sha256',
        CAPTION))

    def build():
        doc.build(story)
        return True

    built = guard_run('doc_build', build)
    if built is None or built is SKIP:
        throw(f'doc.build failed: {OUT}')
    print(f'PDF written: {OUT}')


if __name__ == '__main__':
    main()
