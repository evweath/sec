#!/usr/bin/env python3
"""
Generate a PDF security scan report from SECURITY-CHECKLIST.md and a scan summary.

Usage:
    python3 checklist-pdf.py                        # uses today's scan dir
    python3 checklist-pdf.py --scan-dir scan-2026-06-10
    python3 checklist-pdf.py --checklist-only        # PDF of checklist only

Requires: macOS textutil + cupsfilter (both included with macOS)
Output: <scan-dir>/SECURITY-SCAN-REPORT-<date>.pdf
"""

import argparse
import os
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

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

SECURITY_DIR = Path(__file__).parent
CHECKLIST = SECURITY_DIR / 'SECURITY-CHECKLIST.md'


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def md_to_html(md_path: Path, title: str) -> str:
    """Convert Markdown to styled HTML using pure Python (no deps)."""
    text = md_path.read_text(encoding='utf-8')

    # Very lightweight Markdown-to-HTML (handles headers, code blocks, tables, bold, lists)
    import re
    lines = text.split('\n')
    html_lines = []
    in_code = False
    in_table = False

    for line in lines:
        # Fenced code blocks
        if line.startswith('```'):
            if not in_code:
                lang = line[3:].strip() or 'text'
                html_lines.append(f'<pre><code class="language-{lang}">')
                in_code = True
            else:
                html_lines.append('</code></pre>')
                in_code = False
            continue

        if in_code:
            html_lines.append(line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
            continue

        # Tables
        if '|' in line and line.strip().startswith('|'):
            if not in_table:
                html_lines.append('<table>')
                in_table = True
            if re.match(r'^\s*\|[-|: ]+\|\s*$', line):
                continue  # skip separator row
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            tag = 'th' if html_lines[-1] == '<table>' else 'td'
            row = ''.join(f'<{tag}>{c}</{tag}>' for c in cells)
            html_lines.append(f'<tr>{row}</tr>')
            continue
        else:
            if in_table:
                html_lines.append('</table>')
                in_table = False

        # Headers
        if line.startswith('### '):
            html_lines.append(f'<h3>{line[4:]}</h3>')
        elif line.startswith('## '):
            html_lines.append(f'<h2>{line[3:]}</h2>')
        elif line.startswith('# '):
            html_lines.append(f'<h1>{line[2:]}</h1>')
        # Horizontal rule
        elif re.match(r'^---+$', line.strip()):
            html_lines.append('<hr>')
        # Unordered list
        elif re.match(r'^[-*] ', line):
            html_lines.append(f'<li>{line[2:]}</li>')
        # Numbered list
        elif re.match(r'^\d+\. ', line):
            item = re.sub(r'^\d+\. ', '', line)
            html_lines.append(f'<li>{item}</li>')
        # Blank line
        elif line.strip() == '':
            html_lines.append('<br>')
        else:
            html_lines.append(f'<p>{line}</p>')

    if in_table:
        html_lines.append('</table>')
    if in_code:
        html_lines.append('</code></pre>')

    body = '\n'.join(html_lines)

    # Inline formatting: **bold**, `code`
    body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', body)
    body = re.sub(r'`([^`]+)`', r'<code>\1</code>', body)
    body = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', body)  # strip links, keep text

    css = """
    body { font-family: -apple-system, Helvetica, sans-serif; font-size: 11pt;
           margin: 1.5cm; color: #111; }
    h1 { font-size: 18pt; border-bottom: 2px solid #333; padding-bottom: 4px; }
    h2 { font-size: 14pt; border-bottom: 1px solid #aaa; padding-bottom: 2px;
         margin-top: 20px; }
    h3 { font-size: 12pt; color: #333; margin-top: 14px; }
    pre { background: #f5f5f5; padding: 8px; border-radius: 4px;
          font-size: 9pt; font-family: 'Menlo', 'Courier New', monospace;
          overflow-wrap: break-word; white-space: pre-wrap; }
    code { background: #f5f5f5; padding: 1px 3px; border-radius: 2px;
           font-size: 9pt; font-family: 'Menlo', 'Courier New', monospace; }
    pre code { background: none; padding: 0; }
    table { border-collapse: collapse; width: 100%; margin: 8px 0; }
    th, td { border: 1px solid #ccc; padding: 4px 8px; font-size: 9.5pt; text-align: left; }
    th { background: #eee; font-weight: bold; }
    hr { border: none; border-top: 1px solid #ccc; margin: 12px 0; }
    li { margin: 2px 0; }
    strong { font-weight: bold; }
    .cover { text-align: center; margin-top: 80px; }
    .cover h1 { font-size: 22pt; border: none; }
    .cover p { font-size: 12pt; color: #555; }
    @media print {
      pre { page-break-inside: avoid; }
      h2 { page-break-after: avoid; }
    }
    """

    today_str = date.today().isoformat()
    cover = f"""
    <div class="cover">
      <h1>Security Scan Report</h1>
      <p><strong>Date:</strong> {today_str}</p>
      <p><strong>System:</strong> {os.uname().nodename}</p>
      <p><strong>Classification:</strong> CONFIDENTIAL — Restricted</p>
      <p><em>Generated by ~/dev/security/checklist-pdf.py</em></p>
    </div>
    <hr>
    """

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{css}</style></head>
<body>{cover}{body}</body></html>"""


def html_to_pdf(html_content: str, output_path: Path) -> None:
    """Convert HTML to PDF.

    Preference order:
      1. pandoc (brew install pandoc) — best output
      2. wkhtmltopdf (no longer in Homebrew — used only if already installed)
      3. Open HTML in default browser with instructions to print to PDF
    """
    html_out = output_path.with_suffix('.html')
    html_out.write_text(html_content, encoding='utf-8')

    # Option 1: pandoc
    pandoc = subprocess.run(['which', 'pandoc'], capture_output=True, text=True).stdout.strip()
    if pandoc:
        try:
            result = subprocess.run(
                [pandoc, '--from=html', '--to=pdf',
                 '--pdf-engine=wkhtmltopdf',
                 '-o', str(output_path), str(html_out)],
                capture_output=True, text=True,
            )
            if result.returncode == 0 and output_path.exists():
                print(f'PDF created via pandoc: {output_path}')
                return
        except Exception:
            pass
        # Try pandoc without specifying pdf engine
        try:
            result = subprocess.run(
                [pandoc, '--from=html', '-o', str(output_path), str(html_out)],
                capture_output=True, text=True,
            )
            if result.returncode == 0 and output_path.exists():
                print(f'PDF created via pandoc: {output_path}')
                return
        except Exception:
            pass

    # Option 2: wkhtmltopdf
    wk = subprocess.run(['which', 'wkhtmltopdf'], capture_output=True, text=True).stdout.strip()
    if wk:
        try:
            result = subprocess.run(
                [wk, '--quiet', str(html_out), str(output_path)],
                capture_output=True, text=True,
            )
            if result.returncode == 0 and output_path.exists():
                print(f'PDF created via wkhtmltopdf: {output_path}')
                return
        except Exception:
            pass

    # Fallback: open HTML in default browser for manual print-to-PDF
    print(f'\nHTML report: {html_out}')
    print('To create PDF (one-time): brew install pandoc')
    print('Then rerun: python3 ~/dev/security/checklist-pdf.py')
    print('Opening HTML in default browser — use File > Print > Save as PDF')
    subprocess.run(['open', str(html_out)], check=False)


def cupsfilter_available() -> bool:
    try:
        run(['/usr/sbin/cupsfilter', '--help'], check=False)
        return True
    except FileNotFoundError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate security scan PDF report')
    parser.add_argument('--scan-dir', default=None,
                        help='Scan directory (default: scan-YYYY-MM-DD for today)')
    parser.add_argument('--checklist-only', action='store_true',
                        help='PDF of SECURITY-CHECKLIST.md only')
    args = parser.parse_args()

    today = date.today().isoformat()

    if args.checklist_only:
        output_path = SECURITY_DIR / f'SECURITY-CHECKLIST-{today}.pdf'
        html = guard_run('md_to_html', md_to_html, CHECKLIST, f'Security Checklist — {today}')
        if html is None or html is SKIP:
            throw(f'md_to_html failed: {CHECKLIST}')
        print(f'Generating checklist PDF: {output_path}')
        guard_run('html_to_pdf', html_to_pdf, html, output_path)
        print(f'Done: {output_path}')
        return

    scan_dir_name = args.scan_dir or f'scan-{today}'
    scan_dir = SECURITY_DIR / scan_dir_name

    if not scan_dir.exists():
        print(f'Scan directory not found: {scan_dir}', file=sys.stderr)
        sys.exit(1)

    # Combine SCAN-SUMMARY.md + SECURITY-CHECKLIST.md
    parts: list[str] = []
    summary = scan_dir / 'SCAN-SUMMARY.md'
    if summary.exists():
        parts.append(f'# Scan Summary — {today}\n\n')
        parts.append(summary.read_text(encoding='utf-8'))
        parts.append('\n\n---\n\n')

    parts.append('# Security Checklist\n\n')
    if CHECKLIST.exists():
        parts.append(CHECKLIST.read_text(encoding='utf-8'))

    combined_md = SECURITY_DIR / '_combined_report.md'
    written = guard_run('write_combined_md', combined_md.write_text,
                        ''.join(parts), encoding='utf-8')
    if written is None or written is SKIP:
        throw(f'write failed: {combined_md}')

    output_path = scan_dir / f'SECURITY-SCAN-REPORT-{today}.pdf'
    print(f'Generating PDF: {output_path}')
    html = guard_run('md_to_html', md_to_html, combined_md, f'Security Scan Report — {today}')
    if html is None or html is SKIP:
        throw(f'md_to_html failed: {combined_md}')
    guard_run('html_to_pdf', html_to_pdf, html, output_path)
    combined_md.unlink(missing_ok=True)

    # Also save HTML version as fallback
    html_path = scan_dir / f'SECURITY-SCAN-REPORT-{today}.html'
    written = guard_run('write_html', html_path.write_text, html, encoding='utf-8')
    if written is None or written is SKIP:
        throw(f'write failed: {html_path}')
    print(f'HTML saved: {html_path}')
    print(f'PDF output: {output_path}')


if __name__ == '__main__':
    main()
