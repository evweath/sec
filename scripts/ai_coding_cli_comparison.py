from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

OUTPUT = '/Users/evw/dev/AI_Coding_CLI_Tools_Comparison_2026.pdf'

doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=letter,
    leftMargin=0.75 * inch,
    rightMargin=0.75 * inch,
    topMargin=0.75 * inch,
    bottomMargin=0.75 * inch,
)

styles = getSampleStyleSheet()

title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=18, spaceAfter=6, textColor=colors.HexColor('#1a1a2e'))
h1_style = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=14, spaceBefore=14, spaceAfter=4, textColor=colors.HexColor('#16213e'), borderPad=2)
h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=11, spaceBefore=10, spaceAfter=2, textColor=colors.HexColor('#0f3460'))
body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, leading=13, spaceAfter=3)
bullet_style = ParagraphStyle('Bullet', parent=styles['Normal'], fontSize=9, leading=13, leftIndent=12, spaceAfter=2, bulletIndent=4)
note_style = ParagraphStyle('Note', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor('#555555'), spaceAfter=4)
source_style = ParagraphStyle('Source', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor('#0f3460'), spaceAfter=2)

def bullet(text):
    return Paragraph(f'• {text}', bullet_style)

def h1(text):
    return Paragraph(text, h1_style)

def h2(text):
    return Paragraph(text, h2_style)

def body(text):
    return Paragraph(text, body_style)

def sp(n=6):
    return Spacer(1, n)

def hr():
    return HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6, spaceBefore=2)

# ── Summary Table ──────────────────────────────────────────────────────────────
TABLE_DATA = [
    ['Tool', 'Driven By', 'Input $/1M', 'Free Tier', 'Multi-Agent', 'MCP', 'GitHub PRs'],
    ['Claude Code',   'Anthropic',       '$3–$5',   'No',               'Yes',         'Yes', 'Yes'],
    ['Codex CLI',     'OpenAI',          '$5',       'No ($200/mo plan)','Yes',         'Yes', 'Yes'],
    ['Gemini CLI',    'Google',          '$2',       'Yes',              'Yes',         'Yes', 'Yes'],
    ['Grok Build',    'xAI',             '$0.20',    'No (subscription)','Yes (8)',     'Yes', 'Yes'],
    ['Aider',         'Community',       'BYOK',     'Yes',              'No',          'No',  'Via gh CLI'],
    ['OpenCode',      'Community',       'BYOK',     'Yes',              'Yes',         'Yes', 'Yes'],
    ['Goose',         'Linux Foundation','BYOK',     'Yes',              'Limited',     'Yes', 'Partial'],
    ['Continue',      'Continue.dev',    'BYOK',     'Yes',              'Limited',     'Yes', 'IDE-side'],
    ['Cline',         'Community',       'BYOK',     'Yes',              'No',          'Yes', 'Yes'],
    ['OpenHands',     'All-Hands AI',    'BYOK',     'Yes (self-host)',  'Yes',         'Yes', 'Best in class'],
    ['DeepSeek-TUI',  'Community',       '$0.44',    'Yes',              'Yes',         'Yes', 'Partial'],
    ['Crush',         'Charmbracelet',   'BYOK',     'Yes',              'No',          'Yes', 'Partial'],
    ['Plandex',       'Community',       'BYOK',     'Yes (self-host)',  'No',          'No',  'Partial'],
]

col_widths = [1.1*inch, 1.15*inch, 0.85*inch, 1.1*inch, 0.9*inch, 0.55*inch, 1.0*inch]

table = Table(TABLE_DATA, colWidths=col_widths, repeatRows=1)
table.setStyle(TableStyle([
    ('BACKGROUND',   (0, 0), (-1, 0),  colors.HexColor('#16213e')),
    ('TEXTCOLOR',    (0, 0), (-1, 0),  colors.white),
    ('FONTNAME',     (0, 0), (-1, 0),  'Helvetica-Bold'),
    ('FONTSIZE',     (0, 0), (-1, 0),  8),
    ('FONTSIZE',     (0, 1), (-1, -1), 7.5),
    ('FONTNAME',     (0, 1), (-1, -1), 'Helvetica'),
    ('ROWBACKGROUNDS',(0, 1),(-1, -1), [colors.white, colors.HexColor('#f4f6fb')]),
    ('GRID',         (0, 0), (-1, -1), 0.4, colors.HexColor('#cccccc')),
    ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
    ('TOPPADDING',   (0, 0), (-1, -1), 4),
    ('BOTTOMPADDING',(0, 0), (-1, -1), 4),
    ('LEFTPADDING',  (0, 0), (-1, -1), 5),
    ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ('FONTNAME',     (0, 1), (0, -1),  'Helvetica-Bold'),
]))

# ── Build document ─────────────────────────────────────────────────────────────
story = []

story.append(Paragraph('AI Coding CLI Tools — Complete Industry Comparison', title_style))
story.append(Paragraph('May 2026 · Claude Code Research Session', note_style))
story.append(hr())

story.append(body(
    'A comprehensive list of terminal-based AI coding agents — both company-driven and community-built — '
    'with token pricing, feature sets, and GitHub integration details. '
    '<b>BYOK</b> = Bring Your Own Key (tool is free; you pay the model provider directly).'
))
story.append(sp(8))

# ── OFFICIAL TOOLS ─────────────────────────────────────────────────────────────
story.append(h1('Official / Company-Driven Tools'))
story.append(hr())

tools_official = [
    {
        'name': 'Claude Code (Anthropic)',
        'cost': 'Sonnet 4.6: $3/$15 per 1M tokens · Opus 4.8: $5/$25 per 1M · Max subscription: $200/mo',
        'features': [
            'File read/write, shell execution, multi-agent fan-out',
            'MCP server support, plan mode, extended thinking (Opus only)',
            'Hooks and automation, IDE extensions (VS Code, JetBrains)',
            'SWE-bench Verified: 79.6% (Sonnet 4.6)',
        ],
        'github': 'PR creation, PR review, issue reference, auto-commit with message generation, branch awareness',
        'install': 'npm install -g @anthropic-ai/claude-code',
        'note': None,
    },
    {
        'name': 'OpenAI Codex CLI (OpenAI)',
        'cost': 'GPT-5.5: $5/$30 per 1M tokens · Included in ChatGPT Pro ($200/mo)',
        'features': [
            'File read/write, shell execution, sandboxed execution',
            'Parallel subagents, MCP support',
            'Built-in code review agent before commit',
            'SWE-bench Verified: 88.7%',
        ],
        'github': 'PR creation, diff review, branch operations, auto-commit',
        'install': 'npm i -g @openai/codex   OR   brew install --cask codex',
        'note': '~75K GitHub stars · ~3M weekly active users',
    },
    {
        'name': 'Gemini CLI (Google)',
        'cost': 'Free tier: 1,000 req/day, 1M token context, no card required · Paid API: $2/$12 per 1M',
        'features': [
            'File edit, shell commands, web search built-in',
            'MCP servers, ReAct loop, open-source weekly releases',
            'Runs Gemini 2.5 Pro · 1M token context window',
            'SWE-bench Verified: 80.6%',
        ],
        'github': 'PR creation, diff review, commit generation',
        'install': 'npm install -g @google/gemini-cli',
        'note': 'Free-tier users transitioning to Antigravity CLI on June 18, 2026',
    },
    {
        'name': 'Grok Build (xAI)',
        'cost': 'SuperGrok subscription: $299/mo (or $99/mo promo) · API: $0.20/$1.50 per 1M (grok-build-0.1)',
        'features': [
            'Up to 8 parallel subagents on larger tasks',
            'Plan-first loop — approves plan before executing',
            'MCP support · reads existing Claude Code MCP config',
            'Headless CI mode · 256K context window',
            'SWE-bench Verified: 70.8%',
        ],
        'github': 'PR creation, branch management, auto-commit',
        'install': 'Beta — access via SuperGrok / X Premium+ subscription',
        'note': 'macOS and Linux native · Windows via WSL2 · Native Win32 on roadmap',
    },
]

for t in tools_official:
    story.append(h2(t['name']))
    story.append(Paragraph(f'<b>Cost:</b> {t["cost"]}', body_style))
    story.append(Paragraph('<b>Features:</b>', body_style))
    for f in t['features']:
        story.append(bullet(f))
    story.append(Paragraph(f'<b>GitHub integration:</b> {t["github"]}', body_style))
    story.append(Paragraph(f'<b>Install:</b> <font name="Courier" size="8">{t["install"]}</font>', body_style))
    if t['note']:
        story.append(Paragraph(f'<i>{t["note"]}</i>', note_style))
    story.append(sp(6))

# ── COMMUNITY TOOLS ────────────────────────────────────────────────────────────
story.append(h1('Community / Open-Source Tools'))
story.append(hr())

tools_community = [
    {
        'name': 'Aider',
        'maintainer': 'Paul Gauthier (independent)',
        'cost': 'BYOK — free tool, pay only your model API costs. Works with any OpenAI-compatible endpoint.',
        'stars': '~41K',
        'features': [
            'Tree-sitter repo map across 100+ languages',
            'Auto-commits with descriptive messages',
            'Multi-file edits, voice coding mode, /run shell integration',
            'Works in any editor — no IDE plugin required',
        ],
        'github': 'Git-native auto-commits, branch creation, diff management. No native PR creation — integrates cleanly with the gh CLI.',
        'install': 'pip install aider-chat',
        'note': None,
    },
    {
        'name': 'OpenCode',
        'maintainer': 'Community (OpenAI partnership)',
        'cost': 'Free and open-source. Supports 75+ providers — use GitHub Copilot or ChatGPT Plus auth, or raw API keys.',
        'stars': '~120–150K (fastest-growing)',
        'features': [
            'LSP integration — automatically configures language servers for the LLM',
            'Multi-session parallel agents on the same project',
            'Session sharing via links · desktop app + IDE extension variants',
            '75+ provider support',
        ],
        'github': 'Auto-commit, PR creation, diff review',
        'install': 'npm install -g opencode',
        'note': 'After Anthropic\'s January 2026 enforcement, Claude requires raw API key (not OAuth)',
    },
    {
        'name': 'Goose (Block → Linux Foundation)',
        'maintainer': 'Donated to Linux Foundation Agentic AI Foundation, April 2026',
        'cost': 'Free (Apache 2.0). BYOK — pay your model provider.',
        'stars': '~32K',
        'features': [
            'Full agent loop: installs deps, runs tests, edits files, fixes failures',
            'CLI + desktop app',
            'MCP extensions, built in Rust',
        ],
        'github': 'Auto-commit, branch operations — no native PR creation',
        'install': 'brew install goose   OR   binary from GitHub Releases',
        'note': None,
    },
    {
        'name': 'Continue (Continue.dev)',
        'maintainer': 'Continue.dev (VC-backed startup)',
        'cost': 'Free core (Apache 2.0). Cloud team features on paid plans. BYOK for models.',
        'stars': '~31K',
        'features': [
            'Originally IDE extension (VS Code/JetBrains) — now also has cn terminal agent',
            '200+ model configurations, inline autocomplete',
            'Codebase indexing',
        ],
        'github': 'Commit suggestions, diff integration — deeper on the IDE side than terminal side',
        'install': 'npm install -g continuedev',
        'note': None,
    },
    {
        'name': 'Cline',
        'maintainer': 'Community',
        'cost': 'Free (Apache 2.0). BYOK.',
        'stars': '~58K',
        'features': [
            'VS Code extension + CLI mode',
            'Multi-provider support, tool calling',
            'Browser automation, MCP servers',
        ],
        'github': 'PR review, auto-commit, branch operations',
        'install': 'VS Code extension marketplace or CLI binary',
        'note': None,
    },
    {
        'name': 'OpenHands (formerly OpenDevin)',
        'maintainer': 'All-Hands AI (VC-backed)',
        'cost': 'Free self-hosted (MIT). Cloud platform pricing on request.',
        'stars': '~68K',
        'features': [
            'Full software-engineer agent: browses web, writes and runs code, manages git',
            'Web UI + lightweight CLI binary',
            'Docker or pip install',
        ],
        'github': 'Native PR creation and review, issue triage, branch management — strongest GitHub integration of any open-source tool',
        'install': 'Docker or pip install openhands · CLI: openhands-cli binary',
        'note': None,
    },
    {
        'name': 'DeepSeek-TUI',
        'maintainer': 'Community (not affiliated with DeepSeek officially)',
        'cost': 'BYOK DeepSeek API — $0.44/$1.74 per 1M (V4 Pro). Dramatically low cost.',
        'stars': 'Early-stage',
        'features': [
            'Rust binary — fast startup',
            'Tool calling, auto subagents, sandboxed execution',
            'MCP support, persistent task queue, TUI interface',
        ],
        'github': 'Auto-commit — limited native PR support',
        'install': 'npm install -g deepseek-tui',
        'note': '⚠ API calls route to China-hosted servers — data-residency concerns apply',
    },
    {
        'name': 'Crush (Charmbracelet)',
        'maintainer': 'Charmbracelet (makers of Bubble Tea, Glow)',
        'cost': 'Free (open-source). BYOK multi-provider.',
        'stars': 'N/A',
        'features': [
            'Glamorous TUI in Go',
            'Multi-provider: Claude, GPT, Gemini, Ollama (local)',
            'MCP support, keyboard-driven interface',
        ],
        'github': 'Auto-commit — lightweight git integration',
        'install': 'brew install charmbracelet/tap/crush',
        'note': None,
    },
    {
        'name': 'Plandex',
        'maintainer': 'Community',
        'cost': 'Free self-hosted. Plandex Cloud is winding down.',
        'stars': 'N/A',
        'features': [
            'Plan-first agent — reviews plan before applying',
            'Up to 2M token context window',
            'Diff-review sandbox before applying changes',
            'Built for long, multi-step tasks',
        ],
        'github': 'Diff review, branch operations — no active development on PR features',
        'install': 'Self-hosted only',
        'note': '⚠ No commits since October 2025 — effectively maintenance mode',
    },
]

for t in tools_community:
    story.append(h2(t['name']))
    story.append(Paragraph(f'<b>Maintainer:</b> {t["maintainer"]} · <b>GitHub Stars:</b> {t["stars"]}', body_style))
    story.append(Paragraph(f'<b>Cost:</b> {t["cost"]}', body_style))
    story.append(Paragraph('<b>Features:</b>', body_style))
    for f in t['features']:
        story.append(bullet(f))
    story.append(Paragraph(f'<b>GitHub integration:</b> {t["github"]}', body_style))
    story.append(Paragraph(f'<b>Install:</b> <font name="Courier" size="8">{t["install"]}</font>', body_style))
    if t['note']:
        story.append(Paragraph(f'<i>{t["note"]}</i>', note_style))
    story.append(sp(6))

# ── SUMMARY TABLE ──────────────────────────────────────────────────────────────
story.append(h1('At-a-Glance Summary'))
story.append(hr())
story.append(table)
story.append(sp(6))
story.append(Paragraph('BYOK = Bring Your Own Key — tool is free, you pay the model provider directly.', note_style))

# ── SOURCES ────────────────────────────────────────────────────────────────────
story.append(sp(10))
story.append(h1('Sources'))
story.append(hr())

sources = [
    ('Every AI Coding CLI in 2026: 30+ Tools', 'https://dev.to/soulentheo/every-ai-coding-cli-in-2026-the-complete-map-30-tools-compared-4gob'),
    ('Awesome CLI Coding Agents — GitHub', 'https://github.com/bradAGI/awesome-cli-coding-agents'),
    ('OpenAI Codex CLI — GitHub', 'https://github.com/openai/codex'),
    ('Gemini CLI — Google Developers', 'https://developers.google.com/gemini-code-assist/docs/gemini-cli'),
    ('Grok Build — xAI', 'https://x.ai/news/grok-build-cli'),
    ('OpenHands CLI — GitHub', 'https://github.com/OpenHands/OpenHands-CLI'),
    ('Best Open Source CLI Agents 2026 — Pinggy', 'https://pinggy.io/blog/best_open_source_cli_coding_agents/'),
    ('15 AI Coding CLI Tools Compared — Tembo', 'https://www.tembo.io/blog/coding-cli-tools-comparison'),
    ('Aider — Official Site', 'https://aider.chat/'),
    ('SWE-Bench Leaderboard May 2026', 'https://www.marc0.dev/en/leaderboard'),
]

for title, url in sources:
    story.append(Paragraph(f'• {title} — <font color="#0f3460">{url}</font>', source_style))

doc.build(story)
print(f'PDF written to: {OUTPUT}')
