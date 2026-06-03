#!/usr/bin/env python3
"""Generate a reference PDF documenting all Claude Code hooks: what they are,
where they live, how they're configured, and a full inventory of active hooks."""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, Preformatted
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

OUT = '/Users/evw/dev/security/claude-hooks-reference.pdf'

doc = SimpleDocTemplate(
    OUT,
    pagesize=letter,
    leftMargin=0.85*inch, rightMargin=0.85*inch,
    topMargin=0.9*inch, bottomMargin=0.9*inch,
)

base = getSampleStyleSheet()

def style(name, parent='Normal', **kw):
    s = ParagraphStyle(name, parent=base[parent], **kw)
    return s

H1    = style('H1', 'Heading1', fontSize=18, spaceAfter=6, textColor=colors.HexColor('#1a1a2e'))
H2    = style('H2', 'Heading2', fontSize=13, spaceBefore=14, spaceAfter=4, textColor=colors.HexColor('#16213e'))
H3    = style('H3', 'Heading3', fontSize=11, spaceBefore=10, spaceAfter=3, textColor=colors.HexColor('#0f3460'))
BODY  = style('Body', fontSize=9.5, leading=14, spaceAfter=5)
MONO  = style('Mono', fontName='Courier', fontSize=8.2, leading=12, spaceAfter=3,
              backColor=colors.HexColor('#f4f4f4'), leftIndent=10, rightIndent=10,
              borderPadding=(4,4,4,4))
SMALL = style('Small', fontSize=8.5, leading=12, textColor=colors.HexColor('#444444'))
LABEL = style('Label', fontName='Helvetica-Bold', fontSize=9, textColor=colors.HexColor('#cc0000'))
NOTE  = style('Note', fontSize=8.5, leading=12, textColor=colors.HexColor('#666666'),
              leftIndent=14, borderPadding=2)

def hr(): return HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#cccccc'), spaceAfter=6)
def sp(n=6): return Spacer(1, n)
def p(text, st=BODY): return Paragraph(text, st)
def h1(t): return Paragraph(t, H1)
def h2(t): return Paragraph(t, H2)
def h3(t): return Paragraph(t, H3)
def code(t): return Preformatted(t, MONO)

def table(data, col_widths, header=True):
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style_cmds = [
        ('FONTNAME',  (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',  (0,0), (-1,-1), 8.5),
        ('ROWBACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME',  (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',  (0,0), (-1,0), 9),
        ('ALIGN',     (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',    (0,0), (-1,-1), 'MIDDLE'),
        ('GRID',      (0,0), (-1,-1), 0.3, colors.HexColor('#dddddd')),
        ('ROWBACKGROUND', (0,1), (-1,-1), colors.white),
        ('ROWBACKGROUND', (0,2), (-1,-1), colors.HexColor('#f9f9f9')),
        ('TOPPADDING',  (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
    ]
    # Alternate row shading
    for i in range(1, len(data)):
        bg = colors.white if i % 2 == 1 else colors.HexColor('#f4f7ff')
        style_cmds.append(('ROWBACKGROUND', (0,i), (-1,i), bg))
    t.setStyle(TableStyle(style_cmds))
    return t

# ─────────────────────────────────────────────────────────────────────────────
story = []

# Title page block
story += [
    sp(20),
    h1('Claude Code — Hooks Reference'),
    p('Complete documentation: what hooks are, where they live, how they are configured, '
      'and a full inventory of every active hook on this machine.', BODY),
    p('Generated: 2026-06-03  •  Machine: evw\'s MacBook Pro  •  Claude Code v2.1.161', SMALL),
    hr(), sp(4),
]

# ─── SECTION 1: What are hooks ────────────────────────────────────────────────
story += [
    h2('1. What Are Hooks'),
    p('Hooks are shell commands that Claude Code executes automatically in response to '
      'specific lifecycle events — before a tool runs, after a tool completes, or when '
      'Claude finishes responding. They run on the <b>host machine</b>, outside the '
      'Claude model, giving you deterministic control over the agent\'s behavior.'),
    p('Hooks can:'),
    p('• <b>Block</b> a tool call before it executes (exit 2 from PreToolUse)'),
    p('• <b>Log</b> every tool call for auditing'),
    p('• <b>Auto-format</b> files after edits'),
    p('• <b>Trigger notifications</b> when Claude finishes'),
    p('• <b>Back up work</b> at session end'),
    p('• <b>Suppress or continue</b> the session (Stop hook with block decision)'),
    sp(4),
]

# ─── SECTION 2: Untrusted hooks ───────────────────────────────────────────────
story += [
    h2('2. Untrusted Hooks'),
    p('<b>Untrusted hooks</b> are hooks defined in project-level settings files '
      '(<font face="Courier" size="9">.claude/settings.json</font> or '
      '<font face="Courier" size="9">.claude/settings.local.json</font> inside a '
      'project directory) that were not created by the user in the global config.'),
    p('The distinction matters because:'),
    p('• <b>Global hooks</b> (<font face="Courier" size="9">~/.claude/settings.json</font>) '
      'are set by the owner of the machine and are fully trusted.'),
    p('• <b>Project hooks</b> live inside a repo. If you clone or open a foreign '
      'repository, its <font face="Courier" size="9">.claude/settings.json</font> could '
      'contain malicious hook commands that execute arbitrary shell code on your machine '
      'every time Claude runs a tool.'),
    p('Claude Code surfaces a <b>prompt before running hooks from an unknown project</b> '
      'so you can review and approve them. A hook is considered "untrusted" until you '
      'explicitly approve it for that project. This is the same threat model as '
      '<font face="Courier" size="9">.envrc</font> files in direnv or '
      '<font face="Courier" size="9">package.json</font> postinstall scripts.'),
    p('<b>Security note for this machine:</b> The security project\'s '
      '<font face="Courier" size="9">.claude/settings.local.json</font> defines only '
      'permissions (allow/deny lists), no hooks. All active hooks are defined in the '
      'global <font face="Courier" size="9">~/.claude/settings.json</font> and are '
      'therefore fully trusted.', LABEL),
    sp(4),
]

# ─── SECTION 3: Where hooks live and how they are configured ─────────────────
story += [
    h2('3. Where Hooks Live and How They Are Configured'),
    h3('Configuration files (checked in order)'),
]

loc_data = [
    ['File', 'Scope', 'Trusted?', 'Purpose'],
    ['~/.claude/settings.json',        'Global (all projects)', 'Yes', 'Primary hook config; model, theme, permissions'],
    ['~/.claude/settings.local.json',  'Global (machine-local)', 'Yes', 'Machine-specific overrides; not committed to git'],
    ['.claude/settings.json',          'Project (shared)',       'Prompt', 'Committed to repo; reviewed by Claude Code before use'],
    ['.claude/settings.local.json',    'Project (local)',        'Prompt', 'Not committed; machine-local project overrides'],
]
story.append(table(loc_data, [2.3*inch, 1.5*inch, 0.85*inch, 2.2*inch]))
story.append(sp(8))

story += [
    h3('JSON structure'),
    p('Hooks are defined under the top-level <font face="Courier" size="9">hooks</font> key '
      'in any settings file:'),
    code('''\
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",          // tool name to match, or "" for all tools
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/script.sh",
            "timeout": 10,          // optional, seconds
            "statusMessage": "..."  // optional, shown in UI while running
          }
        ]
      }
    ]
  }
}'''),
    sp(4),
    h3('How to view your current hooks'),
    p('Three ways to inspect active hooks:'),
    p('1. <b>Claude Code UI:</b> Settings → Hooks (visual editor, shows all active hooks)'),
    p('2. <b>Shell:</b> <font face="Courier" size="9">cat ~/.claude/settings.json | python3 -c '
      '"import sys,json; h=json.load(sys.stdin).get(\'hooks\',{}); '
      '[print(k,\':\',len(v),\'matchers\') for k,v in h.items()]"</font>'),
    p('3. <b>Direct file read:</b> open '
      '<font face="Courier" size="9">~/.claude/settings.json</font> in any editor — '
      'the hooks section is human-readable JSON.'),
    sp(4),
]

# ─── SECTION 4: All hook trigger events ──────────────────────────────────────
story += [
    h2('4. All Hook Trigger Events'),
    p('Claude Code defines the following hook event types:'),
]

events_data = [
    ['Event', 'When it fires', 'Can block?', 'Input payload'],
    ['PreToolUse',    'Before any tool executes',           'Yes (exit 2)', 'tool_name, tool_input, session_id'],
    ['PostToolUse',   'After any tool completes',           'No',           'tool_name, tool_input, tool_response, session_id'],
    ['Stop',          'When Claude finishes a response',    'Yes (JSON)',   'transcript_path, session_id'],
    ['SubagentStop',  'When a subagent finishes',           'No',           'transcript_path, session_id, subagent_id'],
    ['PreCompact',    'Before context compaction runs',     'No',           'transcript_path, session_id'],
]
story.append(table(events_data, [1.3*inch, 2.2*inch, 1.15*inch, 2.2*inch]))
story.append(sp(4))

story += [
    h3('Hook exit codes'),
]
exit_data = [
    ['Exit code', 'Meaning', 'Effect'],
    ['0',  'Success',        'Hook ran cleanly; proceed normally'],
    ['1',  'Error',          'Logged as warning; does not block (PostToolUse/Stop)'],
    ['2',  'Block',          'PreToolUse only: tool call is cancelled; stderr shown to Claude'],
    ['JSON {decision:"block"}', 'Block stop', 'Stop hook only: session continues; "reason" fed back as next prompt'],
]
story.append(table(exit_data, [1.6*inch, 1.5*inch, 3.75*inch]))
story.append(sp(4))

story += [
    h3('Matcher syntax'),
    p('The <font face="Courier" size="9">matcher</font> field in PreToolUse/PostToolUse '
      'filters which tool calls trigger the hook:'),
    p('• <font face="Courier" size="9">""</font> (empty string) — matches all tools'),
    p('• <font face="Courier" size="9">"Bash"</font> — matches only Bash tool calls'),
    p('• <font face="Courier" size="9">"Write"</font> — matches only Write tool calls'),
    p('• Multiple matchers: define multiple entries in the array, each with its own matcher'),
    sp(4),
]

# ─── SECTION 5: Active hook inventory ────────────────────────────────────────
story += [
    h2('5. Active Hook Inventory (This Machine)'),
    p('Source: <font face="Courier" size="9">~/.claude/settings.json</font>  •  '
      'Project hooks: none (project settings.local.json has no hooks key)'),
    sp(4),
]

# --- PreToolUse ---
story += [h3('PreToolUse  —  Fires before every tool call')]
inv_pre = [
    ['Matcher', 'Script', 'Timeout', 'Purpose'],
    ['(all tools)', '~/.claude/hooks/pre-tool-use.sh', '—', 'Blocks dangerous operations'],
]
story.append(table(inv_pre, [1.1*inch, 2.5*inch, 0.7*inch, 2.55*inch]))
story.append(sp(4))

story += [
    p('<b>pre-tool-use.sh — what it blocks:</b>', SMALL),
]
blocks_data = [
    ['Pattern', 'Rule'],
    ['git ... --no-verify',                'Blocked — bypasses git hooks'],
    ['git push --force / -f',             'Blocked — force-push not allowed'],
    ['chmod 777 / a+rwx / o+rwx',         'Blocked — overly permissive'],
    ['cat/head/tail/vim *.env *.pem *.key','Blocked — shell read of secrets file'],
    ['cat/head/tail credentials.json',    'Blocked — credential file read'],
    ['Read/Write/Edit *.env',             'Blocked — .env file access'],
    ['Read/Write/Edit credentials.json',  'Blocked — credential file access'],
    ['Read/Write/Edit secrets/**',        'Blocked — secrets directory access'],
]
story.append(table(blocks_data, [3.1*inch, 3.75*inch]))
story.append(sp(8))

# --- PostToolUse ---
story += [h3('PostToolUse  —  Fires after every tool call')]
inv_post = [
    ['Matcher', 'Script', 'Timeout', 'Purpose'],
    ['(all tools)', '~/.claude/hooks/post-tool-use.sh', '—', 'Log + auto-format edited files'],
]
story.append(table(inv_post, [1.1*inch, 2.5*inch, 0.7*inch, 2.55*inch]))
story.append(sp(4))

fmt_data = [
    ['Extension', 'Formatter'],
    ['.js .jsx .ts .tsx .json .css .md .html .yaml .yml', 'prettier --write'],
    ['.py',  'ruff format'],
    ['.go',  'gofmt -w'],
    ['.rb',  'rubocop --auto-correct'],
    ['.sh',  'shfmt -w'],
]
story += [p('<b>Auto-format rules (applied on Write/Edit/MultiEdit):</b>', SMALL)]
story.append(table(fmt_data, [3.2*inch, 3.65*inch]))
story += [
    p('Log destination: <font face="Courier" size="9">~/.claude/tool-log.jsonl</font> '
      '(append-only JSONL, one entry per tool call, includes logged_at timestamp)', SMALL),
    sp(8),
]

# --- Stop ---
story += [h3('Stop  —  Fires when Claude finishes a response')]
inv_stop = [
    ['#', 'Command / Script', 'Timeout', 'Purpose'],
    ['1', '~/.claude/record-session.sh',               '—',   'Record transcript path to ~/.claude/.last_transcript'],
    ['2', '~/.claude/hooks/notify-on-stop.sh',         '—',   'macOS desktop notification: "Claude has finished."'],
    ['3', '[inline] git add -A + commit + rsync',      '30s', 'Session backup: git commit + copy to ~/.claude_home/<project>/'],
    ['4', '[inline] tar + shasum + l5-hash-log.txt',   '30s', 'Archive project as .tar.gz, append SHA-256 to L5 hash log'],
]
story.append(table(inv_stop, [0.3*inch, 3.0*inch, 0.7*inch, 2.85*inch]))
story.append(sp(4))

story += [
    p('<b>Stop hook #3 — Session backup (inline command):</b>', SMALL),
    code('''\
PROJECT_DIR="$PWD"; PROJECT_NAME="$(basename "$PROJECT_DIR")"
if [ -d "$PROJECT_DIR/.git" ]; then
  git -C "$PROJECT_DIR" add -A 2>/dev/null
  git -C "$PROJECT_DIR" diff --cached --quiet || \
    git -C "$PROJECT_DIR" commit -m "Claude session backup: $(date)" 2>/dev/null
fi
mkdir -p "$HOME/.claude_home/$PROJECT_NAME"
rsync -a --exclude=.git "$PROJECT_DIR/" "$HOME/.claude_home/$PROJECT_NAME/" 2>/dev/null'''),
    sp(4),
    p('<b>Stop hook #4 — L5 archive + hash (inline command):</b>', SMALL),
    code('''\
PROJECT_DIR="$PWD"; PROJECT_NAME="$(basename "$PROJECT_DIR")"
ARCHIVE="$HOME/.claude_home/${PROJECT_NAME}.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$PROJECT_DIR")" "$PROJECT_NAME" 2>/dev/null
HASH=$(shasum -a 256 "$ARCHIVE" 2>/dev/null | awk '{print $1}')
[ -n "$HASH" ] && \
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $HASH $PROJECT_NAME" \
  >> "$HOME/dev/security/l5-hash-log.txt" 2>/dev/null'''),
    sp(8),
]

# ─── SECTION 6: Plugin hooks (installed but project-scoped) ──────────────────
story += [
    h2('6. Plugin Hooks (Installed, Project-Scoped)'),
    p('The following hooks ship with installed plugins in '
      '<font face="Courier" size="9">~/.claude/plugins/</font>. They are <b>not active '
      'globally</b> — each fires only when the relevant plugin skill is invoked in a '
      'session or when the plugin is explicitly enabled for a project.'),
    sp(4),
]

plugin_data = [
    ['Plugin', 'Hook event', 'Script', 'Purpose'],
    ['ralph-loop',        'Stop',         'hooks/stop-hook.sh',            'Blocks session exit to re-feed prompt; implements /loop'],
    ['security-guidance', 'PreToolUse',   'hooks/sg-python.sh',            'Python interpreter shim for cross-platform hook execution'],
    ['explanatory-output-style', 'PreToolUse', 'hooks-handlers/session-start.sh', 'Injects output style instructions at session start'],
    ['learning-output-style',    'PreToolUse', 'hooks-handlers/session-start.sh', 'Injects learning-focused output style at session start'],
    ['plugin-dev (examples)',    '—',          'examples/load-context.sh etc.',   'Example hooks for plugin developers (not active)'],
]
story.append(table(plugin_data, [1.6*inch, 1.1*inch, 2.1*inch, 2.05*inch]))
story.append(sp(8))

# ─── SECTION 7: Shell wrapper hooks ──────────────────────────────────────────
story += [
    h2('7. Shell Wrapper (Post-Session Export)'),
    p('This machine\'s <font face="Courier" size="9">~/.zshrc</font> wraps the '
      '<font face="Courier" size="9">claude</font> command in a shell function that calls '
      '<font face="Courier" size="9">~/.claude/export-conversation.sh</font> after the '
      'CLI exits. This is <b>not</b> a Claude Code hook — it runs in the shell after '
      'Claude exits and has no access to the hook payload API.'),
    code('''\
claude () {
    command claude "$@"
    ~/.claude/export-conversation.sh   # runs after CLI exits
}'''),
    p('<b>export-conversation.sh</b> reads '
      '<font face="Courier" size="9">~/.claude/.last_transcript</font> (written by '
      'record-session.sh Stop hook #1), parses the JSONL transcript, and saves a '
      'Markdown export to '
      '<font face="Courier" size="9">~/Documents/claude-exports/YYYY-MM-DD_<slug>.md</font>.', SMALL),
    sp(8),
]

# ─── SECTION 8: Hook file locations summary ──────────────────────────────────
story += [
    h2('8. All Hook-Related Files on This Machine'),
]
files_data = [
    ['Path', 'Type', 'Role'],
    ['~/.claude/settings.json',               'Config',  'Defines all active hooks (global)'],
    ['~/.claude/settings.local.json',         'Config',  'Machine-local permissions only (no hooks)'],
    ['~/dev/security/.claude/settings.local.json', 'Config', 'Project permissions only (no hooks)'],
    ['~/.claude/hooks/pre-tool-use.sh',       'Script',  'PreToolUse: blocks dangerous tool calls'],
    ['~/.claude/hooks/post-tool-use.sh',      'Script',  'PostToolUse: JSONL logging + auto-format'],
    ['~/.claude/hooks/notify-on-stop.sh',     'Script',  'Stop #2: macOS desktop notification'],
    ['~/.claude/record-session.sh',           'Script',  'Stop #1: records transcript path'],
    ['~/.claude/export-conversation.sh',      'Script',  'Shell wrapper (not a hook): exports transcript to MD'],
    ['~/.claude/tool-log.jsonl',              'Log',     'Append-only tool call audit log (PostToolUse output)'],
    ['~/.claude/.last_transcript',            'State',   'Stores current session transcript path'],
    ['~/dev/security/l5-hash-log.txt',        'Log',     'L5 archive hashes appended by Stop hook #4'],
    ['~/.claude_home/<project>/             ', 'Archive', 'Per-project rsync backup (Stop hook #3)'],
    ['~/.claude_home/<project>.tar.gz',       'Archive', 'Per-project tar archive (Stop hook #4)'],
]
story.append(table(files_data, [3.15*inch, 0.75*inch, 2.95*inch]))
story.append(sp(8))

# ─── SECTION 9: Security considerations ──────────────────────────────────────
story += [
    h2('9. Security Considerations'),
    p('<b>Hooks execute with full user privileges</b> — the same permissions as the '
      'running Claude Code process (uid 501, evw). There is no sandbox.'),
    p('Key risks and mitigations on this machine:'),
]
sec_data = [
    ['Risk', 'Mitigation in place'],
    ['Malicious project hook in cloned repo',      'All hooks are global-only; no project hooks defined'],
    ['Hook command injection via tool payload',    'pre-tool-use.sh validates tool_name + command before exec'],
    ['Hook leaks secrets via log',                 'post-tool-use.sh logs to local file; tool-log.jsonl not committed'],
    ['Stop hook auto-commits sensitive files',     'rsync excludes .git; git add -A could catch .env — watch for this'],
    ['Hook scripts tampered on disk',              'scan-hashes.sh hashes all 4 hook scripts per scan'],
    ['Long-running hook blocks session',           'Stop hooks #3/#4 have 30s timeout'],
]
story.append(table(sec_data, [2.8*inch, 4.05*inch]))
story.append(sp(6))

story += [
    p('<b>To audit hook script integrity:</b>', SMALL),
    code('bash ~/dev/security/scan-hashes.sh\n'
         '# Hashes: pre-tool-use.sh, post-tool-use.sh, notify-on-stop.sh,\n'
         '#         record-session.sh, export-conversation.sh'),
    sp(4),
    hr(),
    p('Document generated by generate-hooks-pdf.py  •  /Users/evw/dev/security/claude-hooks-reference.pdf', SMALL),
]

doc.build(story)
print(f'PDF written: {OUT}')
