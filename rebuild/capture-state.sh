#!/usr/bin/env bash
# =============================================================================
# rebuild/capture-state.sh — capture the restorable state of THIS Mac into
# rebuild/state/ so rebuild-mac.sh can reproduce it on a fresh macOS install.
#
# Run:        bash /Users/evw/dev/security/rebuild/capture-state.sh
# Best:    sudo bash /Users/evw/dev/security/rebuild/capture-state.sh
#          (root additionally captures: fresh LS model export, LS license,
#           disabled.501.plist entries)
#
# Re-run monthly, after any deliberate config change, and ALWAYS before a
# rebuild. Idempotent; overwrites rebuild/state/ content, not history.
# =============================================================================

set -uo pipefail

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error-guard.sh)
_eg_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
while [ "$_eg_d" != "/" ] && [ ! -f "$_eg_d/lib/error-guard.sh" ]; do _eg_d="$(dirname "$_eg_d")"; done
[ -f "$_eg_d/lib/error-guard.sh" ] && . "$_eg_d/lib/error-guard.sh"; unset _eg_d
command -v guard_run >/dev/null 2>&1 || guard_run() { shift; "$@"; }

SEC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$SEC_DIR/rebuild/state"
LSCLI="/Applications/Little Snitch.app/Contents/Components/littlesnitch"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$STATE/launchagents" "$STATE/etc/pf.anchors"
info() { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }
warn() { echo "[!] $*"; }
MANIFEST=()

note() { MANIFEST+=("$1"); }

# ── 1. Little Snitch model ────────────────────────────────────────────────────
if [[ $EUID -eq 0 && -x "$LSCLI" ]]; then
    if guard_run "ls-export" "$LSCLI" export-model "$STATE/ls-model.json"; then
        chmod 644 "$STATE/ls-model.json"
        ok "LS model: fresh export ($(python3 -c "import json;print(len(json.load(open('$STATE/ls-model.json'))['rules']))" 2>/dev/null || echo '?') rules)"
        note "ls-model.json        LIVE EXPORT $TS"
    fi
else
    newest="$(ls -t "$SEC_DIR"/scan-*/ls-model.json 2>/dev/null | head -1 || true)"
    if [[ -n "$newest" ]]; then
        guard_run "ls-model-copy" cp "$newest" "$STATE/ls-model.json"
        ok "LS model: copied from $newest (run with sudo for a live export)"
        note "ls-model.json        copied from $newest"
    else
        warn "LS model: no export found anywhere"
        note "ls-model.json        MISSING"
    fi
fi

# ── 2. Little Snitch license/registration ─────────────────────────────────────
LSREG="/Library/Application Support/Objective Development/Little Snitch/registration.xpl"
if [[ -r "$LSREG" ]]; then
    guard_run "ls-reg" cp "$LSREG" "$STATE/ls-registration.xpl" && \
        ok "LS registration captured" && note "ls-registration.xpl  captured"
else
    warn "LS registration not readable (needs sudo) — rebuild will ask for license entry"
    note "ls-registration.xpl  NOT CAPTURED (needs sudo)"
fi

# ── 3. Homebrew bundle ────────────────────────────────────────────────────────
BREW="$(command -v brew || echo /opt/homebrew/bin/brew)"
if [[ -x "$BREW" ]] || [[ -x /opt/homebrew/bin/brew ]]; then
    BREW="${BREW:-/opt/homebrew/bin/brew}"
    if guard_run "brew-bundle" "$BREW" bundle dump --force --file "$STATE/Brewfile"; then
        ok "Brewfile: $(grep -c '^\(brew\|cask\|tap\)' "$STATE/Brewfile" 2>/dev/null || echo '?') entries"
        note "Brewfile             $(wc -l < "$STATE/Brewfile" | tr -d ' ') lines"
    fi
else
    warn "Homebrew not found — no Brewfile"
    note "Brewfile             MISSING (no brew)"
fi

# ── 4. User LaunchAgents (evw/com.ew only) ────────────────────────────────────
n=0
for p in "$HOME"/Library/LaunchAgents/com.evw.*.plist "$HOME"/Library/LaunchAgents/com.ew.*.plist; do
    [[ -f "$p" ]] || continue
    cp "$p" "$STATE/launchagents/" && n=$((n+1))
done
ok "User LaunchAgents: $n plists captured"
note "launchagents/        $n plists"

# ── 5. /etc config: hosts + pf anchors ────────────────────────────────────────
[[ -r /etc/hosts ]] && cp /etc/hosts "$STATE/etc/hosts" && ok "/etc/hosts captured"
n=0
for a in /etc/pf.anchors/com.ew.*; do
    [[ -r "$a" ]] || continue
    cp "$a" "$STATE/etc/pf.anchors/" && n=$((n+1))
done
ok "pf anchors: $n captured"
note "etc/                 hosts + $n pf anchors"

# ── 6. disabled.501.plist entries ─────────────────────────────────────────────
DISABLED_PLIST=/var/db/com.apple.xpc.launchd/disabled.501.plist
if [[ $EUID -eq 0 && -r "$DISABLED_PLIST" ]]; then
    plutil -p "$DISABLED_PLIST" 2>/dev/null | grep -E '=> 1|=> true' | sed -E 's/^ *"([^"]+)".*/\1/' \
        > "$STATE/disabled-501-entries.txt"
    ok "disabled.501.plist: $(wc -l < "$STATE/disabled-501-entries.txt" | tr -d ' ') labels dumped (live)"
    note "disabled-501         LIVE DUMP"
elif [[ ! -s "$STATE/disabled-501-entries.txt" ]]; then
    # Seed with the documented core posture (SESSION.md) — sudo run refreshes
    cat > "$STATE/disabled-501-entries.txt" << 'EOF'
com.apple.replayd
com.apple.replaykit.sharingsession
com.apple.remotemanagementd
com.apple.sharingd
com.apple.identityservicesd
com.apple.replicatord
com.apple.studentd
com.apple.privatecloudcomputed
EOF
    warn "disabled.501.plist not readable — seeded documented core list (re-run with sudo for live dump)"
    note "disabled-501         SEEDED (core 8; refresh with sudo)"
else
    warn "disabled.501.plist not readable — keeping existing state file"
    note "disabled-501         kept existing"
fi

# ── 7. Tooling inventories (documentation for the rebuild, not auto-installed) ─
{ pyenv versions 2>/dev/null; } > "$STATE/pyenv-versions.txt" || true
{ pipx list --short 2>/dev/null; } > "$STATE/pipx-list.txt" || true
{ ls /Applications/ 2>/dev/null; } > "$STATE/apps.txt" || true
{ ls "$HOME/Library/Python"/*/bin/ots 2>/dev/null || echo "OTS CLIENT MISSING (reinstall opentimestamps-client)"; } \
    > "$STATE/ots-status.txt" || true
note "inventories          pyenv/pipx/apps/ots"

# ── 8. Manifest ───────────────────────────────────────────────────────────────
{
    echo "# rebuild state capture — $TS"
    echo "# machine: $(scutil --get LocalHostName 2>/dev/null) / macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
    printf '%s\n' "${MANIFEST[@]}"
} > "$STATE/CAPTURE-MANIFEST.txt"

echo ""
ok "State captured to $STATE"
cat "$STATE/CAPTURE-MANIFEST.txt"
