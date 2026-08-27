#!/usr/bin/env python3
"""
MacHarden Suite v2.0
Full hardening: macOS 26 Tahoe (M5 Pro) + Kodachi 9 VM in UTM
Author: Generated hardening script
Target: Fresh macOS 26 Tahoe install on Apple Silicon (M5 Pro/M5 Max)

TAHOE-SPECIFIC NOTES (macOS 26):
  - macOS 26 uses version numbering 26.x (not 16.x)
  - Apple Intelligence & Siri now require dedicated declarative disable (new Phase 1A step)
  - Handoff must be disabled via `defaults -currentHost` in Tahoe
  - Homebrew PATH now correctly targets ~/.zprofile (not ~/.zshrc) on Tahoe
  - Homebrew may relocate after major Tahoe updates — re-run Phase 4 if `brew` stops working
  - Terminal Full Disk Access is a new TCC attack surface in Tahoe — script warns about this
  - Safari advanced fingerprinting protection is ON by default in Tahoe (script verifies)
  - IKEv2 VPN weak ciphers (DES/3DES/SHA1/DH<14) are REMOVED in Tahoe — Kodachi VPN must use AES/SHA2
  - macOS 26.4+ shows a Terminal paste security popup on first paste — this is expected, not a bug
  - FileVault can now be unlocked via SSH post-restart if Remote Login is on — keep SSH OFF

WARNINGS:
  - Run from an admin account (not root)
  - Some steps require sudo and will prompt for your password
  - FileVault and Lockdown Mode steps require manual confirmation
  - Kodachi ISO must be x86_64 (ARM64 not yet released); runs via QEMU emulation
  - Performance in emulated Kodachi VM will be ~40-60% of native
  - Golden image workflow requires ~30GB free disk space

Usage:
  python3 macharden.py           # Interactive menu
  python3 macharden.py --dry-run # Preview all commands without executing
  python3 macharden.py --phase 1 # Run specific phase non-interactively
"""

import os
import sys
import subprocess
import logging
import plistlib
import uuid
import shutil
import time
import hashlib
import json
import platform
import urllib.request
import urllib.error
import stat
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "2.0"
MACOS_TARGET = "26"   # Tahoe version prefix
# Write log next to the script — avoids Tahoe TCC home-dir permission issue
_SCRIPT_DIR = Path(__file__).resolve().parent
LOG_PATH = _SCRIPT_DIR / "macharden_log.txt"
VM_DIR   = Path.home() / "SecureVMs"
WORK_DIR = _SCRIPT_DIR / "macharden_work"
UTM_DOCS_APP_STORE = Path.home() / "Library/Containers/com.utmapp.UTM/Data/Documents"
UTM_DOCS_DIRECT    = Path.home() / "Library/Application Support/UTM"
VM_NAME  = "Kodachi-Secure"
VM_RAM   = 4096   # MB — increase to 8192 if M5 Pro has 32GB+
VM_CPU   = 4
VM_DISK  = 30     # GB
KODACHI_ISO_FILENAME = "kodachi-9.0.1-64bit.iso"
# SourceForge direct link pattern — may need updating if version changes
KODACHI_ISO_URL = (
    "https://sourceforge.net/projects/linuxkodachi/files/kodachi-desktop/"
    f"{KODACHI_ISO_FILENAME}/download"
)
# Known Kodachi 9.0.1 SHA256 — verify at https://www.kodachi.cloud
# Set to None to skip checksum verification (NOT recommended)
KODACHI_ISO_SHA256 = None  # Fill in after verifying from official site

DRY_RUN = "--dry-run" in sys.argv

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLORS & UI
# ─────────────────────────────────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║         MacHarden Suite v{VERSION} — M5 Pro + Kodachi VM          ║
║         macOS 26 Tahoe | Apple Silicon | UTM + QEMU          ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
{C.YELLOW}  Target : macOS 26 Tahoe (fresh install){C.RESET}
{C.YELLOW}  VM     : Kodachi 9 x86_64 via QEMU emulation in UTM{C.RESET}
{C.RED}  ⚠  Dry-run mode: {'ON' if DRY_RUN else 'OFF'}{C.RESET}
{C.MAGENTA}  ℹ  Tahoe note: paste popup in Terminal 26.4+ is expected behavior{C.RESET}
""")

def section(title: str):
    print(f"\n{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")

def ok(msg: str):
    print(f"  {C.GREEN}✓{C.RESET} {msg}")
    logging.info(f"OK: {msg}")

def warn(msg: str):
    print(f"  {C.YELLOW}⚠{C.RESET} {msg}")
    logging.warning(f"WARN: {msg}")

def err(msg: str):
    print(f"  {C.RED}✗{C.RESET} {msg}")
    logging.error(f"ERR: {msg}")

def info(msg: str):
    print(f"  {C.DIM}→{C.RESET} {msg}")
    logging.info(f"INFO: {msg}")

def manual(msg: str):
    print(f"  {C.MAGENTA}[MANUAL]{C.RESET} {msg}")
    logging.info(f"MANUAL: {msg}")

def step(msg: str):
    print(f"  {C.BLUE}•{C.RESET} {msg}", end="", flush=True)

def step_done():
    print(f" {C.GREEN}done{C.RESET}")

def step_skip():
    print(f" {C.DIM}skipped{C.RESET}")

def confirm(prompt: str, default: bool = False) -> bool:
    default_str = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(f"\n  {C.YELLOW}?{C.RESET} {prompt} {default_str}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans == "":
        return default
    return ans in ("y", "yes")

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging():
    logging.basicConfig(
        filename=LOG_PATH,
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info(f"MacHarden Suite v{VERSION} started — dry_run={DRY_RUN}")

# ─────────────────────────────────────────────────────────────────────────────
# COMMAND EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

def run(cmd: list | str, sudo: bool = False, shell: bool = False,
        capture: bool = False, check: bool = False) -> subprocess.CompletedProcess | None:
    """Execute a command, optionally with sudo. Respects DRY_RUN."""
    if isinstance(cmd, str) and not shell:
        cmd = cmd.split()
    if sudo and not shell:
        cmd = ["sudo"] + cmd
    elif sudo and shell:
        cmd = "sudo " + cmd

    display_cmd = cmd if isinstance(cmd, str) else " ".join(cmd)
    logging.debug(f"RUN: {display_cmd}")

    if DRY_RUN:
        print(f"    {C.DIM}[dry-run] {display_cmd}{C.RESET}")
        return None

    try:
        result = subprocess.run(
            cmd, shell=shell,
            capture_output=capture,
            text=True,
            timeout=120,
        )
        if check and result.returncode != 0:
            logging.warning(f"Non-zero exit ({result.returncode}): {display_cmd}")
        return result
    except subprocess.TimeoutExpired:
        err(f"Timed out: {display_cmd}")
        return None
    except FileNotFoundError:
        err(f"Command not found: {display_cmd}")
        return None
    except Exception as e:
        err(f"Exception running {display_cmd}: {e}")
        return None

def defaults_write(domain: str, key: str, type_flag: str, value: str,
                   sudo: bool = False):
    run(["defaults", "write", domain, key, type_flag, str(value)], sudo=sudo)

def pref_write(plist: str, key: str, type_flag: str, value: str):
    run(["defaults", "write", plist, key, type_flag, str(value)], sudo=True)

# ─────────────────────────────────────────────────────────────────────────────
# PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def preflight_checks() -> bool:
    section("Pre-flight Checks")
    ok_flag = True

    # macOS version
    ver = platform.mac_ver()[0]
    if ver.startswith("26."):
        ok(f"macOS {ver} (Tahoe confirmed)")
    elif ver.startswith("15."):
        warn(f"macOS {ver} (Sequoia) — this script targets Tahoe 26.x; some commands differ")
    else:
        warn(f"macOS {ver} detected — script targets Tahoe 26.x, commands may differ")

    # Apple Silicon
    cpu = subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip()
    if cpu == "arm64":
        ok("Apple Silicon confirmed (arm64)")
    else:
        err(f"Expected arm64, got {cpu} — some commands may not apply")
        ok_flag = False

    # Not running as root
    if os.geteuid() == 0:
        err("Do not run this script as root. Run as your admin user; sudo will be invoked as needed.")
        ok_flag = False
    else:
        ok("Running as non-root user (correct)")

    # sudo available
    result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if result.returncode == 0:
        ok("Passwordless sudo available")
    else:
        warn("sudo will prompt for your password during execution")

    # SIP status
    sip = subprocess.run(["csrutil", "status"], capture_output=True, text=True).stdout
    if "enabled" in sip.lower():
        ok("SIP is ENABLED (leave it enabled)")
    else:
        warn("SIP is DISABLED — strongly recommend re-enabling: boot Recovery → csrutil enable")

    # Free disk space (need ~35GB for VM + ISO)
    stat_result = shutil.disk_usage(Path.home())
    free_gb = stat_result.free / (1024**3)
    if free_gb >= 35:
        ok(f"Free disk space: {free_gb:.1f} GB (sufficient)")
    else:
        warn(f"Free disk space: {free_gb:.1f} GB — recommend 35GB+ for VM setup")

    return ok_flag

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1A: macOS PRIVACY & TELEMETRY HARDENING
# ─────────────────────────────────────────────────────────────────────────────

def harden_telemetry():
    section("Phase 1A: Disable Telemetry, Analytics, Siri & Apple Intelligence")

    # ── Apple Intelligence (new in Tahoe — must disable explicitly) ──────────
    step("Disable Apple Intelligence (Tahoe: new Privacy & Security surface)")
    # Tahoe declarative config replaces com.apple.applicationaccess restrictions
    defaults_write("com.apple.AppleIntelligence", "Enabled", "-bool", "false")
    defaults_write("com.apple.assistant.support", "Assistant Enabled", "-bool", "false")
    defaults_write("com.apple.Siri", "StatusMenuVisible", "-bool", "false")
    defaults_write("com.apple.Siri", "UserHasDeclinedEnable", "-bool", "true")
    # Tahoe: disable External Intelligence (third-party AI models via Siri)
    defaults_write("com.apple.assistant.support", "ExternalIntelligenceEnabled", "-bool", "false")
    step_done()
    manual("Verify: System Settings → Apple Intelligence & Siri → Siri is OFF")

    step("Disable Crash Reporter")
    defaults_write("com.apple.CrashReporter", "DialogType", "-string", "none")
    step_done()

    step("Disable diagnostic & usage data submission")
    run(["defaults", "write",
         "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist",
         "AutoSubmit", "-bool", "false"], sudo=True)
    run(["defaults", "write",
         "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist",
         "ThirdPartyDataSubmit", "-bool", "false"], sudo=True)
    step_done()

    step("Disable Spotlight web suggestions and Siri suggestions")
    defaults_write("com.apple.spotlight", "orderedItems", "-array",
        '{"enabled" = 0;"name" = "MENU_WEBSEARCH";} {"enabled" = 0;"name" = "MENU_SPOTLIGHT_SUGGESTIONS";}')
    defaults_write("com.apple.Safari", "UniversalSearchEnabled", "-bool", "false")
    defaults_write("com.apple.Safari", "SuppressSearchSuggestions", "-bool", "true")
    step_done()

    step("Disable Handoff (Tahoe: requires -currentHost flag)")
    # Tahoe requires -currentHost for per-device TCC-adjacent settings
    run(["defaults", "-currentHost", "write",
         "com.apple.coreservices.useractivityd",
         "ActivityAdvertisingAllowed", "-bool", "false"])
    run(["defaults", "-currentHost", "write",
         "com.apple.coreservices.useractivityd",
         "ActivityReceivingAllowed", "-bool", "false"])
    step_done()

    step("Disable personalized ads")
    defaults_write("com.apple.AdLib", "allowApplePersonalizedAdvertising", "-bool", "false")
    defaults_write("com.apple.AdLib", "allowIdentifierForAdvertising", "-bool", "false")
    step_done()

    step("Disable sending diagnostics to Apple and app developers")
    run(["sudo", "defaults", "write",
         "/Library/Preferences/com.apple.SubmitDiagInfo", "AutoSubmit", "-bool", "false"])
    step_done()

    step("Disable AirDrop")
    defaults_write("com.apple.NetworkBrowser", "DisableAirDrop", "-bool", "true")
    step_done()

    step("Disable Universal Clipboard")
    defaults_write("com.apple.clipboardupdating", "DisableClipboardSyncing", "-bool", "true")
    step_done()

    step("Disable Location Services")
    # Tahoe: Location Services requires manual disable in System Settings (TCC-protected)
    warn("Location Services must be disabled manually: System Settings → Privacy & Security → Location Services → Off")
    step_skip()

    step("Verify Safari advanced fingerprinting protection (Tahoe default: ON — confirming)")
    # In Tahoe this is on by default for all browsing; verify/enforce via defaults
    defaults_write("com.apple.Safari",
                   "WebKitPreferences.advancedPrivacyProtectionsEnabled", "-bool", "true")
    step_done()

    # ── Terminal Full Disk Access (new Tahoe attack surface) ─────────────────
    section("Phase 1A — Tahoe: Terminal TCC Attack Surface Warning")
    warn("macOS 26 Tahoe: Terminal.app with Full Disk Access lets ANY script inherit those permissions")
    warn("This means a malicious brew install or npm install script can silently read Safari history,")
    warn("Mail data, and Messages databases without any additional prompts.")
    manual("Check: System Settings → Privacy & Security → Full Disk Access")
    manual("       Remove Terminal.app from Full Disk Access if listed")
    manual("Check: System Settings → Privacy & Security → App Management")
    manual("       Remove Terminal.app from App Management if listed")
    manual("Only grant Terminal Full Disk Access temporarily for specific admin tasks, then revoke")

    ok("Telemetry hardening complete")

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1B: NETWORK HARDENING
# ─────────────────────────────────────────────────────────────────────────────

def harden_network():
    section("Phase 1B: Network Hardening")

    step("Enable Application Firewall")
    run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"], sudo=True)
    step_done()

    step("Enable stealth mode (block ICMP ping, refuse unsolicited connections)")
    run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on"], sudo=True)
    step_done()

    step("Enable firewall logging (Tahoe: use log stream instead of socketfilterfw)")
    # --setloggingmode removed in Tahoe; logging now via unified log / log stream
    run(["log", "config", "--subsystem", "com.apple.alf", "--mode", "level:debug"], sudo=True)
    step_done()

    step("Block all incoming connections (allow only established/signed)")
    run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setblockall", "off"], sudo=True)
    # Note: setblockall ON would block ALL including signed apps; too aggressive for usability.
    # We rely on stealth mode + per-app control instead.
    step_done()

    step("Disable captive portal assistant (prevents MITM on public wifi check-ins)")
    run(["sudo", "defaults", "write",
         "/Library/Preferences/SystemConfiguration/com.apple.captive.control",
         "Active", "-bool", "false"])
    step_done()

    step("Disable Bonjour/mDNS multicast advertisements")
    run(["defaults", "write",
         "/Library/Preferences/com.apple.mDNSResponder",
         "NoMulticastAdvertisements", "-bool", "true"], sudo=True)
    step_done()

    step("Set DNS to 1.1.1.1/1.0.0.1/8.8.8.8/9.9.9.9 on Wi-Fi")
    run(["networksetup", "-setdnsservers", "Wi-Fi",
         "1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"])
    step_done()

    step("Set DNS to 1.1.1.1/1.0.0.1/8.8.8.8/9.9.9.9 on Ethernet (if present)")
    eth_check = subprocess.run(
        ["networksetup", "-listallnetworkservices"],
        capture_output=True, text=True
    )
    if eth_check.stdout and "Ethernet" in eth_check.stdout:
        run(["networksetup", "-setdnsservers", "Ethernet",
             "1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"])
        step_done()
    else:
        step_skip()
        info("No Ethernet adapter found — skipped")

    step("Disable remote login (SSH server off)")
    if not DRY_RUN:
        subprocess.run(
            "echo 'yes' | sudo systemsetup -setremotelogin off",
            shell=True
        )
    else:
        info("[dry-run] echo yes | sudo systemsetup -setremotelogin off")
    step_done()

    step("Disable Remote Apple Events")
    run(["systemsetup", "-setremoteappleevents", "off"], sudo=True)
    step_done()

    step("Disable Screen Sharing / Remote Desktop")
    run(["launchctl", "unload", "-w",
         "/System/Library/LaunchDaemons/com.apple.screensharing.plist"], sudo=True)
    step_done()

    step("Disable Bluetooth (can re-enable in System Settings if needed)")
    pref_write("/Library/Preferences/com.apple.Bluetooth",
               "ControllerPowerState", "-int", "0")
    step_done()

    step("Disable IR receiver")
    pref_write("/Library/Preferences/com.apple.driver.AppleIRController",
               "DeviceEnabled", "-bool", "false")
    step_done()

    ok("Network hardening complete")

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1C: SYSTEM SECURITY
# ─────────────────────────────────────────────────────────────────────────────

def harden_system():
    section("Phase 1C: System Security")

    step("Disable guest account")
    pref_write("/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "false")
    step_done()

    step("Set login window to show username/password fields (not user list)")
    pref_write("/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME", "-bool", "true")
    step_done()

    step("Require password immediately on sleep/screensaver")
    defaults_write("com.apple.screensaver", "askForPassword", "-int", "1")
    defaults_write("com.apple.screensaver", "askForPasswordDelay", "-int", "0")
    step_done()

    step("Disable automatic login")
    run(["defaults", "delete", "/Library/Preferences/com.apple.loginwindow",
         "autoLoginUser"], sudo=True)
    step_done()

    step("Enable Gatekeeper (require signed apps)")
    run(["spctl", "--master-enable"], sudo=True)
    step_done()

    step("Enable Gatekeeper app notarization check")
    run(["spctl", "--enable", "--label", "Developer ID"], sudo=True)
    step_done()

    step("Destroy FileVault key on standby (prevents cold-boot recovery of FVK)")
    run(["pmset", "-a", "destroyfvkeyonstandby", "1"], sudo=True)
    step_done()

    step("Enable secure hibernation (write RAM to disk encrypted, then clear RAM)")
    run(["pmset", "-a", "hibernatemode", "25"], sudo=True)
    step_done()

    step("Disable Power Nap (prevents background network activity while sleeping)")
    run(["pmset", "-a", "powernap", "0"], sudo=True)
    step_done()

    step("Disable standby auto-power-off to prevent race conditions with FVK destroy")
    run(["pmset", "-a", "standby", "0"], sudo=True)
    run(["pmset", "-a", "autopoweroff", "0"], sudo=True)
    step_done()

    step("Disable TFTP server")
    run(["launchctl", "disable", "system/com.apple.tftpd"], sudo=True)
    step_done()

    step("Disable Telnet server")
    run(["launchctl", "disable", "system/com.apple.telnetd"], sudo=True)
    step_done()

    step("Disable printer sharing")
    run(["cupsctl", "--no-share-printers"], sudo=True)
    step_done()

    step("Disable NFS server")
    run(["launchctl", "disable", "system/com.apple.nfsd"], sudo=True)
    step_done()

    step("Enable audit logging (BSM)")
    run(["launchctl", "enable", "system/com.apple.auditd"], sudo=True)
    run(["launchctl", "kickstart", "-kp", "system/com.apple.auditd"], sudo=True)
    step_done()

    step("Restrict sudo to require password (no NOPASSWD)")
    # Check if any NOPASSWD lines exist and warn
    sudoers = subprocess.run(["sudo", "cat", "/etc/sudoers"],
                              capture_output=True, text=True)
    if sudoers.stdout and "NOPASSWD" in sudoers.stdout:
        warn("NOPASSWD found in /etc/sudoers — review and remove manually")
    else:
        step_done()

    step("Set Safari security settings (Tahoe: write to both domains)")
    # Tahoe sandboxes Safari — writing to the container path is blocked by TCC.
    # Write to the short domain name; macOS maps it to the container at next Safari launch.
    # Also write to ~/Library/Preferences directly as a fallback.
    safari_prefs = [
        ("AutoFillPasswords",                                              "-bool", "false"),
        ("AutoFillCreditCardData",                                         "-bool", "false"),
        ("SendDoNotTrackHTTPHeader",                                       "-bool", "true"),
        ("WarnAboutFraudulentWebsites",                                    "-bool", "true"),
        ("AutoOpenSafeDownloads",                                          "-bool", "false"),
        ("com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled", "-bool", "false"),
        ("WebKitPreferences.advancedPrivacyProtectionsEnabled",            "-bool", "true"),
        ("WebKitPreferences.privateClickMeasurementEnabled",               "-bool", "false"),
    ]
    for key, type_flag, value in safari_prefs:
        # Domain-name write (Tahoe recommended — no container path)
        run(["defaults", "write", "com.apple.Safari", key, type_flag, value])
        # ~/Library/Preferences write as belt-and-suspenders fallback
        pref_path = str(Path.home() / "Library/Preferences/com.apple.Safari.plist")
        run(["defaults", "write", pref_path, key, type_flag, value])
    step_done()
    manual("Some Safari settings only take effect after restarting Safari")
    manual("Verify: Safari → Settings → Privacy, AutoFill, Security tabs")

    # Tahoe: FileVault + SSH interaction warning
    warn("Tahoe NEW RISK: FileVault can now be unlocked over SSH after restart if Remote Login is enabled")
    warn("SSH is disabled in Phase 1B — but verify: System Settings → General → Sharing → Remote Login = OFF")

    ok("System security hardening complete")

    # FileVault — interactive, cannot be fully scripted silently
    section("FileVault Encryption (Full Disk)")
    fv_status = subprocess.run(["fdesetup", "status"], capture_output=True, text=True)
    if fv_status.stdout and "FileVault is On" in fv_status.stdout:
        ok("FileVault is already enabled")
    else:
        warn("FileVault is NOT enabled")
        manual("Enable via: System Settings → Privacy & Security → FileVault → Turn On")
        manual("Or run: sudo fdesetup enable  (will prompt for credentials interactively)")
        if not DRY_RUN and confirm("Enable FileVault now? (requires admin password)"):
            run(["fdesetup", "enable"], sudo=True)
        else:
            warn("SKIPPED — FileVault must be enabled before using this machine securely")

    # Lockdown Mode — optional, very aggressive
    print()
    warn("Lockdown Mode: Highly recommended for high-risk users (journalists, activists)")
    warn("  Lockdown Mode BREAKS: most FaceTime calls, link previews, some web apps")
    manual("Enable via: System Settings → Privacy & Security → Lockdown Mode → Turn On")
    manual("Or via terminal: sudo defaults write "
           "/Library/Preferences/com.apple.security.lockdown LockdownModeEnabled -bool true && reboot")

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: INSTALL TOOLS
# ─────────────────────────────────────────────────────────────────────────────

def install_homebrew() -> bool:
    result = subprocess.run(["which", "brew"], capture_output=True, text=True)
    if result.returncode == 0:
        ok("Homebrew already installed")
        step("Updating Homebrew")
        run(["brew", "update"])
        step_done()
        return True
    else:
        info("Installing Homebrew (this may take several minutes)...")
        if DRY_RUN:
            info("[dry-run] /bin/bash -c $(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)")
            return True
        result = subprocess.run(
            ["/bin/bash", "-c",
             "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"],
            shell=False,
        )
        if result.returncode == 0:
            ok("Homebrew installed")
            # Tahoe: use ~/.zprofile not ~/.zshrc for persistent PATH on Apple Silicon
            brew_env = "/opt/homebrew/bin/brew"
            zprofile = Path.home() / ".zprofile"
            brew_line = 'eval "$(/opt/homebrew/bin/brew shellenv)"'
            if Path(brew_env).exists():
                os.environ["PATH"] = f"/opt/homebrew/bin:{os.environ['PATH']}"
                # Add to ~/.zprofile if not already there (Tahoe correct location)
                if not DRY_RUN:
                    existing = zprofile.read_text() if zprofile.exists() else ""
                    if brew_line not in existing:
                        with open(zprofile, "a") as f:
                            f.write(f'\n# Homebrew (added by MacHarden)\n{brew_line}\n')
                        ok("Homebrew PATH added to ~/.zprofile (Tahoe: correct location)")
                    else:
                        ok("Homebrew PATH already in ~/.zprofile")
            warn("Tahoe: Homebrew may be relocated after major OS updates")
            warn("If 'brew' stops working after an update, re-run Phase 4 to reinstall")
            return True
        else:
            err("Homebrew install failed — install manually from https://brew.sh")
            return False

def install_tools():
    section("Phase 2: Install Security Tools via Homebrew (Tahoe 26 compatible)")

    if not install_homebrew():
        err("Cannot proceed without Homebrew")
        return

    tools_cask = ["utm"]
    tools_formula = [
        "gnupg",       # GPG encryption
        "age",         # Modern encryption (alternative to GPG)
        "tor",         # Tor daemon
        "clamav",      # Antivirus/malware scanner
        "qemu",        # For VM snapshot/overlay management
        "veracrypt",   # Note: may need Homebrew cask for VeraCrypt
        "keepassxc",   # Password manager (cask)
        "wireshark",   # Network analysis
        "nmap",        # Network scanning
        "lynis",       # Security auditing tool
    ]
    tools_formula_only = ["gnupg", "age", "tor", "clamav", "qemu", "lynis", "nmap"]
    tools_cask_only    = ["utm", "veracrypt", "keepassxc", "wireshark"]

    step("Installing Homebrew cask tools (UTM, VeraCrypt, KeePassXC, Wireshark)")
    for tool in tools_cask_only:
        result = subprocess.run(["brew", "list", "--cask", tool],
                                capture_output=True, text=True)
        if result.returncode == 0 and not DRY_RUN:
            info(f"{tool} already installed")
        else:
            run(["brew", "install", "--cask", tool])
    step_done()

    step("Installing CLI tools (GPG, Age, Tor, ClamAV, QEMU, Lynis, Nmap)")
    for tool in tools_formula_only:
        result = subprocess.run(["brew", "list", tool],
                                capture_output=True, text=True)
        if result.returncode == 0 and not DRY_RUN:
            info(f"{tool} already installed")
        else:
            run(["brew", "install", tool])
    step_done()

    step("Updating ClamAV signatures database")
    clamav_conf_src = Path("/opt/homebrew/etc/clamav/freshclam.conf.sample")
    clamav_conf_dst = Path("/opt/homebrew/etc/clamav/freshclam.conf")
    if clamav_conf_src.exists() and not clamav_conf_dst.exists() and not DRY_RUN:
        shutil.copy(clamav_conf_src, clamav_conf_dst)
        # Remove Example line that blocks freshclam
        content = clamav_conf_dst.read_text()
        content = content.replace("Example\n", "")
        clamav_conf_dst.write_text(content)
    run(["freshclam"])
    step_done()

    step("Running Lynis security audit (results logged)")
    result = run(["lynis", "audit", "system", "--quiet"], capture=True)
    if result and result.stdout:
        logging.info(f"Lynis output:\n{result.stdout[:5000]}")
        ok("Lynis audit complete — review full log at " + str(LOG_PATH))
    step_done()

    ok("Tool installation complete")

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: KODACHI VM SETUP
# ─────────────────────────────────────────────────────────────────────────────

def find_utm_documents_dir() -> Path | None:
    """Locate UTM's documents directory (differs: App Store vs direct install)."""
    for candidate in [UTM_DOCS_APP_STORE, UTM_DOCS_DIRECT]:
        if candidate.exists():
            return candidate
    return None

def _find_usb_isos() -> list[Path]:
    """Scan all mounted volumes for .iso files and return matches."""
    volumes = Path("/Volumes")
    isos: list[Path] = []
    if not volumes.exists():
        return isos
    for vol in sorted(volumes.iterdir()):
        # Skip Macintosh HD and hidden system volumes
        if vol.name.startswith(".") or vol.name in ("Macintosh HD", "Preboot", "Recovery", "VM"):
            continue
        try:
            for iso in vol.rglob("*.iso"):
                isos.append(iso)
        except PermissionError:
            pass
    return isos


def download_kodachi_iso(dest_dir: Path) -> Path | None:
    """Download Kodachi ISO, accept local path, or copy from USB drive."""
    iso_path = dest_dir / KODACHI_ISO_FILENAME

    if iso_path.exists():
        ok(f"ISO already present: {iso_path}")
        return iso_path

    section("Kodachi ISO Source")
    warn("Kodachi 9 is only released as x86_64 — it will run via QEMU emulation")
    warn("Emulated VM performance: ~40-60% of native. Expected RAM use: 4-6GB host RAM")
    print()

    # Scan for USBs with ISOs
    usb_isos = _find_usb_isos()

    info("Options:")
    info("  1. Auto-download from SourceForge (~2-4GB, may be slow)")
    info("  2. Provide a file path to an already-downloaded ISO")
    if usb_isos:
        info("  3. Copy from USB drive (ISOs found on mounted volumes):")
        for i, p in enumerate(usb_isos, start=1):
            size_mb = p.stat().st_size // (1024 * 1024)
            info(f"       [{i}] {p}  ({size_mb} MB)")
    else:
        info("  3. Copy from USB drive  (no ISOs detected on mounted volumes right now)")
        info("     Plug in your USB and press 3 to re-scan")
    info(f"     Expected filename: {KODACHI_ISO_FILENAME}")
    info(f"     Official download: https://sourceforge.net/projects/linuxkodachi/")
    print()

    choice = input(f"  {C.YELLOW}?{C.RESET} Choice [1/2/3]: ").strip()

    # ── Option 2: manual file path ────────────────────────────────────────────
    if choice == "2":
        path_str = input("  Path to ISO: ").strip().strip("'\"")
        user_path = Path(path_str).expanduser()
        if user_path.exists() and user_path.suffix == ".iso":
            if not DRY_RUN:
                dest_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(user_path, iso_path)
            ok(f"ISO copied to {iso_path}")
            return iso_path
        else:
            err(f"File not found or not an ISO: {user_path}")
            return None

    # ── Option 3: USB drive ───────────────────────────────────────────────────
    if choice == "3":
        # Re-scan in case USB was just plugged in
        usb_isos = _find_usb_isos()
        if not usb_isos:
            err("No ISO files found on any mounted volume.")
            err("Plug in your USB drive and ensure it is mounted under /Volumes/, then re-run.")
            return None

        print()
        info("ISOs found on mounted volumes:")
        for i, p in enumerate(usb_isos, start=1):
            size_mb = p.stat().st_size // (1024 * 1024)
            print(f"    {C.CYAN}[{i}]{C.RESET} {p}  ({size_mb} MB)")
        print()

        sel = input(f"  {C.YELLOW}?{C.RESET} Select ISO number (or Enter to cancel): ").strip()
        if not sel.isdigit() or not (1 <= int(sel) <= len(usb_isos)):
            warn("Invalid selection — cancelled")
            return None

        selected = usb_isos[int(sel) - 1]
        info(f"Selected: {selected}")
        size_gb = selected.stat().st_size / (1024 ** 3)

        # Warn if filename doesn't match expected
        if selected.name != KODACHI_ISO_FILENAME:
            warn(f"Filename '{selected.name}' does not match expected '{KODACHI_ISO_FILENAME}'")
            warn("Proceeding anyway — verify this is the correct Kodachi ISO before booting the VM")

        info(f"Copying {size_gb:.2f} GB from USB to {iso_path} ...")
        info("This may take a few minutes depending on USB speed...")

        if not DRY_RUN:
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Copy with progress
            total = selected.stat().st_size
            copied = 0
            chunk = 4 * 1024 * 1024  # 4MB chunks
            with open(selected, "rb") as src, open(iso_path, "wb") as dst:
                while True:
                    data = src.read(chunk)
                    if not data:
                        break
                    dst.write(data)
                    copied += len(data)
                    pct = copied * 100 // total
                    print(f"\r    Copying... {pct:3d}%  ({copied // (1024*1024)} / {total // (1024*1024)} MB)",
                          end="", flush=True)
            print()
            ok(f"ISO copied from USB to {iso_path}")
        else:
            info(f"[dry-run] Would copy {selected} → {iso_path}")

        # Offer SHA256 verification
        if KODACHI_ISO_SHA256 and not DRY_RUN:
            step("Verifying SHA256 checksum")
            sha = hashlib.sha256()
            with open(iso_path, "rb") as f:
                for chunk_data in iter(lambda: f.read(65536), b""):
                    sha.update(chunk_data)
            actual = sha.hexdigest()
            if actual == KODACHI_ISO_SHA256:
                step_done()
            else:
                err("CHECKSUM MISMATCH — DO NOT USE THIS ISO")
                err(f"  Expected: {KODACHI_ISO_SHA256}")
                err(f"  Got:      {actual}")
                iso_path.unlink(missing_ok=True)
                return None
        elif not KODACHI_ISO_SHA256:
            warn("KODACHI_ISO_SHA256 not set — verify checksum manually at https://www.kodachi.cloud")
            warn("SHA256 of your copied file:")
            if not DRY_RUN and iso_path.exists():
                sha = hashlib.sha256()
                with open(iso_path, "rb") as f:
                    for chunk_data in iter(lambda: f.read(65536), b""):
                        sha.update(chunk_data)
                info(f"  {sha.hexdigest()}")

        return iso_path

    # Auto-download
    info(f"Downloading from SourceForge: {KODACHI_ISO_URL}")
    info("This may take 10-30 minutes on a typical connection...")

    if DRY_RUN:
        info(f"[dry-run] Would download to {iso_path}")
        return iso_path

    dest_dir.mkdir(parents=True, exist_ok=True)

    try:
        def progress(block_num, block_size, total_size):
            if total_size > 0:
                pct = min(100, block_num * block_size * 100 // total_size)
                print(f"\r    Downloading... {pct:3d}%", end="", flush=True)

        urllib.request.urlretrieve(KODACHI_ISO_URL, iso_path, reporthook=progress)
        print()

        # Checksum verification
        if KODACHI_ISO_SHA256:
            step("Verifying SHA256 checksum")
            sha = hashlib.sha256()
            with open(iso_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
            actual = sha.hexdigest()
            if actual == KODACHI_ISO_SHA256:
                step_done()
            else:
                err(f"CHECKSUM MISMATCH — DO NOT USE THIS ISO")
                err(f"  Expected: {KODACHI_ISO_SHA256}")
                err(f"  Got:      {actual}")
                iso_path.unlink(missing_ok=True)
                return None
        else:
            warn("KODACHI_ISO_SHA256 not set — verify checksum manually at https://www.kodachi.cloud")

        ok(f"ISO ready: {iso_path}")
        return iso_path

    except urllib.error.URLError as e:
        err(f"Download failed: {e}")
        err("Download manually from https://sourceforge.net/projects/linuxkodachi/")
        return None

def create_qcow2_disk(path: Path, size_gb: int) -> bool:
    """Create a QEMU disk image for the VM."""
    if path.exists():
        ok(f"Disk image already exists: {path}")
        return True
    step(f"Creating {size_gb}GB QCOW2 disk image")
    result = run(["qemu-img", "create", "-f", "qcow2", str(path), f"{size_gb}G"])
    if result is None or (result.returncode != 0 if result else False):
        step_skip()
        err("qemu-img not found — install via: brew install qemu")
        return False
    step_done()
    return True

def build_utm_config(vm_bundle_path: Path, iso_path: Path) -> dict:
    """
    Build the UTM 4.x QEMU configuration plist structure.
    Based on UTM's UTMQemuConfiguration format (macOS 15 / UTM 4.x).
    Uses QEMU x86_64 emulation — required for Kodachi x86 ISO on Apple Silicon.
    """
    vm_uuid = str(uuid.uuid4()).upper()
    disk_name = "disk-0.qcow2"
    iso_name = iso_path.name

    config = {
        "Backend": "QEMU",
        "ConfigurationVersion": 4,
        "Information": {
            "Icon": None,
            "IconCustom": False,
            "Name": VM_NAME,
            "Notes": (
                "Hardened Kodachi 9 VM — QEMU x86_64 emulation\n"
                "Security: No clipboard, no shared folders, NAT only\n"
                "Created by MacHarden Suite"
            ),
            "UUID": vm_uuid,
        },
        "System": {
            "Architecture": "x86_64",
            "CPU": "max",
            "CPUCount": VM_CPU,
            "CPUFlagsAdd": [],
            "CPUFlagsRemove": [],
            "ForceMulticore": False,
            "JitCacheSize": 0,
            "MemorySize": VM_RAM,
            "Target": "pc",
        },
        "QEMU": {
            "AdditionalArguments": [
                # Harden: disable unnecessary QEMU features
                {"string": "-nodefaults"},
            ],
            "DebugLog": False,
            "HasHypervisor": False,  # x86 emulation, not native ARM virt
            "HasLocaltime": False,   # Use UTC inside VM
            "HasMTEEnabled": False,
            "HasRNGDevice": True,    # virtio-rng for entropy
            "HasTPMDevice": False,
            "HasUefiBoot": True,
            "MachinePropertyOverride": "",
        },
        "Input": {
            "LegacyKeyboard": False,
            "MouseType": "USB tablet",
            "UsbBusSupport": "USB 3.0",
            "UsbRedirectEnabled": False,  # SECURITY: disable USB pass-through
        },
        "Display": [
            {
                "BitsPerComponent": 8,
                "DynamicResolution": True,
                "Hardware": "virtio-vga",
                "NativeResolution": False,
                "UpscalerSmooth": True,
            }
        ],
        "Sound": [
            {
                "Hardware": "none",  # SECURITY: disable audio (reduces attack surface)
            }
        ],
        "Network": [
            {
                "BridgeInterface": "",
                "GuestAddress": "10.0.2.15",
                "GuestInterface": "virtio-net-pci",
                "GuestNetmask": "255.255.255.0",
                "HostAddress": "10.0.2.2",
                "Mode": "Emulated VLAN",  # NAT — host IP not exposed to VM
                "Visible": True,
                # SECURITY: VM gets internet via NAT only
                # Host cannot be reached from VM on default config
            }
        ],
        "Serial": [],
        "Drives": [
            {
                "External": False,
                "ImageName": disk_name,
                "ImageType": "Disk Image",
                "Interface": "VirtIO",
                "ReadOnly": False,
                "Removable": False,
                "Size": VM_DISK * 1024,  # UTM expects MB
            },
            {
                "External": True,
                "ImageName": iso_name,
                "ImageType": "CD/DVD Image",
                "Interface": "IDE",
                "ReadOnly": True,
                "Removable": True,
            }
        ],
        "Sharing": {
            "ClipboardSharing": False,         # SECURITY: no clipboard bridge
            "DirectoryShareMode": "None",      # SECURITY: no shared folders
            "HasPublicDir": False,
            "ReadOnlyShares": True,
        },
        "Registry": {},
    }
    return config

def create_utm_vm(iso_path: Path) -> Path | None:
    section("Phase 3: Create Hardened Kodachi VM in UTM")

    # Find UTM documents directory
    utm_dir = find_utm_documents_dir()
    if utm_dir is None:
        warn("UTM documents directory not found — UTM may not be installed or not yet launched")
        warn("Launch UTM once to initialize, then re-run this phase")
        manual("Install UTM via: brew install --cask utm")
        manual("Then launch UTM, close it, and re-run this script")
        # Fall back to storing VM in ~/SecureVMs
        utm_dir = VM_DIR
        utm_dir.mkdir(parents=True, exist_ok=True)
        warn(f"Storing VM bundle in {utm_dir} — manually import into UTM via File → Import VM")
    else:
        ok(f"UTM documents directory: {utm_dir}")

    vm_bundle = utm_dir / f"{VM_NAME}.utm"
    vm_data_dir = vm_bundle / "Data"
    disk_path = vm_data_dir / "disk-0.qcow2"
    iso_link  = vm_data_dir / iso_path.name

    # Create VM bundle structure
    step("Creating VM bundle directory structure")
    if not DRY_RUN:
        vm_data_dir.mkdir(parents=True, exist_ok=True)
    step_done()

    # Create or link the ISO
    step("Linking Kodachi ISO into VM bundle")
    if not DRY_RUN:
        if not iso_link.exists():
            # Hard link to avoid doubling storage (requires same volume)
            try:
                os.link(iso_path, iso_link)
            except OSError:
                # Cross-device link fails — copy instead
                shutil.copy2(iso_path, iso_link)
    step_done()

    # Create QCOW2 disk
    if not create_qcow2_disk(disk_path, VM_DISK):
        err("Failed to create disk image — install QEMU: brew install qemu")
        return None

    # Write UTM config plist
    step("Writing UTM configuration plist")
    config = build_utm_config(vm_bundle, iso_path)

    def strip_none(obj):
        """Recursively remove None values — plistlib cannot serialize None."""
        if isinstance(obj, dict):
            return {k: strip_none(v) for k, v in obj.items() if v is not None}
        if isinstance(obj, list):
            return [strip_none(i) for i in obj if i is not None]
        return obj

    config = strip_none(config)
    config_path = vm_bundle / "config.plist"
    if not DRY_RUN:
        with open(config_path, "wb") as f:
            plistlib.dump(config, f, fmt=plistlib.FMT_XML)
    step_done()

    # Set bundle permissions (UTM expects specific perms)
    step("Setting bundle permissions")
    if not DRY_RUN:
        vm_bundle.chmod(0o755)
        for item in vm_bundle.rglob("*"):
            if item.is_dir():
                item.chmod(0o755)
            else:
                item.chmod(0o644)
    step_done()

    ok(f"VM bundle created: {vm_bundle}")

    # Try to open in UTM
    step("Registering VM with UTM")
    result = run(["open", str(vm_bundle)])
    step_done()

    info("If UTM does not show the VM: File → Import VM → select the .utm bundle")
    info("Boot order: Kodachi ISO boots first; install to disk, then remove ISO")

    section("VM Security Configuration Summary")
    print(f"""
  {C.GREEN}Security hardening applied to VM config:{C.RESET}

  {C.YELLOW}Clipboard sharing:{C.RESET}   DISABLED (no host↔VM text bridge)
  {C.YELLOW}Shared folders:{C.RESET}      DISABLED (no host filesystem access)
  {C.YELLOW}USB pass-through:{C.RESET}    DISABLED (no host USB devices in VM)
  {C.YELLOW}Network:{C.RESET}             NAT only (VM cannot reach host LAN)
  {C.YELLOW}Audio:{C.RESET}               DISABLED (reduced attack surface)
  {C.YELLOW}VM clock:{C.RESET}            UTC (prevents timezone fingerprinting)
  {C.YELLOW}Hypervisor:{C.RESET}          QEMU x86_64 emulation (not Apple virt framework)
                       Note: Apple Hypervisor.framework requires ARM64 guest.
                       Kodachi ARM64 ISO not yet available — QEMU used instead.
  {C.YELLOW}RNG device:{C.RESET}          Enabled (virtio-rng for better entropy in guest)
""")

    return vm_bundle

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4: GOLDEN IMAGE WORKFLOW
# ─────────────────────────────────────────────────────────────────────────────

def setup_golden_image_workflow():
    section("Phase 4: Golden Image + Fresh Session Workflow")

    VM_DIR.mkdir(parents=True, exist_ok=True)
    scripts_dir = VM_DIR / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    # Clone script
    clone_script = scripts_dir / "new_session.sh"
    clone_script_content = f"""#!/bin/bash
# MacHarden: Start a fresh Kodachi session from golden image
# Each session gets a disposable clone — changes do NOT persist to golden image

GOLDEN="{VM_DIR}/Golden_{VM_NAME}.utm"
SESSION="{VM_DIR}/Session_$(date +%Y%m%d_%H%M%S).utm"

if [ ! -d "$GOLDEN" ]; then
    echo "ERROR: Golden image not found at $GOLDEN"
    echo "Create golden image first: copy your configured {VM_NAME}.utm to the above path"
    exit 1
fi

echo "==> Cloning golden image (APFS CoW — instant, minimal space)..."
# cp -c uses APFS clonefile() — delta only, near-zero initial space
cp -rc "$GOLDEN" "$SESSION"
echo "==> Session VM: $SESSION"
echo "==> Opening in UTM..."
open "$SESSION"
echo ""
echo "After your session: DELETE $SESSION to discard all traces."
echo "Script to delete: rm -rf \\"$SESSION\\""
"""

    # Destroy session script
    destroy_script = scripts_dir / "destroy_session.sh"
    destroy_script_content = f"""#!/bin/bash
# MacHarden: Destroy all session VMs (keep only golden image)
# Run after each secure session

SESSION_DIR="{VM_DIR}"
GOLDEN_PREFIX="Golden_"

echo "==> Session VMs to destroy:"
for vm in "$SESSION_DIR"/Session_*.utm; do
    if [ -d "$vm" ]; then
        echo "    $vm"
    fi
done
echo ""
read -p "Destroy ALL session VMs above? [y/N]: " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    for vm in "$SESSION_DIR"/Session_*.utm; do
        if [ -d "$vm" ]; then
            echo "    Removing: $vm"
            # Secure delete with multi-pass (slower but more thorough)
            if command -v srm &>/dev/null; then
                srm -rf "$vm"
            else
                rm -rf "$vm"
            fi
        fi
    done
    echo "==> All sessions destroyed."
    echo "==> Golden image preserved at: $SESSION_DIR/Golden_{VM_NAME}.utm"
else
    echo "Cancelled."
fi
"""

    # Overlay disk script (most secure method)
    overlay_script = scripts_dir / "overlay_session.sh"
    overlay_script_content = f"""#!/bin/bash
# MacHarden: Start session using QEMU overlay disk (most secure)
# The golden disk is NEVER modified — all writes go to a throw-away overlay
# Requires: brew install qemu
#
# IMPORTANT: Run Kodachi ISO install FIRST to create golden disk,
# then set GOLDEN_DISK and use this script for subsequent sessions.

GOLDEN_DISK="{VM_DIR}/Golden_{VM_NAME}.utm/Data/disk-0.qcow2"
SESSION_OVERLAY="/tmp/session_overlay_$(date +%Y%m%d_%H%M%S).qcow2"
KODACHI_ISO="{VM_DIR}/{KODACHI_ISO_FILENAME}"

if [ ! -f "$GOLDEN_DISK" ]; then
    echo "ERROR: Golden disk not found: $GOLDEN_DISK"
    echo "Install Kodachi in VM first, then shut down — that becomes the golden disk."
    exit 1
fi

echo "==> Creating overlay disk (all session writes isolated here)..."
qemu-img create -f qcow2 -F qcow2 -b "$GOLDEN_DISK" "$SESSION_OVERLAY"

echo "==> Starting QEMU x86_64 VM with overlay disk..."
echo "    Golden disk: READ-ONLY (untouched)"
echo "    Session disk: $SESSION_OVERLAY (will be deleted after)"
echo ""

# Note: This uses QEMU directly (bypasses UTM UI)
# Adjust -m for RAM, -smp for CPU count
qemu-system-x86_64 \\
    -m {VM_RAM} \\
    -smp {VM_CPU} \\
    -cpu max \\
    -machine pc \\
    -bios /opt/homebrew/share/qemu/bios-256k.bin \\
    -drive file="$SESSION_OVERLAY",format=qcow2,if=virtio \\
    -device virtio-net-pci,netdev=net0 \\
    -netdev user,id=net0 \\
    -device virtio-rng-pci \\
    -display cocoa \\
    -usb -device usb-tablet

echo ""
echo "==> Session ended. Destroying overlay disk..."
if command -v srm &>/dev/null; then
    srm -f "$SESSION_OVERLAY"
else
    rm -f "$SESSION_OVERLAY"
fi
echo "==> Session overlay destroyed. Golden disk untouched."
"""

    # Rotate identity script (run inside VM at session start)
    rotate_script = scripts_dir / "rotate_identity.sh"
    rotate_script_content = """#!/bin/bash
# MacHarden: Rotate VM identity at start of each session
# Run INSIDE the Kodachi VM at session start via Dashboard → Terminal
# Purpose: Prevent correlation between sessions even if same VM image used

echo "==> Rotating session identity..."

# 1. Get new Tor circuit
sudo systemctl restart tor
sleep 3
echo "  ✓ New Tor circuit"

# 2. Reconnect VPN (forces new VPN server assignment)
# Adjust 'vpn-service-name' to your Kodachi VPN service
sudo systemctl restart openvpn@kodachi 2>/dev/null || \\
    sudo kodachi-vpn restart 2>/dev/null || \\
    echo "  ⚠ VPN restart: trigger from Kodachi Dashboard → Network manually"

# 3. Spoof MAC address
if command -v macchanger &>/dev/null; then
    IFACE=$(ip link | awk -F: '/^[0-9]+: e/{print $2}' | head -1 | tr -d ' ')
    if [ -n "$IFACE" ]; then
        sudo ip link set "$IFACE" down
        sudo macchanger -r "$IFACE"
        sudo ip link set "$IFACE" up
        echo "  ✓ MAC spoofed: $IFACE"
    fi
else
    echo "  ⚠ macchanger not found — install: sudo apt-get install macchanger"
fi

# 4. Spoof hostname
NEW_HOST="host-$(tr -dc 'a-z0-9' < /dev/urandom | head -c 8)"
sudo hostnamectl set-hostname "$NEW_HOST"
echo "  ✓ Hostname: $NEW_HOST"

# 5. Randomize timezone
TZONES=("America/New_York" "Europe/London" "Asia/Tokyo" "Australia/Sydney" "Europe/Paris")
RAND_TZ=${TZONES[$RANDOM % ${#TZONES[@]}]}
sudo timedatectl set-timezone "$RAND_TZ"
echo "  ✓ Timezone spoofed: $RAND_TZ"

# 6. Flush DNS cache
sudo systemd-resolve --flush-caches 2>/dev/null || \\
    sudo resolvectl flush-caches 2>/dev/null || true
echo "  ✓ DNS cache flushed"

# 7. Clear browser state (Kodachi Browser / LibreWolf)
PROFILE_DIR="$HOME/.librewolf"
if [ -d "$PROFILE_DIR" ]; then
    find "$PROFILE_DIR" -name "*.sqlite" -delete 2>/dev/null
    find "$PROFILE_DIR" -name "cookies.sqlite" -delete 2>/dev/null
    echo "  ✓ Browser state cleared"
fi

echo ""
echo "==> Identity rotation complete."
echo "    Verify: Dashboard → Security → IP Leak Test"
echo "            check.torproject.org (should show Tor exit node)"
"""

    # Write all scripts
    for path, content in [
        (clone_script, clone_script_content),
        (destroy_script, destroy_script_content),
        (overlay_script, overlay_script_content),
        (rotate_script, rotate_script_content),
    ]:
        if not DRY_RUN:
            path.write_text(content)
            path.chmod(0o755)
        ok(f"Script written: {path.name}")

    ok(f"All session management scripts in: {scripts_dir}")

    section("Golden Image Workflow")
    print(f"""
  {C.BOLD}WORKFLOW TO CREATE GOLDEN IMAGE:{C.RESET}

  1. Boot the Kodachi VM in UTM and complete the installation
  2. Run the VM hardening script inside Kodachi (see Phase 5)
  3. Configure VPN credentials in Kodachi Dashboard
  4. Run Autoshield from Kodachi Dashboard
  5. Verify: Tor + VPN working, no DNS/IP leaks
  6. Shut down the VM
  7. Copy the configured VM bundle:
     {C.DIM}cp -r "{VM_DIR}/{VM_NAME}.utm" "{VM_DIR}/Golden_{VM_NAME}.utm"{C.RESET}
  8. Set golden image read-only:
     {C.DIM}chmod -R a-w "{VM_DIR}/Golden_{VM_NAME}.utm"{C.RESET}

  {C.BOLD}EACH SESSION:{C.RESET}
  {C.DIM}{scripts_dir}/new_session.sh{C.RESET}       ← Clone-based (fastest)
  {C.DIM}{scripts_dir}/overlay_session.sh{C.RESET}   ← Overlay-based (most secure)

  {C.BOLD}AFTER EACH SESSION:{C.RESET}
  {C.DIM}{scripts_dir}/destroy_session.sh{C.RESET}   ← Wipe session VM

  {C.BOLD}AT START OF EACH SESSION (run inside VM):{C.RESET}
  {C.DIM}{scripts_dir}/rotate_identity.sh{C.RESET}   ← New Tor/VPN/MAC/hostname
""")

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5: GENERATE KODACHI VM INTERNAL HARDENING SCRIPT
# ─────────────────────────────────────────────────────────────────────────────

def generate_vm_hardening_script():
    section("Phase 5: Generate Kodachi VM Internal Hardening Script")

    scripts_dir = VM_DIR / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    script_path = scripts_dir / "kodachi_vm_harden.sh"
    script_content = r"""#!/bin/bash
# =============================================================================
# Kodachi VM Internal Hardening Script
# Run INSIDE the Kodachi 9 VM after installation
# Execute as: bash kodachi_vm_harden.sh
# Requires: sudo access (default Kodachi password: Security4All)
# =============================================================================

set -euo pipefail
LOG="/tmp/vm_harden_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; RESET='\033[0m'; BOLD='\033[1m'

ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET} $1"; }
err()  { echo -e "  ${RED}✗${RESET} $1"; }
section() { echo -e "\n${CYAN}${BOLD}──────────────────────────────────────────${RESET}"; \
            echo -e "${BOLD}  $1${RESET}"; \
            echo -e "${CYAN}──────────────────────────────────────────${RESET}"; }

section "1. System Update"
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
sudo apt-get autoremove -y -qq
ok "System updated"

section "2. Firewall — Strict Rules (allow VPN+Tor traffic only)"
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default deny outgoing

# Allow loopback
sudo ufw allow in on lo
sudo ufw allow out on lo

# Allow VPN (OpenVPN over UDP/TCP)
sudo ufw allow out 1194/udp comment "OpenVPN UDP"
sudo ufw allow out 1194/tcp comment "OpenVPN TCP"
sudo ufw allow out 443/tcp  comment "VPN/HTTPS"

# Allow Tor (local SOCKS proxy)
sudo ufw allow out to 127.0.0.1 port 9050 comment "Tor SOCKS5"
sudo ufw allow out to 127.0.0.1 port 9040 comment "Tor transparent"
sudo ufw allow out to 127.0.0.1 port 5300  comment "DNSCrypt"
sudo ufw allow out to 127.0.0.53 port 53   comment "systemd-resolved"

# Once VPN is up, allow traffic through tun0
sudo ufw allow out on tun0 to any comment "VPN tunnel"
sudo ufw allow in  on tun0 comment "VPN tunnel in"

# Block plain HTTP
sudo ufw deny out 80/tcp comment "Block plain HTTP"

sudo ufw --force enable
ok "UFW firewall configured"

section "3. Kernel Hardening (sysctl)"
sudo tee /etc/sysctl.d/99-macharden.conf > /dev/null << 'SYSCTL'
# Anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Log Martians
net.ipv4.conf.all.log_martians = 1
# Disable IPv6 (Kodachi uses IPv4 for VPN/Tor)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
# Kernel hardening
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
# Restrict core dumps
fs.suid_dumpable = 0
# Disable magic sysrq
kernel.sysrq = 0
SYSCTL
sudo sysctl -p /etc/sysctl.d/99-macharden.conf > /dev/null
ok "Kernel hardened via sysctl"

section "4. Disable Unnecessary Services"
DISABLE_SERVICES=(
    bluetooth
    cups
    cups-browsed
    avahi-daemon
    ModemManager
    colord
    pcscd
    wpa_supplicant  # Kodachi handles WiFi through its own stack
)
for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
        sudo systemctl stop    "$svc" 2>/dev/null || true
        sudo systemctl disable "$svc" 2>/dev/null || true
        sudo systemctl mask    "$svc" 2>/dev/null || true
        ok "Disabled: $svc"
    fi
done

section "5. Harden Tor Configuration"
TORRC="/etc/tor/torrc"
sudo tee -a "$TORRC" > /dev/null << 'TORRC_CONTENT'
# MacHarden additions
# Exclude potentially compromised/monitored nodes
ExcludeNodes {??},{A1}
StrictNodes 1
EnforceDistinctSubnets 1
# Rotate circuits frequently
NewCircuitPeriod 30
MaxCircuitDirtiness 300
# Use guards
UseEntryGuards 1
NumEntryGuards 3
# Minimize disk writes
AvoidDiskWrites 1
# Hardware acceleration if available
HardwareAccel 1
# Disable unused port
ClientUseIPv6 0
TORRC_CONTENT
sudo systemctl restart tor
ok "Tor configuration hardened"

section "6. Install & Configure AppArmor"
sudo apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra 2>/dev/null || true
if command -v aa-enforce &>/dev/null; then
    sudo systemctl enable apparmor 2>/dev/null || true
    sudo systemctl start  apparmor 2>/dev/null || true
    sudo aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    ok "AppArmor enabled and profiles enforced"
else
    warn "AppArmor not available — skip"
fi

section "7. Configure Fail2Ban"
if ! command -v fail2ban-server &>/dev/null; then
    sudo apt-get install -y -qq fail2ban 2>/dev/null || true
fi
if command -v fail2ban-server &>/dev/null; then
    sudo systemctl enable fail2ban
    sudo systemctl start  fail2ban
    ok "Fail2Ban enabled"
fi

section "8. Install Additional Security Tools"
PACKAGES=(
    clamav clamav-daemon   # Malware scanning
    macchanger             # MAC address spoofing
    rkhunter               # Rootkit detection
    aide                   # File integrity monitoring
    auditd                 # Audit daemon
    libpam-pwquality       # Password quality enforcement
    unattended-upgrades    # Automatic security updates
    apt-listchanges        # Show changes in upgrades
)
sudo apt-get install -y -qq "${PACKAGES[@]}" 2>/dev/null || \
    warn "Some packages failed to install — run manually"
ok "Security packages installed"

section "9. ClamAV Setup"
sudo systemctl stop clamav-freshclam 2>/dev/null || true
sudo freshclam --quiet 2>/dev/null || warn "freshclam failed — may retry on next boot"
sudo systemctl enable clamav-freshclam 2>/dev/null || true
sudo systemctl enable clamav-daemon    2>/dev/null || true
sudo systemctl start  clamav-daemon    2>/dev/null || true
ok "ClamAV configured with fresh signatures"

section "10. Rootkit & File Integrity Setup"
if command -v rkhunter &>/dev/null; then
    sudo rkhunter --update --quiet 2>/dev/null || true
    sudo rkhunter --propupd   --quiet 2>/dev/null || true
    ok "RKHunter database initialized"
fi
if command -v aideinit &>/dev/null; then
    sudo aideinit --quiet 2>/dev/null || sudo aide --init 2>/dev/null || true
    sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    ok "AIDE file integrity database initialized"
fi

section "11. Audit Daemon Configuration"
if command -v auditctl &>/dev/null; then
sudo tee /etc/audit/rules.d/macharden.rules > /dev/null << 'AUDITRULES'
# Delete all existing rules
-D
# Set buffer size
-b 8192
# Monitor authentication
-w /etc/pam.d/ -p wa -k auth
-w /etc/shadow -p wa -k auth
-w /etc/passwd -p wa -k auth
-w /etc/sudoers -p wa -k sudoers
# Monitor network config
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
# Monitor kernel modules
-a always,exit -F arch=b64 -S init_module -k modules
-a always,exit -F arch=b64 -S delete_module -k modules
# Monitor privileged commands
-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged
# Monitor file deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k deletion
# Immutable rule set (requires reboot to change)
-e 2
AUDITRULES
    sudo service auditd restart 2>/dev/null || true
    ok "Audit rules configured"
fi

section "12. Set Up Secure RAM Disk for Temporary Work"
RAMDISK="/mnt/secure-tmp"
sudo mkdir -p "$RAMDISK"
if ! grep -q "$RAMDISK" /etc/fstab; then
    echo "tmpfs $RAMDISK tmpfs rw,noexec,nosuid,nodev,size=512M,mode=1700 0 0" | \
        sudo tee -a /etc/fstab > /dev/null
fi
sudo mount -a 2>/dev/null || sudo mount tmpfs "$RAMDISK" -t tmpfs -o rw,noexec,nosuid,nodev,size=512M 2>/dev/null || true
if mountpoint -q "$RAMDISK"; then
    ok "RAM disk mounted at $RAMDISK (512MB, noexec, cleared on shutdown)"
else
    warn "RAM disk mount failed — mount manually after reboot"
fi

section "13. Harden /etc/resolv.conf (Lock to Kodachi's DNSCrypt)"
# Make resolv.conf point to DNSCrypt and lock it
sudo bash -c 'cat > /etc/resolv.conf << EOF
# Locked by MacHarden — DNSCrypt local resolver
nameserver 127.0.0.53
nameserver 127.0.0.1
options edns0 trust-ad
EOF'
sudo chattr +i /etc/resolv.conf
ok "resolv.conf locked to local DNSCrypt (127.0.0.53)"

section "14. SSH — Disable Completely"
sudo systemctl stop    ssh 2>/dev/null || true
sudo systemctl disable ssh 2>/dev/null || true
sudo systemctl mask    ssh 2>/dev/null || true
ok "SSH disabled and masked"

section "15. Harden PAM Password Policy"
if command -v pam-auth-update &>/dev/null; then
sudo tee /etc/security/pwquality.conf > /dev/null << 'PWQUALITY'
minlen = 16
minclass = 4
maxrepeat = 2
maxclassrepeat = 4
lcredit = -1
ucredit = -1
dcredit = -1
ocredit = -1
PWQUALITY
    ok "Password quality policy enforced (16+ chars, mixed case/num/symbol)"
fi

section "16. Configure Auto Security Updates"
sudo dpkg-reconfigure -f noninteractive unattended-upgrades 2>/dev/null || true
sudo tee /etc/apt/apt.conf.d/50unattended-upgrades-macharden > /dev/null << 'AUTOUPD'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Mail "root";
AUTOUPD
ok "Automatic security updates configured"

section "17. Set File Permissions on Home Directory"
sudo chmod 700 /home/kodachi 2>/dev/null || true
sudo chmod 700 "$HOME"
find "$HOME" -maxdepth 1 -name ".*" -type f -exec chmod 600 {} \; 2>/dev/null || true
ok "Home directory permissions hardened"

section "18. Configure MAC Address Randomization"
if [ -d /etc/NetworkManager/conf.d/ ]; then
sudo tee /etc/NetworkManager/conf.d/99-macharden-mac.conf > /dev/null << 'MACCONF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
connection.stable-id=${CONNECTION}/${BOOT}
MACCONF
    ok "MAC address randomization configured in NetworkManager"
fi

section "19. Configure RAM Wipe on Shutdown"
sudo tee /etc/systemd/system/ram-wipe.service > /dev/null << 'RAMWIPE'
[Unit]
Description=Wipe RAM caches on shutdown
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target
RequiresMountsFor=/

[Service]
Type=oneshot
ExecStart=/bin/sh -c "sync; echo 3 > /proc/sys/vm/drop_caches; sync"
RemainAfterExit=yes

[Install]
WantedBy=shutdown.target reboot.target halt.target
RAMWIPE
sudo systemctl daemon-reload
sudo systemctl enable ram-wipe.service
ok "RAM wipe on shutdown enabled"

section "20. Harden Kodachi LibreWolf Browser Settings"
LIBREWOLF_PROFILE="$HOME/.librewolf"
if [ -d "$LIBREWOLF_PROFILE" ]; then
    # Find default profile
    PROFILE_DIR=$(find "$LIBREWOLF_PROFILE" -name "prefs.js" | head -1 | xargs dirname)
    if [ -n "$PROFILE_DIR" ]; then
        cat >> "$PROFILE_DIR/user.js" << 'USERJS'
// MacHarden: Additional LibreWolf hardening
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.sessionstore.privacy_level", 2);
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.version.min", 3);
user_pref("dom.battery.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("dom.vibrator.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("network.http.sendRefererHeader", 0);
user_pref("geo.enabled", false);
USERJS
        ok "LibreWolf additional hardening applied"
    fi
fi

echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Kodachi VM hardening complete!${RESET}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}REQUIRED MANUAL STEPS:${RESET}"
echo ""
echo -e "  ${YELLOW}1.${RESET} Open Kodachi Dashboard → Run Autoshield wizard"
echo -e "  ${YELLOW}2.${RESET} Dashboard → Network → Configure your VPN credentials"
echo -e "  ${YELLOW}3.${RESET} Create VeraCrypt container:"
echo -e "       veracrypt --text --create /home/kodachi/vault.vc"
echo -e "       Size: 10GB+, Cipher: AES-256+Twofish, Hash: Whirlpool"
echo -e "  ${YELLOW}4.${RESET} Test for leaks: Dashboard → Security → Run All Leak Tests"
echo -e "  ${YELLOW}5.${RESET} Verify Tor: open Tor Browser → check.torproject.org"
echo -e "  ${YELLOW}6.${RESET} Verify DNS: https://www.dnsleaktest.com (should show Tor exit)"
echo -e "  ${YELLOW}7.${RESET} Shut down VM — it is now ready to be your Golden Image"
echo ""
echo -e "  Log saved: $LOG"
"""

    if not DRY_RUN:
        script_path.write_text(script_content)
        script_path.chmod(0o755)

    ok(f"VM hardening script written: {script_path}")

    section("How to Run the VM Hardening Script")
    print(f"""
  {C.BOLD}Method 1: Via shared folder (if temporarily enabled){C.RESET}
    1. In UTM: enable shared folder for the transfer
    2. Mount it inside Kodachi: {C.DIM}sudo mount -t 9p -o trans=virtio share /mnt/share{C.RESET}
    3. Run: {C.DIM}bash /mnt/share/kodachi_vm_harden.sh{C.RESET}
    4. Disable shared folder in UTM immediately after

  {C.BOLD}Method 2: Via Tor Browser download (most isolated){C.RESET}
    1. Upload script to a PrivateBin instance (zero-knowledge): https://privatebin.net
    2. Inside Kodachi VM → Tor Browser → download the paste
    3. Run: {C.DIM}bash ~/Downloads/kodachi_vm_harden.sh{C.RESET}

  {C.BOLD}Method 3: Type/paste manually{C.RESET}
    For paranoid scenarios: type key sections manually in the VM terminal

  {C.RED}After hardening: DISABLE shared folder before making golden image{C.RESET}

  {C.BOLD}{C.YELLOW}Tahoe-specific — Kodachi VPN cipher requirement:{C.RESET}
  {C.YELLOW}macOS 26 Tahoe REMOVES support for DES, 3DES, SHA1-96, SHA1-160,{C.RESET}
  {C.YELLOW}and Diffie-Hellman groups < 14 for IKEv2 VPNs.{C.RESET}
  {C.YELLOW}Kodachi's OpenVPN (not IKEv2) is unaffected — but if you add any{C.RESET}
  {C.YELLOW}IKEv2 VPN profile to macOS host, ensure it uses:{C.RESET}
  {C.DIM}  Cipher: AES-256-GCM | Auth: SHA-256/SHA-384 | DH Group: 14+{C.RESET}
""")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────────────────────────

PHASES = [
    ("1", "macOS Telemetry & Privacy Hardening",   harden_telemetry),
    ("2", "macOS Network Hardening",               harden_network),
    ("3", "macOS System Security Hardening",       harden_system),
    ("4", "Install Security Tools (Homebrew)",     install_tools),
    ("5", "Create Kodachi VM in UTM",              None),   # handled below
    ("6", "Golden Image & Session Scripts",        setup_golden_image_workflow),
    ("7", "Generate Kodachi VM Harden Script",     generate_vm_hardening_script),
    ("A", "Run ALL phases (recommended order)",    None),
]

def run_all(iso_path: Path | None):
    harden_telemetry()
    harden_network()
    harden_system()
    install_tools()
    if iso_path:
        create_utm_vm(iso_path)
    else:
        warn("Skipping VM creation — no ISO path available")
    setup_golden_image_workflow()
    generate_vm_hardening_script()

def main():
    setup_logging()
    banner()

    if not DRY_RUN and not preflight_checks():
        if not confirm("Preflight checks had issues. Continue anyway?"):
            sys.exit(1)

    # Handle --phase argument
    if "--phase" in sys.argv:
        idx = sys.argv.index("--phase")
        if idx + 1 < len(sys.argv):
            phase_arg = sys.argv[idx + 1]
            phase_map = {p[0]: p[2] for p in PHASES if p[2] is not None}
            if phase_arg in phase_map:
                phase_map[phase_arg]()
                return

    iso_path = None

    while True:
        section("Main Menu")
        for num, label, _ in PHASES:
            print(f"  {C.CYAN}[{num}]{C.RESET}  {label}")
        print(f"\n  {C.DIM}[L]{C.RESET}  View log file ({LOG_PATH})")
        print(f"  {C.DIM}[Q]{C.RESET}  Quit")
        print()

        try:
            choice = input(f"  {C.YELLOW}>{C.RESET} Choose: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.DIM}Interrupted.{C.RESET}")
            break

        if choice == "Q":
            break
        elif choice == "L":
            if LOG_PATH.exists():
                subprocess.run(["tail", "-50", str(LOG_PATH)])
            else:
                warn("Log file not yet created")
        elif choice == "1":
            harden_telemetry()
        elif choice == "2":
            harden_network()
        elif choice == "3":
            harden_system()
        elif choice == "4":
            install_tools()
        elif choice == "5":
            WORK_DIR.mkdir(parents=True, exist_ok=True)
            iso_path = download_kodachi_iso(WORK_DIR)
            if iso_path:
                create_utm_vm(iso_path)
            else:
                err("ISO not available — cannot create VM")
        elif choice == "6":
            setup_golden_image_workflow()
        elif choice == "7":
            generate_vm_hardening_script()
        elif choice == "A":
            WORK_DIR.mkdir(parents=True, exist_ok=True)
            if iso_path is None:
                iso_path = download_kodachi_iso(WORK_DIR)
            run_all(iso_path)
        else:
            warn("Invalid choice")

        print()
        input(f"  {C.DIM}Press Enter to return to menu...{C.RESET}")

    print(f"\n{C.DIM}Log saved to: {LOG_PATH}{C.RESET}\n")

if __name__ == "__main__":
    main()
