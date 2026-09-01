#!/usr/bin/env python3
# ls-deny-screenshare.py — [AUTO-EVW] plant blanket any-remote deny rules for
# screen-sharing / remote-desktop programs (2026-09-01).
#   python3 ls-deny-screenshare.py model.json --apply --undo undo.json
# Rules for programs that are not installed are inert (never match).
import json
import sys
import time

PROCS = [
    # ── Apple screen sharing (client side + agents; daemon already denied) ──
    "com.apple.ScreenSharing",
    "com.apple.screensharing.agent",
    "com.apple.screensharing.menuextra",
    "com.apple.RemoteDesktop",              # Apple Remote Desktop admin app
    # ── TeamViewer ──
    "com.teamviewer.TeamViewer",
    "com.teamviewer.TeamViewerHost",
    "com.teamviewer.Desktop",
    # ── AnyDesk ──
    "com.philandro.anydesk",
    # ── Chrome Remote Desktop ──
    "org.chromium.chromoting",
    "com.google.ChromeRemoteDesktopHost",
    # ── VNC (RealVNC/TigerVNC) ──
    "com.realvnc.vncviewer",
    "com.realvnc.vncserver",
    # ── Splashtop ──
    "com.splashtop.Splashtop-Streamer",
    "com.splashtop.Splashtop-Personal",
    # ── LogMeIn / GoToMyPC ──
    "com.logmein.LogMeIn",
    "com.logmein.LogMeInRescueApplet",
    "com.gotomypc.GoToMyPC",
    # ── RustDesk / Parsec / NoMachine ──
    "com.rustdesk.rustdesk",
    "tv.parsec.www",
    "com.nomachine.nxplayer",
    "com.nomachine.nxserver",
    # ── Zoho Assist / DWService / Supremo ──
    "com.zoho.assist",
    "com.dwservice.agent",
    "com.supremo.Supremo",
    # ── Microsoft Remote Desktop (RDP client) ──
    "com.microsoft.rdc.macos",
]
NOTES = "[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)"


def main():
    path = sys.argv[1]
    apply = "--apply" in sys.argv
    undo = sys.argv[sys.argv.index("--undo") + 1] if "--undo" in sys.argv else None

    model = json.load(open(path))
    rules = model.get("rules", [])
    blanket = {str(r.get("process", "")) for r in rules
               if r.get("action") == "deny" and str(r.get("remote", "")) == "any"}

    added, skipped = [], []
    for pid in PROCS:
        proc_field = pid if "/" in pid or "." in pid.split(".", 1)[0] else pid
        # Apple-signed -> identifier.APPLE/<id>; third-party -> identifier.<id>
        if pid.startswith("com.apple."):
            proc_field = "identifier.APPLE/" + pid
        else:
            proc_field = "identifier." + pid
        if any(pid in p for p in blanket):
            skipped.append(pid)
            continue
        rules.append({
            "action": "deny",
            "process": proc_field,
            "remote": "any",
            "origin": "frontend",
            "approved": True,
            "creationDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "notes": NOTES,
        })
        added.append(pid)

    if undo:
        json.dump({"added": added, "skipped_already_denied": skipped},
                  open(undo, "w"), indent=2)
    if apply and added:
        model["rules"] = rules
        json.dump(model, open(path, "w"), indent=2)
    print("ADDED={} SKIP={} total_rules={}".format(len(added), len(skipped), len(rules)))
    for a in added:
        print("  + deny any-remote:", a)


if __name__ == "__main__":
    main()
