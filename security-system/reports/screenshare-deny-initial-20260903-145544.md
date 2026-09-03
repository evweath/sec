# [AUTO-EVW-LS] screenshare-deny (both-ways) report
# 2026-09-03 14:55:44  model=/tmp/ls-screenshare-initial.3Kwn8TOr/model.json  apply=True
# config=/var/db/evw-security-system/security-system.json  identifiers=12 (config=12 ensure=0)
# ADD=0 rules  SKIP=12 identifiers (already covered)

## ADDED (durable both-ways denies, grouped by identifier)

## SKIPPED (an existing deny already covers both directions)
- identifier.APPLE/com.apple.screensharingd — covered by: deny identifier.APPLE/com.apple.screensharingd -> any dir=absent(both) origin=frontend notes=[AUTO-EVW-LS] screenshare-deny (both-ways; kill-on-sight backstop)
- identifier.APPLE/com.apple.ARDAgent — covered by: deny identifier.APPLE/com.apple.ARDAgent -> any dir=absent(both) origin=frontend notes=[AUTO-EVW-LS] screenshare-deny (both-ways; kill-on-sight backstop)
- identifier.APPLE/com.apple.AppleVNCServer — covered by: deny identifier.APPLE/com.apple.AppleVNCServer -> any dir=absent(both) origin=frontend notes=[AUTO-EVW-LS] screenshare-deny (both-ways; kill-on-sight backstop)
- identifier.com.google.ChromeRemoteDesktopHost — covered by: deny identifier.com.google.ChromeRemoteDesktopHost -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.teamviewer.TeamViewer — covered by: deny identifier.com.teamviewer.TeamViewer -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.teamviewer.TeamViewerHost — covered by: deny identifier.com.teamviewer.TeamViewerHost -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.anydesk.AnyDesk — covered by: deny identifier.com.anydesk.AnyDesk -> any dir=absent(both) origin=frontend notes=[AUTO-EVW-LS] screenshare-deny (both-ways; kill-on-sight backstop)
- identifier.com.carriez.rustdesk — covered by: deny identifier.com.carriez.rustdesk -> any dir=absent(both) origin=frontend notes=[AUTO-EVW-LS] screenshare-deny (both-ways; kill-on-sight backstop)
- identifier.com.splashtop.Splashtop-Streamer — covered by: deny identifier.com.splashtop.Splashtop-Streamer -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.logmein.LogMeIn — covered by: deny identifier.com.logmein.LogMeIn -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.realvnc.vncserver — covered by: deny identifier.com.realvnc.vncserver -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.realvnc.VNCViewer — covered by: deny identifier.com.realvnc.VNCViewer -> any dir=absent(both) origin=frontend notes=[AUTO-EVW-LS] screenshare-deny (both-ways; kill-on-sight backstop)
