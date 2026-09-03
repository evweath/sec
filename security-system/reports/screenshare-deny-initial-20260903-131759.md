# [AUTO-EVW-LS] screenshare-deny (both-ways) report
# 2026-09-03 13:17:59  model=/tmp/ls-screenshare-initial.7sK3ro99/model.json  apply=True
# config=/var/db/evw-security-system/security-system.json  identifiers=12 (config=12 ensure=0)
# ADD=12 rules  SKIP=6 identifiers (already covered)

## ADDED (durable both-ways denies, grouped by identifier)
### identifier.APPLE/com.apple.screensharingd
- deny outgoing identifier.APPLE/com.apple.screensharingd -> any
- deny incoming identifier.APPLE/com.apple.screensharingd -> any
### identifier.APPLE/com.apple.ARDAgent
- deny outgoing identifier.APPLE/com.apple.ARDAgent -> any
- deny incoming identifier.APPLE/com.apple.ARDAgent -> any
### identifier.APPLE/com.apple.AppleVNCServer
- deny outgoing identifier.APPLE/com.apple.AppleVNCServer -> any
- deny incoming identifier.APPLE/com.apple.AppleVNCServer -> any
### identifier.com.anydesk.AnyDesk
- deny outgoing identifier.com.anydesk.AnyDesk -> any
- deny incoming identifier.com.anydesk.AnyDesk -> any
### identifier.com.carriez.rustdesk
- deny outgoing identifier.com.carriez.rustdesk -> any
- deny incoming identifier.com.carriez.rustdesk -> any
### identifier.com.realvnc.VNCViewer
- deny outgoing identifier.com.realvnc.VNCViewer -> any
- deny incoming identifier.com.realvnc.VNCViewer -> any

## SKIPPED (an existing deny already covers both directions)
- identifier.com.google.ChromeRemoteDesktopHost — covered by: deny identifier.com.google.ChromeRemoteDesktopHost -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.teamviewer.TeamViewer — covered by: deny identifier.com.teamviewer.TeamViewer -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.teamviewer.TeamViewerHost — covered by: deny identifier.com.teamviewer.TeamViewerHost -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.splashtop.Splashtop-Streamer — covered by: deny identifier.com.splashtop.Splashtop-Streamer -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.logmein.LogMeIn — covered by: deny identifier.com.logmein.LogMeIn -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
- identifier.com.realvnc.vncserver — covered by: deny identifier.com.realvnc.vncserver -> any dir=absent(both) origin=frontend notes=[AUTO-EVW] block screen-sharing/remote-desktop program (2026-09-01)
