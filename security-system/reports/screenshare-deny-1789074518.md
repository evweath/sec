# [AUTO-EVW-LS] screenshare-deny (both-ways) report
# 2026-09-10 16:08:39  model=/tmp/evw-ls-model-rdsrp49s.json  apply=True
# config=/var/db/evw-security-system/security-system.json  identifiers=14 (config=12 ensure=2)
# ADD=4 rules  SKIP=12 identifiers (already covered)

## ADDED (durable both-ways denies, grouped by identifier)
### identifier.com.apple.parsecd	/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot/System/Library/PrivateFrameworks/CoreParsec.framework/parsecd
- deny outgoing identifier.com.apple.parsecd	/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot/System/Library/PrivateFrameworks/CoreParsec.framework/parsecd -> any
- deny incoming identifier.com.apple.parsecd	/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot/System/Library/PrivateFrameworks/CoreParsec.framework/parsecd -> any
### identifier.com.apple.parsec-fbf	/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot/System/Library/PrivateFrameworks/CoreParsec.framework/parsec-fbf
- deny outgoing identifier.com.apple.parsec-fbf	/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot/System/Library/PrivateFrameworks/CoreParsec.framework/parsec-fbf -> any
- deny incoming identifier.com.apple.parsec-fbf	/Library/Developer/CoreSimulator/Volumes/iOS_23F77/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot/System/Library/PrivateFrameworks/CoreParsec.framework/parsec-fbf -> any

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
