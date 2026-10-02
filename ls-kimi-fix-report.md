RESOLVE kimi endpoint family -> 23 IPs
DELETE 14 sentinel-deny artifacts on kimi edge IPs
  - deny 45.78.216.166 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 45.78.216.166:443 (Byteplus Pte Ltd administrator 
  - deny 104.18.16.93 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 104.18.16.93:443 (Cloudflare, Inc. ptr=none) seen 
  - allow 109.61.92.193 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 109.61.92.193:443 (DATACAMP-MNT ptr=unn-109-61-92-
  - deny 109.61.92.193 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 109.61.92.193:443 (DATACAMP-MNT ptr=unn-109-61-92-
  - deny 128.14.219.131 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 128.14.219.131:443 (ZENLA-1 ptr=none) seen Monday,
  - allow 169.150.230.97 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 169.150.230.97:443 (DATACAMP-MNT ptr=unn-169-150-2
  - deny 169.150.230.97 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 169.150.230.97:443 (DATACAMP-MNT ptr=unn-169-150-2
  - deny 2606:4700::6812:105d [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 2606:4700::6812:105d:443 (Cloudflare, Inc. ptr=non
  - allow 2a02:6ea0:d216::2 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 2a02:6ea0:d216::2:443 (DATACAMP-MNT ptr=unn-dal.cd
  - deny 2a02:6ea0:d216::2 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 2a02:6ea0:d216::2:443 (DATACAMP-MNT ptr=unn-dal.cd
  - allow 2a02:6ea0:d216::3 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 2a02:6ea0:d216::3:443 (DATACAMP-MNT ptr=unn-dal.cd
  - deny 2a02:6ea0:d216::3 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 2a02:6ea0:d216::3:443 (DATACAMP-MNT ptr=unn-dal.cd
  - allow 2a02:6ea0:d216::4 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 2a02:6ea0:d216::4:443 (DATACAMP-MNT ptr=unn-dal.cd
  - deny 2a02:6ea0:d216::4 [AUTO-EVW-LS] sentinel-deny: com.apple.WebKit.Networking -> 2a02:6ea0:d216::4:443 (DATACAMP-MNT ptr=unn-dal.cd
ADD allow identifier.2J9472RW75/kimi -> kimi.ai,moonshot.ai,moonshot.cn tcp:443
ADD allow identifier.APPLE/com.apple.Terminal via identifier.2J9472RW75/kimi -> kimi.ai,moonshot.ai,moonshot.cn tcp:443
ADD allow identifier.H7V7XYVQ7D/com.googlecode.iterm2 via identifier.2J9472RW75/kimi -> kimi.ai,moonshot.ai,moonshot.cn tcp:443
ADD skipped: kimi -> api.kimi.com host allow already present
ADD skipped: kimi -> cdn.kimi.com host allow already present
ADD skipped: kimi -> code.kimi.com host allow already present
ADD allow identifier.2J9472RW75/kimi -> auth.kimi.com tcp:443
SUMMARY: deleted=14 added=4 rules 4794 -> 4784
