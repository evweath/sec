# [AUTO-EVW-LS] Cleaned-up Little Snitch rules — consolidated record
# Compiled 2026-09-01 13:30 from the three hygiene passes (see STATE.md).
# Undo: full rule JSON in ls-hygiene-undo.json (latest pass) +
#       model backups /var/log/mac-sentinel/ls-model-pre-hygiene-*.json (root).

## Pass 1 — 2026-09-01 12:58 (16 deleted)
T1 tracker allows (Safari, :443, origin=alert):
  a.klaviyo.com x2, acdn.adnxs.com, ads.pro-market.net, bat.bing.com,
  fast.a.klaviyo.com x2, static-forms.klaviyo.com,
  static-tracking.klaviyo.com x2, static.klaviyo.com x2
T3 DHCP-risk denies:
  deny configd -> 10.236.160.51:67
  deny configd -> ff02::2 (any)
T2 OCSP/cert-validation-killing denies:
  deny trustd -> any
  deny trustd -> ocsp2.apple.com:443 (1826 hits)

## Pass 2 — 2026-09-01 13:17 (10 deleted, 4 added)
Deleted: a.klaviyo.com x2, fast.a.klaviyo.com x2, static.klaviyo.com x2,
  static-tracking.klaviyo.com, static-forms.klaviyo.com, bat.bing.com (all
  regenerated via alert approvals, uses <= 2)
Deleted: deny trustd -> ocsp.sectigo.com:80 (new OCSP block, uses 9)
Added (durable any-process deny, tagged [AUTO-EVW-LS]):
  a.klaviyo.com, fast.a.klaviyo.com, static.klaviyo.com, static-tracking.klaviyo.com

## Pass 3 — 2026-09-01 13:21 (1 deleted)
  allow Safari -> static-forms.klaviyo.com (regenerated)

## Verification scans
  13:25 549 rules — 0 risk rules (all categories)
  Totals: 27 deleted, 4 planted denies. Ruleset clean.
