# es-plist-guard — Endpoint Security client that denies writes to `disabled.501.plist`

## What it does

Subscribes to **AUTH** `write` / `unlink` / `rename` / `create` events and
responds `DENY` whenever the target is
`/var/db/com.apple.xpc.launchd/disabled.501.plist` (or its `/private` twin).
Everything else is allowed instantly. Atomic-save writers (including launchd's
plist serializer, which writes a temp file and renames it over the target) are
covered by the `rename` destination check.

While the daemon runs, the uid-501 disabled-services database is **frozen**:
`launchctl enable/disable` still changes launchd's *in-memory* state, but the
change cannot be persisted to disk. Denials are logged to
`/var/log/evw-es-plist-guard.log` with actor path, pid, ppid, ruid — the same
attribution `evw-plist-monitor.sh` provides, with teeth.

Freeze/unfreeze:

```
sudo launchctl bootout system/com.evw.es-plist-guard                                   # unfreeze
sudo launchctl bootstrap system /Library/LaunchDaemons/com.evw.es-plist-guard.plist    # refreeze
```

## Why it doesn't run yet — two gates

### Gate 1: the restricted entitlement (the real project)

ES clients must be signed with `com.apple.developer.endpoint-security.client`.
That requires:

1. A **paid Apple Developer account** ($99/yr).
2. The **Endpoint Security capability** approved by Apple for your App ID:
   developer.apple.com → Certificates, Identifiers & Profiles → Identifiers →
   your App ID → enable "Endpoint Security". If it isn't selectable, request it
   via Apple's Endpoint Security entitlement request form. Approval is manual
   and geared toward security vendors; individuals have mixed results.
3. A development (or distribution) provisioning profile that includes this
   Mac's UDID.

Until then, `./build.sh && ./es-plist-guard` compiles fine and fails at
`es_new_client()` — that refusal is the expected self-test.

### Gate 2: Full Disk Access (TCC)

Same requirement as eslogger. After installing the signed binary:
System Settings → Privacy & Security → Full Disk Access → `+` →
Cmd-Shift-G → `/usr/local/bin/es-plist-guard` → enable.

## Build and install (once Gate 1 is cleared)

```
./build.sh
codesign --force --options runtime --timestamp \
  --sign "Apple Development: <your name> (<team id>)" \
  --entitlements entitlements.plist es-plist-guard
sudo install -m 755 -o root -g wheel es-plist-guard /usr/local/bin/
sudo install -m 644 -o root -g wheel com.evw.es-plist-guard.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.evw.es-plist-guard.plist
```

Verify: `tail /var/log/evw-es-plist-guard.log` should print the "active" line;
then `sudo launchctl disable user/501/com.example.test` should appear in the
log as a DENY and the plist on disk should be unchanged.

## Zero-signing alternative (works today)

For *this one file*, the system-immutable flag freezes it with no entitlement
at all:

```
sudo chflags schg /var/db/com.apple.xpc.launchd/disabled.501.plist    # freeze
sudo chflags noschg /var/db/com.apple.xpc.launchd/disabled.501.plist  # unfreeze
```

`schg` blocks writes/renames/unlinks even for root, with the same side effect
(launchd can't persist disable-state for uid 501 and will log errors when it
tries). The ES client is the better long-term tool — selective, logged,
extensible to more paths and to actor allow-lists (e.g. "deny everyone except
launchd(pid 1) itself" is a one-line change in `classify()`). `schg` is the
30-second version.
