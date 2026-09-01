#!/usr/bin/env python3
"""
Claude Security Memory Manager — evw's MacBook Pro

Two persistent encrypted stores (in git repo under memory/):
  memory/short_term.csmem  — pending tasks + next-scan checklist
  memory/long_term.csmem   — append-only HMAC-chained event log

Scan archives (in git repo under memory/scans/):
  memory/scans/scan-DATE.enc — AES-256-CBC encrypted tarballs of scan dirs

File format (.csmem and .enc):
  Line 1:  CSMEM:v2
  Line 2:  WRITTEN:<ISO8601>
  Line 3:  MACHINE:<hostname>
  Line 4:  HMAC:<sha256-hex of compressed plaintext>
  Line 5+: <base64 of AES-256-CBC(gzip(payload))>

Key: 32 random bytes in macOS Keychain (no machine-serial mixing so files
     survive a machine wipe if the Keychain key is backed up offline).
     Service: claude-security-memory-v1  Account: claude-ai

Threat-model note: the master key is retrievable by ANY process running as
     this user (CLI-created Keychain items carry no ACL/TouchID gate, and the
     raw key hex still transits `security add-generic-password -w` argv).
     This protects against repo-only attackers — not user-context malware.

Recovery after machine wipe:
  1. python3 security-memory-manager.py export-recovery-key   (run before wipe)
     → prints hex key; store on paper / encrypted USB
  2. python3 security-memory-manager.py import-recovery-key   (prompts for the hex key)
     → re-installs the key in new machine's Keychain

Long-term log entries form an HMAC chain: each entry embeds the HMAC of the
previous entry — deletion or reordering is detectable.

Commands:
  read short | long
  write-short '<json>'
  append-long '<json>'
  verify short | long
  archive-scan <scan-dir-path>
  restore-scan <scan-DATE.enc> <dest-dir>
  export-recovery-key
  import-recovery-key [hex]   (prompts via getpass when hex omitted — preferred)
"""

import json, gzip, hashlib, hmac as hmaclib, base64, subprocess, os, sys, tarfile, io, getpass
import ctypes
from datetime import datetime, timezone

# error-guard: shared try/catch + 10-failure circuit breaker (lib/error_guard.py)
try:
    import pathlib as _pathlib, sys as _sys
    _d = _pathlib.Path(__file__).resolve().parent
    for _ in range(6):
        _eg = _d / "lib" / "error_guard.py"
        if _eg.exists():
            # running as root: only trust a root-owned lib — a user-writable
            # error_guard would be arbitrary code execution as root
            if os.geteuid() != 0 or _eg.stat().st_uid == 0:
                _sys.path.insert(0, str(_d / "lib"))
            break
        _d = _d.parent
    from error_guard import guard_run, guarded, SKIP, throw, GuardError
except ImportError:
    SKIP = object()
    def guard_run(_l, fn, *a, **kw): return fn(*a, **kw)
    def guarded(_l=None):
        def deco(fn): return fn
        return deco
    class GuardError(RuntimeError): pass
    def throw(msg): raise GuardError(str(msg))

REPO_MEMORY_DIR  = os.path.join(os.path.dirname(__file__), 'memory')
SHORT_TERM_FILE  = os.path.join(REPO_MEMORY_DIR, 'short_term.csmem')
LONG_TERM_FILE   = os.path.join(REPO_MEMORY_DIR, 'long_term.csmem')
SCANS_DIR        = os.path.join(REPO_MEMORY_DIR, 'scans')
KEYCHAIN_SERVICE = 'claude-security-memory-v1'
KEYCHAIN_ACCOUNT = 'claude-ai'
MACHINE_HOST     = subprocess.run(['scutil','--get','ComputerName'],
                    capture_output=True, text=True).stdout.strip()

os.makedirs(REPO_MEMORY_DIR, exist_ok=True)
os.makedirs(SCANS_DIR, exist_ok=True)

# ── Key management ─────────────────────────────────────────────────────────

def _get_or_create_key() -> bytes:
    r = subprocess.run(
        ['security','find-generic-password','-a',KEYCHAIN_ACCOUNT,
         '-s',KEYCHAIN_SERVICE,'-w'],
        capture_output=True, text=True)
    if r.returncode == 0:
        return bytes.fromhex(r.stdout.strip())
    raw = os.urandom(32)
    subprocess.run(
        ['security','add-generic-password','-a',KEYCHAIN_ACCOUNT,
         '-s',KEYCHAIN_SERVICE,'-w',raw.hex()],
        check=True, capture_output=True)
    return raw

def _derive_key() -> bytes:
    base = _get_or_create_key()
    return hashlib.pbkdf2_hmac('sha256', base, b'csmem-v2', iterations=100_000)

# ── Crypto ─────────────────────────────────────────────────────────────────
# AES-256-CBC via CommonCrypto's CCCrypt (ctypes → libSystem) so key material
# no longer transits process argv. Byte-compatible with the previous
# `openssl enc -aes-256-cbc -K <hex> -iv <hex> -nosalt` (PKCS#7 padding) —
# existing .csmem/.enc files remain readable.
_CC = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
_CCCrypt = _CC.CCCrypt
_CCCrypt.restype = ctypes.c_int32
_CCCrypt.argtypes = [
    ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,   # op, alg, options
    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,   # key, keyLength, iv
    ctypes.c_char_p, ctypes.c_size_t,                    # dataIn, dataInLength
    ctypes.c_char_p, ctypes.c_size_t,                    # dataOut, dataOutAvailable
    ctypes.POINTER(ctypes.c_size_t)]                     # dataOutMoved

# kCCEncrypt=0, kCCDecrypt=1, kCCAlgorithmAES=0, kCCOptionPKCS7Padding=1
def _cc_crypt(op: int, data: bytes, key: bytes, iv: bytes) -> bytes:
    out = ctypes.create_string_buffer(len(data) + 16)
    moved = ctypes.c_size_t(0)
    status = _CCCrypt(op, 0, 1, key, len(key), iv, data, len(data),
                      out, len(out), ctypes.byref(moved))
    if status != 0:
        raise RuntimeError(f'CCCrypt failed (status {status})')
    return out.raw[:moved.value]

def _encrypt(plaintext: bytes, key: bytes) -> str:
    iv = os.urandom(16)
    ct = _cc_crypt(0, plaintext, key, iv)   # kCCEncrypt
    return base64.b64encode(iv + ct).decode()

def _decrypt(b64: str, key: bytes) -> bytes:
    raw = base64.b64decode(b64)
    iv, ct = raw[:16], raw[16:]
    try:
        return _cc_crypt(1, ct, key, iv)    # kCCDecrypt
    except RuntimeError:
        raise RuntimeError('Decryption failed — wrong key or tampered file')

def _hmac(key: bytes, data: bytes) -> str:
    return hmaclib.new(key, data, hashlib.sha256).hexdigest()

# ── File I/O ───────────────────────────────────────────────────────────────

def _write_file(path: str, payload, key: bytes):
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    if isinstance(payload, (dict, list)):
        raw = json.dumps(payload).encode()
    else:
        raw = payload  # bytes (for scan archives)
    compressed = gzip.compress(raw)
    file_hmac = _hmac(key, compressed)
    ct_b64 = _encrypt(compressed, key)
    with open(path, 'w') as f:
        f.write('CSMEM:v2\n')
        f.write(f'WRITTEN:{now}\n')
        f.write(f'MACHINE:{MACHINE_HOST}\n')
        f.write(f'HMAC:{file_hmac}\n')
        f.write(ct_b64 + '\n')

def _read_file(path: str, key: bytes):
    with open(path) as f:
        lines = f.read().splitlines()
    headers = {}
    for line in lines[:4]:
        k, _, v = line.partition(':')
        headers[k] = v
    compressed = _decrypt(lines[4], key)
    actual = _hmac(key, compressed)
    if actual != headers.get('HMAC'):
        raise RuntimeError(
            f'HMAC MISMATCH — {path} has been tampered!\n'
            f'  stored:   {headers.get("HMAC")}\n'
            f'  computed: {actual}')
    return headers, gzip.decompress(compressed)

def _read_json(path: str, key: bytes):
    h, raw = _read_file(path, key)
    return h, json.loads(raw)

# ── Short-term memory ──────────────────────────────────────────────────────

def write_short(content: dict):
    key = _derive_key()
    _write_file(SHORT_TERM_FILE, content, key)
    print(f'✓ short_term.csmem written')

def read_short() -> dict:
    key = _derive_key()
    h, payload = _read_json(SHORT_TERM_FILE, key)
    print(f'Written:  {h["WRITTEN"]}  Machine: {h["MACHINE"]}  HMAC: ✓')
    return payload

# ── Long-term log (HMAC chain) ─────────────────────────────────────────────

def _entry_hmac(key: bytes, entry: dict) -> str:
    e = {k: v for k, v in entry.items() if k != 'entry_hmac'}
    return _hmac(key, json.dumps(e, sort_keys=True).encode())

def append_long(event: dict):
    key = _derive_key()
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    if os.path.exists(LONG_TERM_FILE):
        _, payload = _read_json(LONG_TERM_FILE, key)
        entries = payload['entries']
        prev_hmac = entries[-1]['entry_hmac'] if entries else 'genesis'
        seq = len(entries) + 1
    else:
        entries, prev_hmac, seq = [], 'genesis', 1
    entry = {'seq': seq, 'timestamp': now, 'machine': MACHINE_HOST,
             'previous_hmac': prev_hmac, **event}
    entry['entry_hmac'] = _entry_hmac(key, entry)
    entries.append(entry)
    _write_file(LONG_TERM_FILE, {'entries': entries}, key)
    print(f'✓ long_term.csmem: appended entry #{seq}')

def read_long() -> list:
    key = _derive_key()
    h, payload = _read_json(LONG_TERM_FILE, key)
    entries = payload['entries']
    print(f'Written: {h["WRITTEN"]}  Machine: {h["MACHINE"]}  File HMAC: ✓')
    for i, entry in enumerate(entries):
        if _entry_hmac(key, entry) != entry['entry_hmac']:
            raise RuntimeError(f'Chain broken — entry #{entry["seq"]} tampered')
        if i > 0 and entry['previous_hmac'] != entries[i-1]['entry_hmac']:
            raise RuntimeError(f'Chain broken — entry #{entry["seq"]} predecessor deleted/reordered')
    print(f'Chain: ✓ ({len(entries)} entries)')
    return entries

def verify(which: str):
    key = _derive_key()
    path = SHORT_TERM_FILE if which == 'short' else LONG_TERM_FILE
    h, raw = _read_file(path, key)
    print(f'File:    {path}')
    print(f'Written: {h["WRITTEN"]}  Machine: {h["MACHINE"]}  HMAC: ✓')
    if which == 'long':
        entries = json.loads(raw)['entries']
        for i, e in enumerate(entries):
            if _entry_hmac(key, e) != e['entry_hmac']:
                raise RuntimeError(f'Chain broken at #{e["seq"]}')
            if i > 0 and e['previous_hmac'] != entries[i-1]['entry_hmac']:
                raise RuntimeError(f'Link broken at #{e["seq"]}')
        print(f'Chain:   ✓ ({len(entries)} entries intact)')

# ── Scan archive ───────────────────────────────────────────────────────────

def archive_scan(scan_dir: str):
    scan_dir = os.path.realpath(scan_dir)
    name = os.path.basename(scan_dir)
    out_path = os.path.join(SCANS_DIR, f'{name}.enc')
    key = _derive_key()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        tar.add(scan_dir, arcname=name)
    _write_file(out_path, buf.getvalue(), key)
    size = os.path.getsize(out_path)
    print(f'✓ archived {name} → memory/scans/{name}.enc ({size:,} bytes)')

def restore_scan(enc_file: str, dest_dir: str):
    key = _derive_key()
    _, raw = _read_file(enc_file, key)
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
        tar.extractall(dest_dir)
    print(f'✓ restored {enc_file} → {dest_dir}')

# ── Key recovery ───────────────────────────────────────────────────────────

def export_recovery_key():
    raw = _get_or_create_key()
    print('=== RECOVERY KEY (store offline — paper/encrypted USB only) ===')
    print(raw.hex())
    print('=== To restore on new machine: ===')
    print('python3 security-memory-manager.py import-recovery-key   # prompts for the key — keeps it out of shell history/ps')

def import_recovery_key(hex_key: str):
    raw = bytes.fromhex(hex_key)
    assert len(raw) == 32, 'Key must be 32 bytes (64 hex chars)'
    r = subprocess.run(
        ['security','find-generic-password','-a',KEYCHAIN_ACCOUNT,
         '-s',KEYCHAIN_SERVICE,'-w'],
        capture_output=True, text=True)
    if r.returncode == 0:
        subprocess.run(
            ['security','delete-generic-password','-a',KEYCHAIN_ACCOUNT,
             '-s',KEYCHAIN_SERVICE],
            capture_output=True)
    subprocess.run(
        ['security','add-generic-password','-a',KEYCHAIN_ACCOUNT,
         '-s',KEYCHAIN_SERVICE,'-w',raw.hex()],
        check=True, capture_output=True)
    print('✓ Recovery key installed in Keychain')

# ── CLI ────────────────────────────────────────────────────────────────────

def _dispatch(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if   cmd == 'read'               and len(argv) > 2 and argv[2] == 'short': print(json.dumps(read_short(), indent=2))
    elif cmd == 'read'               and len(argv) > 2 and argv[2] == 'long':  print(json.dumps(read_long(), indent=2))
    elif cmd == 'write-short'        and len(argv) > 2: write_short(json.loads(argv[2]))
    elif cmd == 'append-long'        and len(argv) > 2: append_long(json.loads(argv[2]))
    elif cmd == 'verify'             and len(argv) > 2: verify(argv[2])
    elif cmd == 'archive-scan'       and len(argv) > 2: archive_scan(argv[2])
    elif cmd == 'restore-scan'       and len(argv) > 3: restore_scan(argv[2], argv[3])
    elif cmd == 'export-recovery-key':export_recovery_key()
    elif cmd == 'import-recovery-key':
        if len(argv) > 2:
            print('WARNING: a key on argv leaks into shell history and `ps` — prefer the no-argument prompt.', file=sys.stderr)
            import_recovery_key(argv[2])
        else:
            import_recovery_key(getpass.getpass('Recovery key (64 hex chars): '))
    else:                             print(__doc__)
    return True

if __name__ == '__main__':
    if not guard_run("dispatch", _dispatch, sys.argv):
        sys.exit(1)
