#!/usr/bin/env python3
"""Verify files listed by a security-backup *-BACKUP-STATUS.md report."""

import argparse
import hashlib
import os
import re
import sys

DEFAULT_ROOT = "/Users/evw/dev/security-backups"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_status(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    def field(name):
        m = re.search(r"^%s: `([^`]+)`" % re.escape(name), text, re.MULTILINE)
        return m.group(1).rstrip("/") if m else ""
    paths = [m.group(1) for m in re.finditer(r"^- `([^`]+)`", text, re.MULTILINE)]
    return field("Backup source"), field("Backup destination"), paths


def compare(source_root, backup_root, rel):
    source = os.path.join(source_root, rel)
    backup = os.path.join(backup_root, rel)
    try:
        src = os.lstat(source)
    except OSError as e:
        return "SOURCE-MISSING", "source %s: %s" % (source, e)
    try:
        dst = os.lstat(backup)
    except OSError as e:
        return "BACKUP-MISSING", "backup %s: %s" % (backup, e)
    if src.st_size != dst.st_size:
        return "CHANGED", "size source=%d backup=%d" % (src.st_size, dst.st_size)
    try:
        src_hash = sha256_file(source)
    except OSError as e:
        return "SOURCE-UNREADABLE", "source %s: %s" % (source, e)
    try:
        dst_hash = sha256_file(backup)
    except OSError as e:
        return "BACKUP-UNREADABLE", "backup %s: %s" % (backup, e)
    if src_hash != dst_hash:
        return "CHANGED", "sha256 source=%s backup=%s" % (src_hash, dst_hash)
    return "OK", ""


def check_file(path):
    source_root, backup_root, rel_paths = parse_status(path)
    rows = []
    issues = 0
    if not source_root or not backup_root:
        return [("STATUS-INVALID", path, "missing source or destination")], 1
    if not os.path.isdir(source_root):
        rows.append(("SOURCE-ROOT-MISSING", source_root, ""))
        issues += 1
    if not os.path.isdir(backup_root):
        rows.append(("BACKUP-ROOT-MISSING", backup_root, ""))
        issues += 1
    for rel in rel_paths:
        if not os.path.isdir(source_root) or not os.path.isdir(backup_root):
            status, detail = "NOT-CHECKED", "root missing"
        else:
            status, detail = compare(source_root, backup_root, rel)
        rows.append((status, os.path.join(source_root, rel), detail))
        if status != "OK":
            issues += 1
    return rows, issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backups-root", default=os.environ.get("EVW_BACKUPS_ROOT", DEFAULT_ROOT))
    parser.add_argument("--report")
    args = parser.parse_args()

    try:
        statuses = [os.path.join(args.backups_root, name)
                    for name in os.listdir(args.backups_root)
                    if name.endswith("-BACKUP-STATUS.md")]
    except OSError as e:
        print("cannot list %s: %s" % (args.backups_root, e), file=sys.stderr)
        return 1
    statuses.sort(key=lambda p: os.stat(p).st_mtime)

    lines = ["# Backup completeness check", "# Root: %s" % args.backups_root, ""]
    total_issues = 0
    for status_path in statuses:
        rows, issues = check_file(status_path)
        total_issues += issues
        lines.extend(["## %s" % status_path,
                      "issues: %d" % issues, ""])
        for status, path, detail in rows:
            line = "%s  %s" % (status, path)
            if detail:
                line += "  — %s" % detail
            lines.append(line)
        lines.append("")
    lines.append("total statuses: %d" % len(statuses))
    lines.append("total issues: %d" % total_issues)
    output = "\n".join(lines) + "\n"
    if args.report:
        os.makedirs(os.path.dirname(args.report), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(output)
    print(output, end="")
    return 1 if total_issues else 0


if __name__ == "__main__":
    sys.exit(main())
