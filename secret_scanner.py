#!/usr/bin/env python3
"""Scan a directory tree for hardcoded secrets.

Combines high-signal vendor patterns (cloud keys, tokens, private keys) with a
generic assignment + Shannon-entropy check. Matches are redacted in output so
the scanner never prints a full secret. Supports an inline allowlist marker and
directory/extension excludes. Standard library only.
"""
import argparse
import json
import math
import os
import re
import sys

ALLOWLIST_MARKER = "allowlist secret"

# name, compiled pattern, severity
PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("aws_secret_access_key",
     re.compile(r"(?i)aws.{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"), "critical"),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "critical"),
    ("github_token", re.compile(r"\b(ghp|gho|ghs|ghu|ghr)_[0-9A-Za-z]{36}\b"), "high"),
    ("github_pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("stripe_secret_key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "critical"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "medium"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "high"),
]

ASSIGN_RE = re.compile(
    r"(?i)([\w.\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|auth[_-]?token))\s*[:=]\s*['\"]?([^\s'\"`,;]{6,})")

PLACEHOLDER_RE = re.compile(r"(?i)(example|changeme|placeholder|your[_-]?|xxx+|<[^>]+>|\.\.\.|redacted|dummy|test)")

DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".idea",
}
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".tgz", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mov", ".mp3", ".class", ".jar", ".pyc",
}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact(secret):
    secret = secret.strip("'\"")
    if len(secret) <= 6:
        return "*" * len(secret)
    return "%s...[%d chars]" % (secret[:3], len(secret))


def is_binary(path):
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(1024)
    except OSError:
        return True


def scan_text(text, entropy_threshold=3.5):
    """Yield findings for one blob of text. Pure function over the text."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOWLIST_MARKER in line.lower():
            continue
        for name, pattern, severity in PATTERNS:
            for m in pattern.finditer(line):
                token = m.group(1) if m.groups() else m.group(0)
                findings.append({"line": lineno, "rule": name, "severity": severity,
                                 "match": redact(token)})
        for m in ASSIGN_RE.finditer(line):
            key, value = m.group(1), m.group(2)
            if PLACEHOLDER_RE.search(value):
                continue
            entropy = shannon_entropy(value)
            severity = "high" if entropy >= entropy_threshold and len(value) >= 12 else "medium"
            findings.append({"line": lineno, "rule": "assigned_secret:%s" % key.lower(),
                             "severity": severity, "match": redact(value),
                             "entropy": round(entropy, 2)})
    return findings


def scan_file(path, entropy_threshold=3.5):
    if os.path.splitext(path)[1].lower() in BINARY_EXTS or is_binary(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    findings = scan_text(text, entropy_threshold)
    for f in findings:
        f["file"] = path
    return findings


def scan_dir(root, exclude_dirs=None, entropy_threshold=3.5):
    exclude_dirs = exclude_dirs or DEFAULT_EXCLUDE_DIRS
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for name in filenames:
            findings.extend(scan_file(os.path.join(dirpath, name), entropy_threshold))
    findings.sort(key=lambda f: SEVERITY_RANK[f["severity"]], reverse=True)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan a directory for hardcoded secrets (redacted output).")
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--json", dest="json_out", help="write findings to this JSON file")
    parser.add_argument("--entropy", type=float, default=3.5, help="entropy threshold for assigned values")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK), default="medium")
    parser.add_argument("--exclude", action="append", default=[], help="extra directory name to skip")
    args = parser.parse_args(argv)

    excludes = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude)
    if os.path.isdir(args.path):
        findings = scan_dir(args.path, excludes, args.entropy)
    else:
        findings = scan_file(args.path, args.entropy)

    for f in findings:
        sys.stdout.write("[%-8s] %s:%d %s = %s\n" % (
            f["severity"].upper(), f["file"], f["line"], f["rule"], f["match"]))
    sys.stderr.write("\n%d potential secret(s) found\n" % len(findings))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as out:
            json.dump(findings, out, indent=2)

    worst = max((SEVERITY_RANK[f["severity"]] for f in findings), default=-1)
    return 1 if worst >= SEVERITY_RANK[args.fail_on] else 0


if __name__ == "__main__":
    raise SystemExit(main())
