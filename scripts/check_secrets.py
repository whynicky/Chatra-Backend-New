#!/usr/bin/env python3
"""Fail on likely secrets in tracked or not-yet-committed files without printing values.

The output contains only a file path, line number, and rule name. This scanner is
deliberately small and repository-owned so it works in local hooks and CI without
giving file contents to a third party. It complements (not replaces) provider
secret scanning and an owner-reviewed history scan.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 2_000_000
SKIP_PREFIXES = (".git/", "node_modules/", ".venv/")
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2",
    ".ttf", ".pdf", ".zip", ".gz", ".mp4", ".mov", ".db", ".sqlite",
)

RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("stripe-live-key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)

SENSITIVE_PATHS = tuple(re.compile(p, re.I) for p in (
    r"(^|/)\.env(?:\.|$)",
    r"(^|/)(?:credentials|service[-_]?account)[^/]*\.json$",
    r"firebase-adminsdk.*\.json$",
    r"\.(?:pem|key|p8|p12|pfx|dump|backup)$",
    r"(^|/)backup[^/]*\.sql$",
))


def candidate_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [p.decode("utf-8", "surrogateescape") for p in result.stdout.split(b"\0") if p]


def scan() -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for relative in candidate_paths():
        normalized = relative.replace("\\", "/")
        # The scanner necessarily contains its own detection signatures.
        if normalized == "scripts/check_secrets.py":
            continue
        if normalized == ".env.example":
            pass
        elif any(pattern.search(normalized) for pattern in SENSITIVE_PATHS):
            findings.append((normalized, 0, "sensitive-path"))
            continue
        if normalized.startswith(SKIP_PREFIXES) or normalized.lower().endswith(SKIP_SUFFIXES):
            continue
        path = ROOT / relative
        try:
            if not path.is_file() or path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if "secret-scan: allow" in line:
                continue
            for name, pattern in RULES:
                if pattern.search(line):
                    findings.append((normalized, line_no, name))
    return findings


def main() -> int:
    findings = scan()
    if findings:
        print("Potential secrets detected (values intentionally redacted):", file=sys.stderr)
        for path, line, rule in findings:
            location = f"{path}:{line}" if line else path
            print(f"- {location} [{rule}]", file=sys.stderr)
        return 1
    print("Secret scan passed: no high-confidence secrets in tracked or untracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
