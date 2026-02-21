#!/usr/bin/env python3
"""
update_sigma_rules.py — Curate Sigma rules for system-coroner embedding.

Usage:
    python3 scripts/update_sigma_rules.py <sigma-rules-dir> <output-dir>

Selects Windows-relevant rules from SigmaHQ that are useful for intrusion
detection (process_creation, network, registry, powershell, file categories).
Rules are filtered by relevance to post-exploitation activities.

Called by: make update-sigma (SIG-006)
"""

import sys
import os
import shutil
import yaml
import re
from pathlib import Path

# Maximum number of rules per category to embed (keep binary size manageable)
MAX_RULES_PER_CATEGORY = 50

# Categories to include (in priority order)
INCLUDE_CATEGORIES = [
    "windows/process_creation",
    "windows/network_connection",
    "windows/registry",
    "windows/powershell",
    "windows/file_event",
    "windows/builtin",
]

# Minimum rule severity to include
MIN_LEVEL = {"low", "medium", "high", "critical"}

# Keywords that indicate post-exploitation relevance
RELEVANCE_KEYWORDS = [
    "mimikatz", "credential", "dump", "lsass", "c2", "beacon", "cobalt",
    "lateral", "psexec", "winrm", "rdp", "persistence", "registry run",
    "scheduled task", "service install", "webshell", "discovery",
    "reconnaissance", "bloodhound", "sharphound", "encode", "base64",
    "download", "temp", "staging", "exfil", "shadow", "vssadmin",
    "wmic", "powershell -enc", "invoke-", "certutil", "regsvr32",
    "mshta", "rundll32", "network scan", "port scan", "nmap",
]


def is_relevant(rule_path: Path, rule_data: dict) -> bool:
    """Check if a rule is relevant for intrusion detection."""
    level = rule_data.get("level", "").lower()
    if level not in MIN_LEVEL:
        return False

    # Check title and description for relevance keywords
    title = rule_data.get("title", "").lower()
    description = rule_data.get("description", "").lower()
    tags = str(rule_data.get("tags", [])).lower()
    combined = title + " " + description + " " + tags

    for kw in RELEVANCE_KEYWORDS:
        if kw in combined:
            return True

    # Include all critical/high rules regardless
    if level in {"critical", "high"}:
        return True

    return False


def process_rules(src_dir: str, dst_dir: str) -> int:
    """Copy relevant rules from src_dir to dst_dir. Returns count of copied rules."""
    src = Path(src_dir)
    dst = Path(dst_dir)

    if not src.exists():
        print(f"Error: source directory not found: {src}", file=sys.stderr)
        sys.exit(1)

    # Clear existing curated rules
    for existing in dst.glob("*.yml"):
        existing.unlink()
    for existing in dst.glob("**/*.yml"):
        existing.unlink()

    copied = 0
    for category in INCLUDE_CATEGORIES:
        cat_dir = src / category
        if not cat_dir.exists():
            print(f"  skip: {category} (not found)", file=sys.stderr)
            continue

        cat_count = 0
        rule_files = sorted(cat_dir.glob("*.yml"))

        # Sort by severity (critical > high > medium > low)
        def severity_key(p: Path) -> int:
            try:
                with open(p, encoding="utf-8") as f:
                    d = yaml.safe_load(f)
                    lvl = d.get("level", "").lower() if d else ""
                    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(lvl, 9)
            except Exception:
                return 9

        rule_files = sorted(rule_files, key=severity_key)

        for rule_file in rule_files:
            if cat_count >= MAX_RULES_PER_CATEGORY:
                break
            try:
                with open(rule_file, encoding="utf-8") as f:
                    rule_data = yaml.safe_load(f)

                if not isinstance(rule_data, dict):
                    continue
                if not is_relevant(rule_file, rule_data):
                    continue

                # Compute output path
                cat_name = category.replace("/", "_")
                out_file = dst / f"{cat_name}_{rule_file.name}"
                out_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(rule_file, out_file)
                cat_count += 1
                copied += 1
            except Exception as e:
                print(f"  warning: {rule_file}: {e}", file=sys.stderr)

        print(f"  {category}: {cat_count} rules selected")

    return copied


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sigma-rules-dir> <output-dir>", file=sys.stderr)
        sys.exit(1)

    src_dir = sys.argv[1]
    dst_dir = sys.argv[2]

    print(f"Source: {src_dir}")
    print(f"Output: {dst_dir}")

    count = process_rules(src_dir, dst_dir)
    print(f"\nTotal rules selected: {count}")
    print("Note: Run 'go build ./...' to re-embed the updated rules.")


if __name__ == "__main__":
    main()
