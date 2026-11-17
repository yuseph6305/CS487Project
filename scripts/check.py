#!/usr/bin/env python3
"""Check one email from the command line.

  python scripts/check.py suspicious.eml
  pbpaste | python scripts/check.py -
  python scripts/check.py email.txt --mode rules --json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishcheck.checker import MODES, PhishChecker  # noqa: E402

COLORS = {"phishing": "\033[91m", "suspicious": "\033[93m", "legitimate": "\033[92m", "error": "\033[95m"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="email file, or - for stdin")
    ap.add_argument("--mode", choices=MODES, default="full")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    raw = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8", errors="replace")
    r = PhishChecker().check(raw, mode=a.mode)
    if a.json:
        print(json.dumps(r.to_dict(), indent=2))
        return
    c = COLORS.get(r.verdict, "")
    print(f"\n{c}\033[1m{r.verdict.upper()}\033[0m  ({r.probability:.0%} phishing risk)   [{r.engine}]\n")
    print(r.summary, "\n")
    for x in r.reasons:
        print(f"  • {x}")
    if r.injection and r.injection.detected:
        print("\n\033[95mPrompt injection detected:\033[0m")
        for f in r.injection.findings:
            print(f"  • {f.message}{' (hidden)' if f.hidden else ''}: {f.evidence}")
    for o in r.overrides:
        print(f"\n  ⚠ {o}")
    print(f"\n→ {r.advice}\n")


if __name__ == "__main__":
    main()
