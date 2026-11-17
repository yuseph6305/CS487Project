"""Dataset loading.

Real datasets: `load_csv()` reads the common public phishing CSVs (Kaggle "Phishing Email Dataset" by
Naser Abdullah Alam -- CEAS_08 / Nazario / Enron / Ling / SpamAssassin files; "phishing_email.csv" with
text_combined; zefang-liu "Phishing_Email.csv" with Email Text / Email Type; etc.) by auto-detecting
columns.

Bundled data: `synthetic.py` generates a labelled demo corpus so everything runs offline. It is NOT a
substitute for real data in the final report.
"""
from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

TEXT_COLS = ["text_combined", "body", "email text", "text", "content", "message", "email", "email_text"]
LABEL_COLS = ["label", "email type", "class", "is_phishing", "phishing", "type", "category", "spam"]
POS = {"1", "phishing", "phishing email", "phish", "spam", "malicious", "fraud", "true", "yes", "bad"}
NEG = {"0", "safe", "safe email", "ham", "legitimate", "legit", "benign", "normal", "false", "no", "good"}


@dataclass
class Sample:
    raw: str
    label: int                 # 1 = phishing, 0 = legitimate
    category: str = "unknown"  # e.g. phish_classic, phish_ai, injection, legit
    id: str = ""


def _find(cols: list[str], wanted: list[str]) -> str | None:
    low = {c.lower().strip(): c for c in cols}
    for w in wanted:
        if w in low:
            return low[w]
    return None


def load_csv(path: str | Path, category: str | None = None, limit: int | None = None) -> list[Sample]:
    path = Path(path)
    out: list[Sample] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames or []
        tcol, lcol = _find(cols, TEXT_COLS), _find(cols, LABEL_COLS)
        if not tcol or not lcol:
            raise ValueError(f"{path.name}: could not find text/label columns in {cols}")
        scol, fcol = _find(cols, ["subject"]), _find(cols, ["sender", "from"])
        for i, row in enumerate(reader):
            lab = str(row.get(lcol, "")).strip().lower()
            if lab in POS:
                y = 1
            elif lab in NEG:
                y = 0
            else:
                continue
            body = row.get(tcol) or ""
            if not body.strip():
                continue
            headers = ""
            if fcol and row.get(fcol):
                headers += f"From: {row[fcol].strip()}\n"
            if scol and row.get(scol):
                headers += f"Subject: {' '.join(row[scol].split())}\n"
            raw = f"{headers}\n{body}" if headers else body
            out.append(Sample(raw, y, category or ("phish_real" if y else "legit_real"), f"{path.stem}-{i}"))
            if limit and len(out) >= limit:
                break
    return out


def load_jsonl(path: str | Path) -> list[Sample]:
    out = []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        if line.strip():
            d = json.loads(line)
            out.append(Sample(d["raw"], int(d["label"]), d.get("category", "unknown"), d.get("id", str(i))))
    return out


def save_jsonl(samples: list[Sample], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps({"id": s.id, "label": s.label, "category": s.category, "raw": s.raw}) + "\n")


def load_any(paths: list[str | Path], limit_per_file: int | None = None) -> list[Sample]:
    out = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out += load_any(sorted([*p.glob("*.csv"), *p.glob("*.jsonl")]), limit_per_file)
        elif p.suffix == ".jsonl":
            out += load_jsonl(p)[: limit_per_file or None]
        else:
            out += load_csv(p, limit=limit_per_file)
    return out
