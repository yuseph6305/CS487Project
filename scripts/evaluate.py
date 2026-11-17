#!/usr/bin/env python3
"""Ablation study: compare rules-only, ML-only, LLM-only and the full checker.

Reports, overall and per category (real phishing, AI-written phishing, prompt injection, normal email):
  detection rate (recall on phishing), false-positive rate on normal email, precision, F1, accuracy.

  python scripts/evaluate.py                                   # synthetic held-out test set
  python scripts/evaluate.py --data data/real_test.jsonl data/synthetic_test.jsonl
  python scripts/evaluate.py --modes rules ml full --limit 200 --out results/
"""
import argparse
import csv
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishcheck.checker import PhishChecker  # noqa: E402
from phishcheck.data import load_any  # noqa: E402
from phishcheck.parsing import parse_email  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def metrics(rows):
    tp = sum(1 for y, p in rows if y and p)
    fp = sum(1 for y, p in rows if not y and p)
    fn = sum(1 for y, p in rows if y and not p)
    tn = sum(1 for y, p in rows if not y and not p)
    pos, neg = tp + fn, fp + tn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / pos if pos else None
    f1 = 2 * prec * rec / (prec + rec) if rec and prec + rec else 0.0
    return {"n": len(rows), "detection_rate": rec, "false_positive_rate": fp / neg if neg else None,
            "precision": prec if pos else None, "f1": f1 if pos else None, "accuracy": (tp + tn) / len(rows) if rows else None}


def fmt(x):
    return "   -  " if x is None else f"{x:6.1%}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="*", default=[str(ROOT / "data" / "synthetic_test.jsonl")])
    ap.add_argument("--modes", nargs="*", default=["rules", "ml", "llm", "full"])
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default=str(ROOT / "results"))
    args = ap.parse_args()

    samples = load_any(args.data)[: args.limit or None]
    checker = PhishChecker()
    modes = [m for m in args.modes if not (m == "llm" and not checker.llm.available)]
    if "llm" in args.modes and "llm" not in modes:
        print("! skipping 'llm' mode: no ANTHROPIC_API_KEY set ('full' will use its offline fusion fallback)\n")
    if checker.model is None:
        modes = [m for m in modes if m != "ml"]
        print("! no trained model: run scripts/train.py first; skipping 'ml'\n")

    parsed = [parse_email(s.raw) for s in samples]
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    preds = []
    summary = {}
    for mode in modes:
        t0 = time.time()
        per_cat = defaultdict(list)
        allrows = []
        for s, em in zip(samples, parsed):
            r = checker.check(em, mode=mode, explain=False)
            yhat = int(r.is_phishing)
            per_cat[s.category].append((s.label, yhat))
            allrows.append((s.label, yhat))
            preds.append({"id": s.id, "category": s.category, "label": s.label, "mode": mode, "verdict": r.verdict,
                          "probability": round(r.probability, 3), "engine": r.engine,
                          "injection_detected": r.injection.detected if r.injection else None})
        summary[mode] = {"overall": metrics(allrows), **{c: metrics(v) for c, v in sorted(per_cat.items())},
                         "seconds": round(time.time() - t0, 1), "engine": r.engine}

    cats = sorted({s.category for s in samples})
    print(f"Evaluated {len(samples)} emails: " + ", ".join(f"{c}={sum(1 for s in samples if s.category == c)}" for c in cats))
    print(f"\n{'mode':8} {'detect':>7} {'FPR':>7} {'prec':>7} {'F1':>7} {'acc':>7}   engine")
    for mode, m in summary.items():
        o = m["overall"]
        print(f"{mode:8} {fmt(o['detection_rate'])} {fmt(o['false_positive_rate'])} {fmt(o['precision'])} {fmt(o['f1'])} {fmt(o['accuracy'])}   {m['engine']}")
    print("\nPer category (detection rate for phishing categories, false-positive rate for legit):")
    print(f"{'category':16}" + "".join(f"{m:>9}" for m in summary))
    for c in cats:
        cells = []
        for mode in summary:
            mm = summary[mode][c]
            cells.append(fmt(mm["detection_rate"] if mm["detection_rate"] is not None else mm["false_positive_rate"]))
        tag = " (FPR)" if summary[next(iter(summary))][c]["detection_rate"] is None else ""
        print(f"{(c + tag):16}" + "".join(f"  {x:>7}" for x in cells))

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    with (out_dir / "predictions.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(preds[0]))
        w.writeheader()
        w.writerows(preds)
    print(f"\nwrote {out_dir/'summary.json'} and {out_dir/'predictions.csv'}")


if __name__ == "__main__":
    main()
