#!/usr/bin/env python3
"""Train the ML model.

  python scripts/train.py                          # synthetic demo data only
  python scripts/train.py --data data/real/        # every CSV/JSONL in a folder (e.g. Kaggle phishing datasets)
  python scripts/train.py --data a.csv b.csv --no-synthetic --limit 20000
"""
import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sklearn.metrics import classification_report, roc_auc_score  # noqa: E402

from phishcheck.data import load_any, save_jsonl  # noqa: E402
from phishcheck.model import DEFAULT_PATH, PhishModel  # noqa: E402
from phishcheck.parsing import parse_email  # noqa: E402
from phishcheck.synthetic import generate  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="*", default=[], help="CSV/JSONL files or folders with real datasets")
    ap.add_argument("--no-synthetic", action="store_true", help="don't add the synthetic training set")
    ap.add_argument("--limit", type=int, default=None, help="max rows per file")
    ap.add_argument("--holdout", type=float, default=0.2, help="fraction of real data held out for testing")
    ap.add_argument("--out", default=str(DEFAULT_PATH))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    train, test = [], []
    if args.data:
        real = load_any(args.data, args.limit)
        rng.shuffle(real)
        k = int(len(real) * args.holdout)
        test += real[:k]
        train += real[k:]
        save_jsonl(real[:k], ROOT / "data" / "real_test.jsonl")
        print(f"real data: {len(real)} emails ({sum(s.label for s in real)} phishing) -> {len(real)-k} train / {k} test")
    if not args.no_synthetic:
        syn_train = generate(150, split="train", seed=args.seed)
        syn_test = generate(60, split="test", seed=args.seed + 1)
        save_jsonl(syn_train, ROOT / "data" / "synthetic_train.jsonl")
        save_jsonl(syn_test, ROOT / "data" / "synthetic_test.jsonl")
        train += syn_train
        test += syn_test
        print(f"synthetic: {len(syn_train)} train / {len(syn_test)} test (test uses unseen templates)")
    if not train:
        sys.exit("no training data")

    print("parsing…")
    Xtr = [parse_email(s.raw) for s in train]
    ytr = [s.label for s in train]
    model = PhishModel().fit(Xtr, ytr)
    model.save(args.out)
    print(f"saved model -> {args.out}")

    if test:
        p = model.predict_proba([parse_email(s.raw) for s in test])
        y = [s.label for s in test]
        print("\nheld-out test set:")
        print(classification_report(y, (p >= 0.5).astype(int), target_names=["legit", "phishing"], digits=3))
        if len(set(y)) == 2:
            print(f"ROC-AUC: {roc_auc_score(y, p):.3f}")


if __name__ == "__main__":
    main()
