"""ML phishing classifier: TF-IDF (word + char n-grams) + a few structural features -> logistic regression."""
from __future__ import annotations

import re
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .parsing import Email, parse_email
from .redflags import host_of, registrable_domain

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "models" / "phish_model.joblib"


def model_text(em: Email) -> str:
    """Text the model sees. URLs are replaced by tokens so the model learns patterns, not specific domains."""
    def url_tok(m):
        host = host_of(m.group(0))
        tld = registrable_domain(host).rsplit(".", 1)[-1] if host else "none"
        return f" URLTOKEN URLTLD_{tld} "
    sender = f"SENDERTLD_{em.sender_domain.rsplit('.', 1)[-1]}" if em.sender_domain else "NOSENDER"
    body = re.sub(r"(?:https?://|www\.)\S+", url_tok, em.full_text())
    return f"{sender} {em.sender_name}\n{body}"


def structural_features(em: Email) -> list[float]:
    text = em.text
    words = max(1, len(text.split()))
    hosts = {registrable_domain(host_of(l.href)) for l in em.links if host_of(l.href)}
    sender_reg = registrable_domain(em.sender_domain) if em.sender_domain else ""
    return [
        min(len(em.links), 10) / 10,
        min(len(hosts), 5) / 5,
        float(bool(sender_reg) and bool(hosts) and sender_reg not in hosts),
        float(bool(em.reply_to_domain) and registrable_domain(em.reply_to_domain) != sender_reg),
        float(bool(em.html)),
        min(sum(len(h.split()) for h in em.hidden_text), 50) / 50,
        sum(c.isupper() for c in text) / max(1, len(text)),
        min(text.count("!"), 10) / 10,
        min(words, 500) / 500,
    ]


class PhishModel:
    def __init__(self):
        self.word = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=40000, sublinear_tf=True, lowercase=True)
        self.char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=60000, sublinear_tf=True)
        self.clf = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced")

    def _X(self, emails: list[Email], fit: bool = False):
        texts = [model_text(e) for e in emails]
        if fit:
            W, C = self.word.fit_transform(texts), self.char.fit_transform(texts)
        else:
            W, C = self.word.transform(texts), self.char.transform(texts)
        S = csr_matrix(np.array([structural_features(e) for e in emails]))
        return hstack([W, C, S]).tocsr()

    def fit(self, emails: list[Email], labels: list[int]) -> "PhishModel":
        self.clf.fit(self._X(emails, fit=True), labels)
        return self

    def predict_proba(self, emails: list[Email]) -> np.ndarray:
        return self.clf.predict_proba(self._X(emails))[:, 1]

    def score(self, em: Email | str) -> float:
        em = parse_email(em) if isinstance(em, str) else em
        return float(self.predict_proba([em])[0])

    def top_terms(self, em: Email, k: int = 6) -> list[tuple[str, float]]:
        """Most influential word n-grams for this email (for explanations)."""
        x = self.word.transform([model_text(em)])
        coefs = self.clf.coef_[0][: len(self.word.vocabulary_)]
        contrib = x.multiply(coefs).tocsr()
        names = self.word.get_feature_names_out()
        idx = contrib.indices[np.argsort(-np.abs(contrib.data))][:k]
        return [(names[i], round(float(contrib[0, i]), 3)) for i in idx]

    def save(self, path: str | Path = DEFAULT_PATH) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path = DEFAULT_PATH) -> "PhishModel":
        return joblib.load(path)
