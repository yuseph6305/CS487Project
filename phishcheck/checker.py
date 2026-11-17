"""Combines red-flag rules, the ML model, the injection detector and the LLM into one verdict.

Modes (used for the ablation study in the proposal):
  rules  - red-flag checks only
  ml     - ML model only
  llm    - LLM only, no evidence from the other components
  full   - everything: rules + ML + injection detector feed the LLM; guardrails on top.
           Without an API key, `full` falls back to a weighted fusion of rules + ML + injection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .injection import InjectionReport, detect_injection
from .llm import LLMJudge, LLMResult
from .model import DEFAULT_PATH, PhishModel
from .parsing import Email, parse_email
from .redflags import Flag, red_flag_score, run_red_flags

PHISH_T, SUSPICIOUS_T = 0.65, 0.35
MODES = ("rules", "ml", "llm", "full")


@dataclass
class CheckResult:
    verdict: str                          # phishing | suspicious | legitimate | error
    probability: float                    # 0..1 that the email is phishing
    summary: str
    reasons: list[str]
    advice: str
    mode: str
    engine: str                           # what actually produced the verdict
    red_flags: list[Flag] = field(default_factory=list)
    rule_score: float | None = None
    ml_score: float | None = None
    ml_terms: list = field(default_factory=list)
    injection: InjectionReport | None = None
    llm: LLMResult | None = None
    overrides: list[str] = field(default_factory=list)
    email: Email | None = None

    @property
    def is_phishing(self) -> bool:
        return self.probability >= 0.5

    def to_dict(self) -> dict:
        em = self.email
        return {
            "verdict": self.verdict, "probability": round(self.probability, 3), "summary": self.summary,
            "reasons": self.reasons, "advice": self.advice, "mode": self.mode, "engine": self.engine,
            "red_flags": [f.to_dict() for f in self.red_flags], "rule_score": self.rule_score,
            "ml_score": None if self.ml_score is None else round(self.ml_score, 3), "ml_terms": self.ml_terms,
            "injection": self.injection.to_dict() if self.injection else None,
            "llm": self.llm.to_dict() if self.llm else None, "overrides": self.overrides,
            "parsed": None if em is None else {
                "from": em.sender, "reply_to": em.reply_to, "subject": em.subject,
                "links": [{"text": l.text, "href": l.href} for l in em.links], "hidden_text": em.hidden_text,
                "attachments": em.attachments},
        }


def verdict_for(p: float) -> str:
    return "phishing" if p >= PHISH_T else "suspicious" if p >= SUSPICIOUS_T else "legitimate"


ADVICE = {
    "phishing": "Don't click links, open attachments or reply. Report it to your IT/security team or the impersonated company, then delete it.",
    "suspicious": "Be careful. Don't use the links in the email: go to the company's site or app directly, or confirm with the sender through a channel you already trust.",
    "legitimate": "No strong warning signs found. As always, never send passwords or codes by email.",
}


class PhishChecker:
    def __init__(self, model: PhishModel | None = None, llm: LLMJudge | None = None, model_path: str | Path = DEFAULT_PATH):
        if model is None and Path(model_path).exists():
            model = PhishModel.load(model_path)
        self.model = model
        self.llm = llm if llm is not None else LLMJudge()

    # ------------------------------------------------------------------ public
    def check(self, raw: str | Email, mode: str = "full", explain: bool = True) -> CheckResult:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        em = raw if isinstance(raw, Email) else parse_email(raw)
        flags = run_red_flags(em)
        inj = detect_injection(em)
        rscore = red_flag_score(flags)
        ml, terms = (None, [])
        if self.model is not None and mode in ("ml", "full"):
            ml = self.model.score(em)
            terms = self.model.top_terms(em) if explain else []

        common = dict(email=em, red_flags=flags, rule_score=rscore, ml_score=ml, ml_terms=terms, injection=inj)

        if mode == "rules":
            p = max(rscore, 0.8 if inj.detected else 0.0)
            return self._finish(p, mode, "rules", flags, inj, **common)
        if mode == "ml":
            if ml is None:
                return self._error(mode, "No trained model found. Run: python scripts/train.py", **common)
            return self._finish(ml, mode, "ml", [], None, **common)
        if mode == "llm":
            res = self.llm.judge(em)              # no evidence: pure LLM baseline
            if not res.ok:
                return self._error(mode, res.error, llm=res, **common)
            return self._from_llm(res, mode, "llm", [], **common)

        # full
        if self.llm.available:
            res = self.llm.judge(em, flags, ml, terms, inj)
            if res.ok:
                return self._from_llm(res, mode, "rules+ml+injection+llm", self._guardrails(res, flags, inj, ml), **common)
            common["llm"] = res
        return self._finish(self._fuse(rscore, ml, flags, inj), mode,
                            "rules+ml+injection (LLM unavailable)" if ml is not None else "rules+injection (no model, LLM unavailable)",
                            flags, inj, **common)

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _fuse(rscore: float, ml: float | None, flags: list[Flag], inj: InjectionReport) -> float:
        # Noisy-OR: rules add evidence on top of the ML score but never pull it down.
        # (Chosen on held-out data: keeps ML's recall on real phishing, catches more polished phishing.)
        p = rscore if ml is None else 1 - (1 - ml) * (1 - 0.7 * rscore)
        if any(f.severity >= 4 for f in flags):
            p = max(p, 0.8)
        if inj.detected:
            p = max(p, 0.85 if any(f.hidden for f in inj.findings) else 0.75)
        return min(1.0, p)

    @staticmethod
    def _guardrails(res: LLMResult, flags: list[Flag], inj: InjectionReport, ml: float | None) -> list[str]:
        """Rules the LLM cannot talk its way out of. Returns human-readable notes; mutates res."""
        notes = []
        if inj.detected and res.probability < 0.75:
            notes.append("Prompt-injection detected: the LLM's verdict was raised because the email tried to manipulate AI filters.")
            res.probability = max(res.probability, 0.85 if any(f.hidden for f in inj.findings) else 0.75)
        strong = [f for f in flags if f.severity >= 4]
        if strong and res.probability < 0.5:
            notes.append(f"Strong red flag ({strong[0].message}) kept the verdict at least 'suspicious'.")
            res.probability = 0.55
        if res.injection_detected and not inj.detected and res.probability < 0.6:
            notes.append("The LLM noticed a prompt-injection attempt the detector missed.")
            res.probability = 0.7
        return notes

    def _from_llm(self, res: LLMResult, mode, engine, overrides, **common) -> CheckResult:
        v = verdict_for(res.probability)
        reasons = list(res.reasons)
        if res.injection_detected and res.injection_details:
            reasons.insert(0, f"Prompt injection: {res.injection_details}")
        summary = res.summary if v == res.verdict else f"{res.summary} (Raised to '{v}' by safety guardrails.)"
        return CheckResult(v, res.probability, summary, reasons, res.advice or ADVICE[v], mode, engine,
                           llm=res, overrides=overrides, **common)

    def _finish(self, p, mode, engine, flags, inj, **common) -> CheckResult:
        v = verdict_for(p)
        reasons: list[str] = []
        if inj is not None and inj.detected:
            first = next(f for f in inj.findings if f.kind != "concealment")
            reasons.append(f"Prompt injection — {first.message}. Emails that try to manipulate AI filters are almost never legitimate.")
        reasons += [f.message for f in sorted(flags, key=lambda f: -f.severity)[:6]]
        ml = common.get("ml_score")
        if ml is not None and mode != "rules":
            reasons.append(f"The ML model rates it {ml:.0%} likely to be phishing based on its wording.")
        n = sum(1 for f in flags if f.severity >= 2)
        summary = {
            "phishing": f"This looks like a phishing email ({p:.0%} risk). {n} significant warning sign(s) found.",
            "suspicious": f"This email has some warning signs ({p:.0%} risk). Treat it with caution.",
            "legitimate": f"No strong signs of phishing ({p:.0%} risk).",
        }[v]
        return CheckResult(v, p, summary, reasons or ["No red flags found."], ADVICE[v], mode, engine, **common)

    @staticmethod
    def _error(mode, msg, **common) -> CheckResult:
        return CheckResult("error", 0.5, msg, [], "", mode, "none", **common)
