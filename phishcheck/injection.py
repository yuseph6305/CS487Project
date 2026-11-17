"""Detects prompt injections aimed at AI email assistants / classifiers.

Two kinds of signal:
  * concealment  - text a human reader can't see (hidden CSS, zero-width chars, HTML comments, tiny/white text)
  * instruction  - text that addresses an AI model or tries to dictate the verdict
Instructions that are also concealed are the strongest signal.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, asdict

from .parsing import Email

ZERO_WIDTH = re.compile("[​‌‍⁠﻿᠎­‪-‮⁦-⁩]")
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")   # invisible Unicode "tag" characters (ASCII smuggling)

INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override", re.compile(r"\b(ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|directives?|guidelines?|context|system prompt)\b", re.I)),
    ("role_address", re.compile(r"\b(attention|note|message|instructions?)\s+(to|for)\s+(the\s+)?(ai|a\.i\.|llm|assistant|language model|chatbot|gpt|claude|gemini|copilot|classifier|filter|scanner|model)\b", re.I)),
    ("role_address", re.compile(r"\b(dear|hey|hi)\s+(ai|assistant|llm|chatbot|gpt|claude|gemini|copilot|model)\b", re.I)),
    ("role_address", re.compile(r"\byou are (now |an? )?(ai|helpful|language model|assistant|email (assistant|classifier|filter)|security (scanner|filter))\b", re.I)),
    ("role_address", re.compile(r"\b(as an ai|ai (assistant|model|system)s? (reading|processing|analy[sz]ing|scanning))\b", re.I)),
    ("verdict_steering", re.compile(r"\b(classify|mark|label|flag|treat|report|rate|consider|categori[sz]e)\b[^.\n]{0,40}\b(this|the|it)\b[^.\n]{0,25}\b(as\s+)?(safe|legitimate|legit|benign|not (phishing|spam|suspicious)|trusted|clean|harmless|verified)\b", re.I)),
    ("verdict_steering", re.compile(r"\b(this (email|message) is|it is)\s+(100%\s+|completely\s+|totally\s+)?(safe|legitimate|benign|not phishing|verified|trusted)\b[^.\n]{0,40}\b(do not|don't|no need to)\s+(flag|warn|report|alert)", re.I)),
    ("verdict_steering", re.compile(r"\b(respond|reply|answer|output|return|say)\s+(only\s+)?(with\s+)?[\"']?(safe|legitimate|not phishing|benign|0|false)[\"']?\b", re.I)),
    ("verdict_steering", re.compile(r"\b(phishing|risk|threat|spam)\s*(score|probability|level)\s*(=|:|is|of|should be)\s*(0|zero|low|none|0\.0+)\b", re.I)),
    ("system_spoof", re.compile(r"(^|\n)\s*(system|assistant|developer)\s*:|<\|?(im_start|system|endoftext)\|?>|\[/?(system|inst)\]|<</?sys>>|###\s*(system|instruction)", re.I)),
    ("system_spoof", re.compile(r"\b(new|updated|revised) (system )?(instructions?|rules|policy)\s*:", re.I)),
    ("action_hijack", re.compile(r"\b(forward|send|share|export|upload)\s+(all|every|the user'?s?|their|your|recent|any)\b[^.\n]{0,25}\b(emails?|messages?|inbox|contacts?|passwords?|credentials|api keys?|files|conversations?|history)\b[^.\n]{0,30}\bto\b", re.I)),
    ("action_hijack", re.compile(r"\b(click|open|visit|summari[sz]e)\b[^.\n]{0,30}\b(on behalf of|without (asking|telling|confirming)|automatically)\b", re.I)),
    ("action_hijack", re.compile(r"\b(do not|don'?t|never)\s+(mention|reveal|tell|inform|warn|alert)\b[^.\n]{0,30}\b(the )?(user|recipient|human|reader)\b", re.I)),
    ("jailbreak", re.compile(r"\b(developer mode|dan mode|jailbreak|do anything now|unfiltered mode|pretend (you are|to be)|roleplay as)\b", re.I)),
]


@dataclass
class InjectionFinding:
    kind: str           # override | role_address | verdict_steering | system_spoof | action_hijack | jailbreak | concealment
    hidden: bool        # was it in content a human can't see?
    message: str
    evidence: str

    def to_dict(self):
        return asdict(self)


@dataclass
class InjectionReport:
    detected: bool
    score: float                    # 0..1
    findings: list[InjectionFinding]

    def to_dict(self):
        return {"detected": self.detected, "score": self.score, "findings": [f.to_dict() for f in self.findings]}


def _snip(s: str, n: int = 140) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _decode_tag_chars(s: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0000 <= ord(c) <= 0xE007F)


def _decoded_base64_blobs(s: str) -> list[str]:
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", s):
        try:
            dec = base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except Exception:
            continue
        if sum(c.isprintable() for c in dec) / max(1, len(dec)) > 0.95:
            out.append(dec)
    return out


def _scan(text: str, hidden: bool, where: str) -> list[InjectionFinding]:
    found = []
    norm = unicodedata.normalize("NFKC", ZERO_WIDTH.sub("", text))
    for kind, pat in INSTRUCTION_PATTERNS:
        m = pat.search(norm)
        if m:
            start = max(0, m.start() - 30)
            if start:
                sp = norm.find(" ", start, m.start())
                start = sp + 1 if sp != -1 else m.start()
            found.append(InjectionFinding(kind, hidden, f"{where}: {_KIND_MSG[kind]}", _snip(norm[start: m.end() + 60])))
    return found


_KIND_MSG = {
    "override": "tries to override an AI's instructions",
    "role_address": "speaks directly to an AI model",
    "verdict_steering": "tries to dictate the safety verdict",
    "system_spoof": "imitates system/chat-template markup",
    "action_hijack": "tries to make an AI assistant take an action",
    "jailbreak": "uses jailbreak phrasing",
}


def detect_injection(em: Email) -> InjectionReport:
    findings: list[InjectionFinding] = []

    # 1. Content hidden from humans
    for h in em.hidden_text:
        findings += _scan(h, True, "Hidden text")
    for c in em.html_comments:
        findings += _scan(c, True, "HTML comment")
    raw_all = "\n".join([em.subject, em.text, em.html, *em.hidden_text])
    tag_payload = _decode_tag_chars(raw_all)
    if tag_payload.strip():
        findings.append(InjectionFinding("concealment", True, "Invisible Unicode tag characters smuggle hidden text",
                                         _snip(tag_payload)))
        findings += _scan(tag_payload, True, "Invisible Unicode text")
    for blob in _decoded_base64_blobs(em.text + "\n" + "\n".join(em.hidden_text)):
        findings += _scan(blob, True, "Base64-encoded text")

    # 2. Visible text
    findings += _scan(em.subject + "\n" + em.text, False, "Visible text")

    # 3. Concealment on its own (even without obvious instructions)
    zw = len(ZERO_WIDTH.findall(em.text + em.subject))
    if zw >= 5:
        findings.append(InjectionFinding("concealment", True, f"Contains {zw} zero-width/invisible characters, used to hide or split words",
                                         f"{zw} characters"))
    hidden_words = sum(len(h.split()) for h in em.hidden_text)
    if hidden_words >= 15:
        findings.append(InjectionFinding("concealment", True,
                                         f"{hidden_words} words of text are hidden with CSS (invisible to the reader, visible to AI)",
                                         _snip(" | ".join(em.hidden_text))))

    # Deduplicate
    uniq, seen = [], set()
    for f in findings:
        k = (f.kind, f.evidence[:60])
        if k not in seen:
            seen.add(k)
            uniq.append(f)

    instr = [f for f in uniq if f.kind != "concealment"]
    hidden_instr = [f for f in instr if f.hidden]
    score = 0.0
    if hidden_instr:
        score = 0.95
    elif instr:
        strong = {f.kind for f in instr} & {"override", "system_spoof", "verdict_steering", "action_hijack"}
        score = 0.85 if strong else 0.5
    elif uniq:
        score = 0.4
    return InjectionReport(detected=score >= 0.5, score=score, findings=uniq)


def sanitize_for_llm(text: str) -> str:
    """Neutralise characters that could break the LLM prompt's data boundary."""
    text = ZERO_WIDTH.sub("", text)
    text = TAG_CHARS.sub("", text)
    text = re.sub(r"</?\s*untrusted_email[^>]*>", "[removed tag]", text, flags=re.I)
    return text
