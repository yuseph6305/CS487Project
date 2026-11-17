"""Turn a pasted email (raw .eml, headers + body, or just a body) into a structured object."""
from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from html.parser import HTMLParser

HEADER_RE = re.compile(r"^(From|To|Reply-To|Return-Path|Subject|Date|Cc|Sender|Received|Message-ID|MIME-Version|Content-Type|Authentication-Results|X-[\w-]+):", re.I)
URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"')\]]+""", re.I)
HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem|%)?\s*(?:;|$)|"
    r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|color\s*:\s*(?:#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)\b|"
    r"max-height\s*:\s*0|height\s*:\s*0(?:px)?\s*;?\s*overflow\s*:\s*hidden",
    re.I,
)
VOID_TAGS = {"br", "img", "hr", "meta", "link", "input", "area", "base", "col", "embed", "source", "wbr"}


@dataclass
class Link:
    text: str
    href: str


@dataclass
class Email:
    sender: str = ""          # full From header, e.g. 'PayPal <service@paypa1.com>'
    sender_name: str = ""
    sender_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    auth_results: str = ""
    text: str = ""            # visible text (HTML rendered to text)
    html: str = ""
    links: list[Link] = field(default_factory=list)
    hidden_text: list[str] = field(default_factory=list)   # text a human would not see
    html_comments: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)

    @property
    def sender_domain(self) -> str:
        return domain_of_address(self.sender_address)

    @property
    def reply_to_domain(self) -> str:
        return domain_of_address(parseaddr(self.reply_to)[1])

    def full_text(self) -> str:
        """Everything, including hidden content: what an ML model or LLM would actually read."""
        parts = [self.subject, self.text, *self.hidden_text, *self.html_comments]
        return "\n".join(p for p in parts if p)


def domain_of_address(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().strip(">").lower() if "@" in addr else ""


class _HTMLExtractor(HTMLParser):
    """Extracts visible text, hidden text, links and comments from HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.comments: list[str] = []
        self.links: list[Link] = []
        self._stack: list[bool] = []      # hidden flag per open element
        self._link: dict | None = None
        self._skip = 0                    # inside <script>/<style>

    @property
    def _hidden(self) -> bool:
        return any(self._stack)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
            return
        hidden = bool(HIDDEN_STYLE_RE.search(a.get("style") or "")) or "hidden" in a
        if tag == "a" and a.get("href"):
            self._link = {"href": a["href"].strip(), "text": []}
        if tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "table"):
            (self.hidden if self._hidden else self.visible).append("\n")
        if tag not in VOID_TAGS:
            self._stack.append(hidden)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
            return
        if tag == "a" and self._link is not None:
            self.links.append(Link(" ".join("".join(self._link["text"]).split()), self._link["href"]))
            self._link = None
        if tag not in VOID_TAGS and self._stack:
            self._stack.pop()

    def handle_data(self, data):
        if self._skip:
            return
        if self._link is not None and not self._hidden:
            self._link["text"].append(data)
        (self.hidden if self._hidden else self.visible).append(data)

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip())


def _looks_like_html(s: str) -> bool:
    return bool(re.search(r"<(html|body|div|p|a|span|table|br|font)\b", s, re.I))


def _clean(s: str) -> str:
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n\n", s)
    return s.strip()


def _apply_html(em: Email, html: str) -> None:
    p = _HTMLExtractor()
    p.feed(html)
    p.close()
    em.html = html
    em.text = _clean("".join(p.visible))
    em.hidden_text = [h for h in (_clean(x) for x in "".join(p.hidden).split("\n\n")) if h]
    em.html_comments = p.comments
    em.links.extend(p.links)


def parse_email(raw: str) -> Email:
    """Accepts anything a user might paste."""
    raw = raw.replace("\r\n", "\n").lstrip("﻿")
    em = Email()
    first_lines = raw.lstrip().split("\n", 5)
    has_headers = sum(1 for ln in first_lines if HEADER_RE.match(ln)) >= 1 and HEADER_RE.match(raw.lstrip())

    body_text, body_html = raw, ""
    if has_headers:
        msg = email.message_from_string(raw.lstrip(), policy=email.policy.default)
        em.sender = str(msg.get("From", "") or "")
        em.reply_to = str(msg.get("Reply-To", "") or "")
        em.return_path = str(msg.get("Return-Path", "") or "")
        em.subject = str(msg.get("Subject", "") or "")
        em.auth_results = str(msg.get("Authentication-Results", "") or "")
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                fname = part.get_filename()
                if fname:
                    em.attachments.append(fname)
                    continue
                ctype = part.get_content_type()
                try:
                    content = part.get_content()
                except Exception:
                    content = part.get_payload(decode=True) or b""
                    content = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
                if ctype == "text/html" and not body_html:
                    body_html = content
                elif ctype == "text/plain" and not body_text:
                    body_text = content
        else:
            try:
                content = msg.get_content()
            except Exception:
                content = msg.get_payload()
            content = content if isinstance(content, str) else str(content)
            if msg.get_content_type() == "text/html" or _looks_like_html(content):
                body_html = content
            else:
                body_text = content

    if not body_html and _looks_like_html(body_text):
        body_html, body_text = body_text, ""

    if body_html:
        _apply_html(em, body_html)
        if body_text and not em.text:
            em.text = _clean(body_text)
    else:
        em.text = _clean(body_text)

    # Bare URLs in visible text count as links where the text *is* the href.
    seen = {l.href for l in em.links} | {l.text.rstrip("/") for l in em.links}
    for m in URL_RE.finditer(em.text):
        url = m.group(0).rstrip(".,;:!?")
        if url not in seen and url.rstrip("/") not in seen:
            em.links.append(Link(url, url))
            seen.add(url)

    name, addr = parseaddr(em.sender)
    em.sender_name, em.sender_address = name.strip(), addr.strip().lower()
    return em
