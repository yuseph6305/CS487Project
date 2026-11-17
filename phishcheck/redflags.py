"""Rule-based red-flag checks: sender domains, links, lookalikes and classic phishing language."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

from .parsing import Email

# Official domains of commonly impersonated brands. Extend freely.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "office365.com", "microsoftonline.com"},
    "office365": {"office.com", "office365.com", "microsoft.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ca", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citi.com", "citibank.com"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "dhl": {"dhl.com"},
    "irs": {"irs.gov"},
    "coinbase": {"coinbase.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com"},
    "adobe": {"adobe.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "ebay": {"ebay.com"},
    "walmart": {"walmart.com"},
    "github": {"github.com"},
}
BRAND_DISPLAY = {"wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America", "office365": "Office 365"}

FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com", "proton.me",
             "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com", "live.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "rb.gy", "tiny.cc", "t.ly", "s.id", "v.gd"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "link", "work", "support", "rest", "country", "gq", "tk", "ml",
              "cf", "ga", "buzz", "monster", "cam", "icu", "live", "shop", "online", "site", "info", "ru", "cn", "su"}
MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.in", "com.br",
                       "com.mx", "co.nz", "com.cn", "co.za"}
DANGEROUS_EXT = re.compile(r"\.(exe|scr|js|vbs|bat|cmd|msi|jar|iso|img|html?|hta|lnk|docm|xlsm|pptm|zip|rar|7z)$", re.I)

PHISHY_AFFIXES = {"secure", "security", "login", "signin", "verify", "verification", "account", "accounts", "support",
                  "update", "service", "services", "help", "helpdesk", "billing", "online", "auth", "alert", "alerts",
                  "team", "center", "id", "safe", "access", "my", "web", "mail", "pay", "payment", "refund", "notice", "app", "bank", "banking", "official", "portal", "member", "customer", "info"}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a",
                            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
                            "і": "i", "ԁ": "d", "ɡ": "g"})

PATTERNS: list[tuple[str, int, str, re.Pattern]] = [
    ("urgency", 2, "Pressures you to act fast",
     re.compile(r"\b(urgent(ly)?|immediately|within \d+ (hours?|minutes?|days?)|act now|right away|as soon as possible|"
                r"final (notice|warning|reminder)|last chance|expires? (today|soon|in)|deadline|time[- ]sensitive|asap)\b", re.I)),
    ("threat", 2, "Threatens account suspension, legal action or loss",
     re.compile(r"\b(suspend(ed|ion)?|locked|disabled|deactivat(ed|ion)|terminat(ed|ion)|permanently (closed|deleted)|"
                r"legal action|arrest|penalt(y|ies)|unauthori[sz]ed (access|activity|login|sign[- ]in)|"
                r"unusual (activity|sign[- ]in)|compromised|restricted|on hold)\b", re.I)),
    ("credentials", 3, "Asks you to verify, log in, or hand over credentials or personal data",
     re.compile(r"\b(verify (your|the) (account|identity|information|details|email|payment)|confirm (your|the) "
                r"(account|identity|password|details|billing|payment)|(re-?)?enter (your )?(password|credentials|pin)|"
                r"update (your )?(payment|billing|account) (information|details|method)|social security|ssn\b|"
                r"one[- ]time (code|passcode)|mfa code|2fa code|validate your (account|mailbox)|sign in to (restore|unlock|confirm)|"
                r"log ?in to (restore|unlock|verify|confirm|avoid))", re.I)),
    ("money", 2, "Mentions payments, gift cards, wire transfers or crypto",
     re.compile(r"\b(gift ?cards?|wire transfer|bitcoin|btc|crypto(currency)? wallet|western union|moneygram|"
                r"refund (of|is) (pending|available)|unclaimed|you('ve| have) won|lottery|prize|inheritance|"
                r"invoice (attached|overdue)|outstanding (balance|payment)|bank details|routing number)\b", re.I)),
    ("secrecy", 2, "Asks you to keep it secret or bypass normal process",
     re.compile(r"\b(keep (this|it) (confidential|between us|quiet)|don'?t (tell|mention|share) (anyone|this)|"
                r"i'?m in a meeting|can'?t talk (right )?now|do not discuss)\b", re.I)),
    ("generic_greeting", 1, "Uses a generic greeting instead of your name",
     re.compile(r"^\s*(dear (customer|user|client|member|account ?holder|valued \w+|sir|madam|sir/madam|beneficiary)|"
                r"hello (customer|user|dear)|greetings)\b", re.I | re.M)),
]


@dataclass
class Flag:
    id: str
    severity: int        # 1 = weak signal, 3 = strong, 4 = near-conclusive
    message: str
    evidence: str = ""

    def to_dict(self):
        return asdict(self)


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".").split(":")[0]
    if host.startswith("xn--") or ".xn--" in host:
        try:
            host = host.encode().decode("idna")
        except Exception:
            pass
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def host_of(url: str) -> str:
    u = url.strip()
    if u.lower().startswith("www."):
        u = "http://" + u
    try:
        return (urlparse(u).hostname or "").lower()
    except ValueError:
        return ""


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _official(domain: str) -> str | None:
    """Brand key if `domain` is one of the brand's official domains."""
    for brand, doms in BRANDS.items():
        if domain in doms:
            return brand
    return None


def lookalike_brand(host: str) -> str | None:
    """Return the brand a host is impersonating, or None. Official domains return None."""
    if not host:
        return None
    reg = registrable_domain(host)
    if _official(reg):
        return None
    raw_host = host.lower()
    is_idn = "xn--" in raw_host or any(ord(c) > 127 for c in raw_host)
    label = reg.split(".")[0]
    homo = label.translate(HOMOGLYPHS)
    squashed = re.sub(r"[^a-z]", "", homo)
    variants = {squashed, squashed.replace("rn", "m"), squashed.replace("vv", "w")}
    tokens = [t for t in re.split(r"[-_]+", homo) if t]
    sub = raw_host[: -len(reg)].strip(".") if raw_host.endswith(reg) else ""
    sub_tokens = {t for t in re.split(r"[.\-_]+", sub.translate(HOMOGLYPHS)) if t}
    for brand in BRANDS:
        if brand in sub_tokens:
            return brand                                   # paypal.com.verify-account.ru, ups.track-parcel.top
        if brand in variants and (label != brand or is_idn):
            return brand                                   # paypa1.com, rnicrosoft.com, аpple.com (Cyrillic а)
        if label == brand and reg.rsplit(".", 1)[-1] in RISKY_TLDS:
            return brand                                   # paypal.xyz — brand on a throwaway TLD
        if brand in tokens:
            return brand                                   # paypal-security.com, usps-redelivery.top
        if len(brand) < 4:
            continue                                       # ups/dhl/irs: too short for fuzzy matching
        for t in tokens:
            if t != brand and (t.startswith(brand) or t.endswith(brand)):
                rest = t.replace(brand, "", 1)
                if rest in PHISHY_AFFIXES:
                    return brand                           # paypalsupport.com, securechase.net
        if len(brand) >= 6 and any(_levenshtein(v, brand) <= (1 if len(brand) <= 7 else 2) for v in variants):
            return brand                                   # paypall.com, amazom.com
    return None


def _display_brand(b: str) -> str:
    return BRAND_DISPLAY.get(b, b.capitalize())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def check_sender(em: Email) -> list[Flag]:
    flags: list[Flag] = []
    dom = registrable_domain(em.sender_domain) if em.sender_domain else ""
    if not dom:
        return flags

    imp = lookalike_brand(em.sender_domain)
    if imp:
        flags.append(Flag("sender_lookalike", 4,
                          f"Sender domain '{em.sender_domain}' imitates {_display_brand(imp)} but is not one of its real domains",
                          em.sender_address))

    name_l = em.sender_name.lower()
    name_squashed = re.sub(r"[^a-z]", "", name_l)
    for brand in BRANDS:
        if (brand in name_squashed if len(brand) >= 4 else re.search(rf"\b{brand}\b", name_l)) and dom not in BRANDS[brand]:
            if not imp:
                flags.append(Flag("display_name_spoof", 3,
                                  f"Display name says '{em.sender_name}' but the address is from '{dom}', not a {_display_brand(brand)} domain",
                                  em.sender))
            break
    else:
        m = re.search(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", em.sender_name, re.I)
        if m and registrable_domain(m.group(0).split("@")[1]) != dom:
            flags.append(Flag("display_name_spoof", 3, "Display name contains a different email address than the real sender",
                              em.sender))

    if em.reply_to_domain and registrable_domain(em.reply_to_domain) != dom:
        flags.append(Flag("reply_to_mismatch", 2,
                          f"Replies go to '{em.reply_to_domain}', a different domain from the sender '{dom}'", em.reply_to))

    if em.return_path:
        rp = registrable_domain(em.return_path.split("@")[-1].strip("<> "))
        if rp and rp != dom and "@" in em.return_path:
            flags.append(Flag("return_path_mismatch", 1, f"Return-Path domain '{rp}' differs from sender '{dom}'",
                              em.return_path))

    corp_words = re.search(r"\b(support|security|billing|account|service|team|helpdesk|it department|admin|payroll|hr)\b", name_l)
    if dom in FREE_MAIL and corp_words:
        flags.append(Flag("freemail_official", 2,
                          f"Claims to be '{em.sender_name}' but sends from a free webmail account ({dom})", em.sender_address))

    tld = dom.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        flags.append(Flag("sender_risky_tld", 1, f"Sender uses the '.{tld}' top-level domain, common in phishing", dom))

    ar = em.auth_results.lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mech}=(fail|softfail|permerror)", ar):
            flags.append(Flag(f"{mech}_fail", 3, f"{mech.upper()} authentication failed for this message", mech))
    return flags


def check_links(em: Email) -> list[Flag]:
    flags: list[Flag] = []
    sender_dom = registrable_domain(em.sender_domain) if em.sender_domain else ""
    seen: set[str] = set()

    def add(f: Flag):
        key = f.id + f.evidence
        if key not in seen:
            seen.add(key)
            flags.append(f)

    for link in em.links:
        href = link.href
        hl = href.lower()
        if hl.startswith(("mailto:", "tel:", "#")):
            continue
        if hl.startswith(("javascript:", "data:", "file:")):
            add(Flag("dangerous_scheme", 4, f"Link uses a '{hl.split(':')[0]}:' URL, which can run code or hide content", href[:80]))
            continue
        host = host_of(href)
        if not host:
            continue
        reg = registrable_domain(host)

        if _is_ip(host):
            add(Flag("ip_url", 3, f"Link points at a raw IP address ({host}) instead of a domain name", href))
        if "@" in (urlparse(href if "//" in href else "http://" + href).netloc or ""):
            add(Flag("userinfo_url", 4, "Link hides its real destination after an '@' sign", href))
        if "xn--" in host:
            add(Flag("punycode_url", 3, f"Link uses an internationalized (punycode) domain that can disguise letters: {host}", href))
        if reg in SHORTENERS:
            add(Flag("shortened_url", 2, f"Link uses a URL shortener ({reg}) that hides where it goes", href))
        imp = lookalike_brand(host)
        if imp:
            add(Flag("link_lookalike", 4, f"Link goes to '{host}', which imitates {_display_brand(imp)}", href))
        tld = reg.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS and not imp:
            add(Flag("link_risky_tld", 1, f"Link uses the '.{tld}' top-level domain, common in phishing", href))
        if host.count(".") >= 4:
            add(Flag("deep_subdomain", 1, f"Link has an unusually deep subdomain chain ({host})", href))

        # Text says one place, href goes somewhere else.
        shown_host = ""
        m = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})(?:/|\b)", link.text.strip(), re.I)
        if m and link.text.strip() != href:
            shown_host = m.group(1).lower()
        if shown_host and registrable_domain(shown_host) != reg:
            add(Flag("link_text_mismatch", 4,
                     f"Link text shows '{shown_host}' but actually goes to '{host}'", f"{link.text} -> {href}"))
        else:
            # Text names a brand, link goes elsewhere ("Log in to PayPal" -> evil.com)
            text_sq = re.sub(r"[^a-z]", "", link.text.lower())
            for brand, doms in BRANDS.items():
                if len(brand) >= 4 and brand in text_sq and reg not in doms and not imp:
                    add(Flag("link_brand_mismatch", 3,
                             f"Link text mentions {_display_brand(brand)} but goes to '{reg}'", f"{link.text} -> {href}"))
                    break

        # Sender claims a brand but links go elsewhere.
        sb = _official(sender_dom) if sender_dom else None
        if sb and reg not in BRANDS[sb] and not _official(reg) and reg not in SHORTENERS:
            add(Flag("offdomain_link", 1, f"Email is from {sender_dom} but links to unrelated domain '{reg}'", href))

        if href.lower().startswith("http://") and re.search(r"login|signin|verify|account|secure|password|update", hl):
            add(Flag("insecure_login_link", 2, "Login/verification link is not using HTTPS", href))
    return flags


def check_content(em: Email) -> list[Flag]:
    flags: list[Flag] = []
    text = f"{em.subject}\n{em.text}"
    for fid, sev, msg, pat in PATTERNS:
        hits = sorted({m.group(0).strip() for m in pat.finditer(text)}, key=str.lower)
        if hits:
            flags.append(Flag(fid, sev, msg, ", ".join(f'"{h}"' for h in hits[:4])))
    for att in em.attachments:
        if DANGEROUS_EXT.search(att) or re.search(r"\.\w{2,4}\.(exe|scr|js|html?)$", att, re.I):
            flags.append(Flag("dangerous_attachment", 3, f"Attachment '{att}' is a file type often used to deliver malware or fake login pages", att))
    m = re.search(r"\b(see|open|download|review) (the )?attached (\w+ )?(invoice|document|file|statement|form)\b", text, re.I)
    if m and not em.attachments:
        flags.append(Flag("attachment_lure", 1, "Pushes you to open an attached document", m.group(0)))
    if re.search(r"<form\b[^>]*>.*?(password|passwd|ssn|card)", em.html or "", re.I | re.S):
        flags.append(Flag("embedded_form", 4, "Email contains an embedded form asking for a password or card details", "<form>"))
    return flags


def run_red_flags(em: Email) -> list[Flag]:
    return check_sender(em) + check_links(em) + check_content(em)


def red_flag_score(flags: list[Flag]) -> float:
    """Squash summed severities into 0..1. ~4 points ≈ 0.5, ~8 ≈ 0.8."""
    total = sum(f.severity for f in flags if not f.id.startswith("injection"))
    return round(1 - 0.84 ** total, 3) if total else 0.0
