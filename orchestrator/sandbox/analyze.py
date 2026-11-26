#!/usr/bin/env python3
"""Rule-based phishing analysis. Runs inside the sandbox container (no network).

Input : path to a JSON file with the email (proto field names).
Output: JSON on stdout: {"score": 0-100, "findings": [...]}
"""
import json
import re
import sys
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq"}
EXEC_EXT = {".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs", ".vbe", ".ps1",
            ".msi", ".jar", ".lnk", ".iso", ".img", ".hta", ".wsf"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz"}
HTML_EXT = {".html", ".htm"}
KEYWORDS = ["verify your account", "confirm your identity", "urgent", "immediately", "suspended",
            "password", "click here", "limited time", "unusual activity", "security alert",
            "wire transfer", "gift card"]

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}")
DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|bat|js|vbs|cmd|com|lnk)$")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})


def norm(token: str) -> str:
    """Undo common lookalike tricks (paypa1 -> paypal, rnicrosoft -> microsoft)."""
    return token.lower().translate(_LEET).replace("rn", "m").replace("vv", "w")


def reg_domain(host: str) -> str:
    """Crude registered-domain extraction (no public-suffix list)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "gov", "ac"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_misuse(host: str):
    """Return (brand, is_lookalike) if host uses a brand name but isn't the brand's domain."""
    reg = reg_domain(host)
    tokens = re.split(r"[.\-_]", host.lower())
    for brand, legit in BRANDS.items():
        if reg in legit:
            continue
        for t in tokens:
            if norm(t) == brand:
                return brand, t != brand
    return None


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.text = [], []
        self._href, self._buf = None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._buf = dict(attrs).get("href"), []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None


def analyze(email: dict) -> dict:
    findings = {}  # description -> points (dict dedupes repeated findings)

    def add(pts, text):
        findings.setdefault(text, pts)

    sender = email.get("sender", "") or ""
    s_name, s_addr = parseaddr(sender)
    s_domain = s_addr.rsplit("@", 1)[-1].lower() if "@" in s_addr else ""
    hdrs = {k.lower(): str(v) for k, v in (email.get("custom_headers") or {}).items()}

    # --- header checks ---
    rt_addr = parseaddr(hdrs.get("reply-to", ""))[1]
    if "@" in rt_addr and s_domain:
        rt_domain = rt_addr.rsplit("@", 1)[-1].lower()
        if reg_domain(rt_domain) != reg_domain(s_domain):
            add(25, f"Reply-To domain ({rt_domain}) differs from sender domain ({s_domain})")
    auth = (hdrs.get("authentication-results", "") + " " + hdrs.get("received-spf", "")).lower()
    if "spf=fail" in auth or "spf=softfail" in auth or hdrs.get("received-spf", "").lower().startswith(("fail", "softfail")):
        add(15, "SPF check failed")
    if "dkim=fail" in auth:
        add(15, "DKIM check failed")
    if "dmarc=fail" in auth:
        add(15, "DMARC check failed")

    # --- sender impersonation ---
    if s_domain:
        hit = brand_misuse(s_domain)
        if hit:
            if hit[1]:
                add(30, f"Sender domain {s_domain} is a lookalike of {hit[0]}")
            else:
                add(30, f"Sender domain {s_domain} uses the name {hit[0]} but is not their domain")
        for tok in re.split(r"[^A-Za-z0-9]+", s_name):
            b = norm(tok)
            if b in BRANDS and reg_domain(s_domain) not in BRANDS[b]:
                add(25, f"Display name claims to be {b} but sender domain is {s_domain}")
                break

    # --- collect links ---
    plain = email.get("plain_text_body", "") or ""
    html = email.get("html_body", "") or ""
    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    html_text = " ".join(parser.text)
    urls = set(URL_RE.findall(plain)) | set(URL_RE.findall(html)) | set(URL_RE.findall(html_text))
    attachments = email.get("attachment_urls", []) or []
    urls |= {a for a in attachments if "://" in a}

    for href, text in parser.links:
        if not href or href.startswith(("mailto:", "#")):
            continue
        urls.add(href)
        shown = DOMAIN_RE.search(text.lower())
        host = (urlparse(href if "://" in href else "http://" + href).hostname or "")
        if shown and host and reg_domain(shown.group(0)) != reg_domain(host):
            add(30, f"Link text shows {shown.group(0)} but points to {host}")

    for url in list(urls)[:50]:
        try:
            u = urlparse(url if "://" in url else "http://" + url)
            host = (u.hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if u.scheme == "http":
            add(5, "Link uses plain http")
        if IP_RE.match(host):
            add(25, f"Link points to a raw IP address ({host})")
        if "@" in u.netloc:
            add(15, f"Link contains '@' in its address ({host})")
        if host in SHORTENERS:
            add(10, f"Link uses URL shortener ({host})")
        if "xn--" in host:
            add(20, f"Link uses punycode domain ({host})")
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add(10, f"Link uses suspicious TLD ({host})")
        hit = brand_misuse(host)
        if hit:
            add(30, f"Link domain {host} impersonates {hit[0]}")

    # --- urgency language ---
    text_blob = ((email.get("subject", "") or "") + " " + plain + " " + html_text).lower()
    hits = [k for k in KEYWORDS if k in text_blob]
    if hits:
        add(min(20, 5 * len(hits)), "Urgency/credential language: " + ", ".join(hits))

    # --- attachments ---
    for a in attachments:
        name = urlparse(a).path.rsplit("/", 1)[-1].lower() or a.lower()
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if DOUBLE_EXT_RE.search(name):
            add(30, f"Attachment {name} has a double extension")
        if ext in EXEC_EXT:
            add(40, f"Attachment {name} is an executable/script type")
        elif ext in MACRO_EXT:
            add(30, f"Attachment {name} is a macro-enabled document")
        elif ext in HTML_EXT:
            add(15, f"Attachment {name} is an HTML file")
        elif ext in ARCHIVE_EXT:
            add(10, f"Attachment {name} is an archive")

    score = min(100, sum(findings.values()))
    return {"score": score, "findings": [f"[+{p}] {t}" for t, p in findings.items()]}


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        print(json.dumps(analyze(json.load(f))))
