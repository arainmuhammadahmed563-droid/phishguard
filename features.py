"""URL feature extraction (pure Python, no network access needed)."""
import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "paypal", "wallet", "suspend", "unlock", "billing",
    "support", "alert", "validate", "recover", "webscr", "ebay", "apple",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work",
              "zip", "country", "loan", "support", "info", "online", "site"}
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
SUSPICIOUS_EXT = (".php", ".exe", ".zip", ".scr", ".apk", ".js", ".html", ".htm")

# brand -> official registered domains (used for impersonation + trusted list)
BRAND_DOMAINS = {
    "paypal": {"paypal.com"}, "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "youtube.com", "gmail.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in"},
    "netflix": {"netflix.com"}, "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"}, "binance": {"binance.com"},
    "ebay": {"ebay.com"}, "dhl": {"dhl.com"},
    "hbl": {"hbl.com"}, "ubl": {"ubl.com.pk"},
    "easypaisa": {"easypaisa.com.pk"}, "jazzcash": {"jazzcash.com.pk"},
}
TRUSTED_DOMAINS = set().union(*BRAND_DOMAINS.values()) | {
    "wikipedia.org", "github.com", "stackoverflow.com", "linkedin.com",
    "bbc.com", "nytimes.com", "python.org", "mozilla.org", "reddit.com",
    "dropbox.com", "cloudflare.com", "medium.com", "nasa.gov", "mit.edu",
    "dawn.com", "who.int", "gov.pk",
}
_SECOND_LEVEL = {"co", "com", "gov", "org", "net", "edu", "ac"}

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_digits",
    "num_special", "num_subdomains", "has_ip", "has_at", "has_https",
    "has_port", "double_slash_in_path", "num_suspicious_words",
    "is_shortener", "risky_tld", "host_digit_ratio", "url_entropy",
    "host_entropy", "num_params", "hex_encoded_chars", "punycode",
    "longest_token_len", "brand_mismatch", "path_depth", "suspicious_ext",
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def registered_domain(host: str) -> str:
    """'mail.google.com' -> 'google.com'; 'a.b.co.uk' -> 'b.co.uk'."""
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_mismatch(host: str) -> int:
    """1 if a known brand name appears in the host but the domain isn't official."""
    reg = registered_domain(host)
    tokens = re.split(r"[.\-_0-9]+", host)
    for brand, official in BRAND_DOMAINS.items():
        hit = brand in tokens or (len(brand) >= 5 and any(t.startswith(brand) for t in tokens))
        if hit and reg not in official:
            return 1
    return 0


def get_host(url: str) -> str:
    try:
        return (urlparse(normalize(url)).hostname or "").lower()
    except ValueError:
        return ""


def normalize(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_features(url: str) -> dict:
    url = normalize(url)
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        p, host, port = urlparse("http://invalid"), "", None
    path, query = p.path or "", p.query or ""
    labels = [l for l in host.split(".") if l]
    tld = labels[-1] if labels else ""
    low = url.lower()
    tokens = re.split(r"[^a-zA-Z0-9]+", low)

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": sum(not c.isalnum() for c in url),
        "num_subdomains": max(len(labels) - 2, 0),
        "has_ip": int(bool(IP_RE.match(host))),
        "has_at": int("@" in url),
        "has_https": int(p.scheme == "https"),
        "has_port": int(port is not None and port not in (80, 443)),
        "double_slash_in_path": int("//" in path),
        "num_suspicious_words": sum(w in low for w in SUSPICIOUS_WORDS),
        "is_shortener": int(host in SHORTENERS),
        "risky_tld": int(tld in RISKY_TLDS),
        "host_digit_ratio": (sum(c.isdigit() for c in host) / len(host)) if host else 0.0,
        "url_entropy": _entropy(low),
        "host_entropy": _entropy(host),
        "num_params": len([q for q in query.split("&") if q]),
        "hex_encoded_chars": len(re.findall(r"%[0-9a-fA-F]{2}", url)),
        "punycode": int("xn--" in host),
        "longest_token_len": max((len(t) for t in tokens), default=0),
        "brand_mismatch": brand_mismatch(host),
        "path_depth": len([x for x in path.split("/") if x]),
        "suspicious_ext": int(path.lower().endswith(SUSPICIOUS_EXT)),
    }


def features_vector(url: str) -> list:
    f = extract_features(url)
    return [f[n] for n in FEATURE_NAMES]
