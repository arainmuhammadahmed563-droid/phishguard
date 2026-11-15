"""Generate a synthetic labelled URL dataset (label 1 = phishing, 0 = legit).

NOTE: Synthetic data is for demo/testing only. For real-world accuracy, train
on a real dataset (e.g. Kaggle 'Phishing Site URLs' / PhishTank) with columns
`url,label` -- see README.
"""
import argparse
import os
import random
import string

import pandas as pd

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com", "amazon.com",
    "microsoft.com", "apple.com", "stackoverflow.com", "linkedin.com",
    "bbc.com", "nytimes.com", "python.org", "mozilla.org", "reddit.com",
    "netflix.com", "dropbox.com", "paypal.com", "ebay.com", "cloudflare.com",
    "medium.com", "nasa.gov", "mit.edu", "dawn.com", "who.int", "gov.pk",
]
LEGIT_PATHS = ["", "/", "/about", "/docs/intro", "/blog/2024/post-title",
               "/products/item", "/search", "/help/contact", "/news/world",
               "/wiki/Python_(programming_language)", "/downloads", "/careers"]
LEGIT_QUERIES = ["", "", "", "?q=python", "?id=42", "?page=2&sort=asc", "?lang=en"]

BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix",
          "facebook", "instagram", "hbl", "ubl", "easypaisa", "jazzcash",
          "binance", "dhl", "ebay"]
WORDS = ["login", "verify", "secure", "update", "account", "signin",
         "confirm", "banking", "support", "billing", "unlock", "recover"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work",
            "online", "site", "info", "support"]


def rnd(n, chars=string.ascii_lowercase + string.digits):
    return "".join(random.choice(chars) for _ in range(n))


def legit_url():
    scheme = random.choices(["https", "http"], [0.85, 0.15])[0]
    dom = random.choice(LEGIT_DOMAINS)
    sub = random.choice(["", "", "www.", "docs.", "mail.", "blog.", "support."])
    return f"{scheme}://{sub}{dom}{random.choice(LEGIT_PATHS)}{random.choice(LEGIT_QUERIES)}"


def phish_url():
    brand, w1, w2 = random.choice(BRANDS), random.choice(WORDS), random.choice(WORDS)
    tld = random.choice(BAD_TLDS)
    kind = random.randint(0, 5)
    if kind == 0:  # IP address host
        host = ".".join(str(random.randint(1, 254)) for _ in range(4))
        url = f"http://{host}/{brand}/{w1}/{rnd(6)}.php?id={rnd(10)}"
    elif kind == 1:  # brand in subdomain of junk domain
        url = f"http://{brand}.{w1}.{rnd(random.randint(6, 12))}.{tld}/{w2}/index.php"
    elif kind == 2:  # hyphenated lookalike
        url = f"https://{brand}-{w1}-{w2}.{tld}/{rnd(8)}?session={rnd(24)}"
    elif kind == 3:  # @ trick
        url = f"http://{brand}.com@{rnd(9)}.{tld}/{w1}"
    elif kind == 4:  # shortener / odd port / encoded
        url = f"http://{rnd(7)}.{tld}:{random.choice([8080, 8888, 2083])}/{w1}%2F{w2}%20{rnd(5)}"
    else:  # long deep path
        url = (f"http://secure-{brand}{random.randint(1, 999)}.{tld}/"
               f"{w1}/{w2}/{rnd(12)}/{rnd(10)}.html?token={rnd(30)}&user={rnd(6)}")
    return url


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6000, help="rows per class")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/urls.csv")
    a = ap.parse_args()
    random.seed(a.seed)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    rows = [(legit_url(), 0) for _ in range(a.n)] + [(phish_url(), 1) for _ in range(a.n)]
    random.shuffle(rows)
    pd.DataFrame(rows, columns=["url", "label"]).drop_duplicates().to_csv(a.out, index=False)
    print(f"Dataset saved: {a.out} ({len(rows)} rows requested)")


if __name__ == "__main__":
    main()
