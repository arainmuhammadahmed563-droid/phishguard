"""CLI: python predict.py <url> [<url> ...]   or   python predict.py -f urls.txt [--json] [--threshold 0.4]
Exit code is 1 if any URL is flagged as PHISHING (handy in scripts/CI)."""
import argparse
import json
import sys

from detector import DEFAULT_THRESHOLD, predict


def main():
    ap = argparse.ArgumentParser(description="Phishing URL detector")
    ap.add_argument("urls", nargs="*")
    ap.add_argument("-f", "--file", help="text file with one URL per line")
    ap.add_argument("--json", action="store_true", help="print JSON output")
    ap.add_argument("-t", "--threshold", type=float, default=DEFAULT_THRESHOLD,
                    help="phishing cut-off 0-1 (lower = stricter, default 0.5)")
    a = ap.parse_args()
    urls = list(a.urls)
    if a.file:
        with open(a.file) as fh:
            urls += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not urls:
        ap.error("give at least one URL")
    if not 0 <= a.threshold <= 1:
        ap.error("--threshold must be between 0 and 1")

    results = [predict(u, a.threshold) for u in urls]
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"[{r['label']:10}] {r['phishing_probability']*100:5.1f}%  "
                  f"({r['risk_level']})  {r['url']}")
            for reason in r["reasons"]:
                print(f"      - {reason}")
    sys.exit(int(any(r["label"] == "PHISHING" for r in results)))


if __name__ == "__main__":
    main()
