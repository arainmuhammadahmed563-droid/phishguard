"""Tiny SQLite log of scans (used by Dashboard / History pages)."""
import os, sqlite3, time

PATH = os.environ.get("PHISH_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scans.db"))


def _c():
    c = sqlite3.connect(PATH)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, ts REAL, url TEXT, label TEXT, prob REAL, risk TEXT)")
    return c


def add(r):
    with _c() as c:
        c.execute("INSERT INTO scans(ts,url,label,prob,risk) VALUES(?,?,?,?,?)",
                  (time.time(), r["url"], r["label"], r["phishing_probability"], r["risk_level"]))


def recent(n=100, label=None):
    q, a = "SELECT * FROM scans", []
    if label in ("PHISHING", "LEGITIMATE"):
        q, a = q + " WHERE label=?", [label]
    with _c() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY id DESC LIMIT ?", a + [n])]


def stats():
    with _c() as c:
        t = c.execute("SELECT COUNT(*) n, SUM(label='PHISHING') p FROM scans").fetchone()
        risk = {r["risk"]: r["n"] for r in c.execute("SELECT risk, COUNT(*) n FROM scans GROUP BY risk")}
    n, p = t["n"] or 0, t["p"] or 0
    return {"total": n, "phishing": p, "legit": n - p,
            "risk": {k: risk.get(k, 0) for k in ("LOW", "MEDIUM", "HIGH")}}


def clear():
    with _c() as c:
        c.execute("DELETE FROM scans")
