"""Web UI + JSON API.  Run: python app.py  ->  http://127.0.0.1:5000"""
import json
import os

from flask import Flask, jsonify, render_template, request, send_from_directory

import db
from detector import DEFAULT_THRESHOLD, predict

app = Flask(__name__)
MAX_URL_LEN, MAX_BATCH = 2048, 50
METRICS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "metrics.json")


def _threshold(data):
    try:
        t = float(data.get("threshold", DEFAULT_THRESHOLD))
    except (TypeError, ValueError):
        return None
    return t if 0 <= t <= 1 else None


PAGES = {"/": ("dashboard", "Dashboard"), "/scan": ("scan", "Scan URL"), "/bulk": ("bulk", "Bulk Scan"),
         "/history": ("history", "History"), "/model": ("model", "Model Insights"), "/learn": ("learn", "Learn & API")}


def _page(path):
    tpl, title = PAGES[path]
    return lambda: render_template(f"{tpl}.html", title=title, pages=PAGES, active=path)


for _p in PAGES:
    app.add_url_rule(_p, endpoint=PAGES[_p][0], view_func=_page(_p))


@app.route("/sw.js")
def service_worker():
    r = send_from_directory(app.static_folder, "sw.js", mimetype="application/javascript")
    r.headers["Service-Worker-Allowed"] = "/"
    r.headers["Cache-Control"] = "no-cache"
    return r


@app.route("/manifest.json")
def manifest():
    return send_from_directory(app.static_folder, "manifest.json", mimetype="application/manifest+json")


@app.route("/api/stats")
def api_stats():
    return jsonify(db.stats())


@app.route("/api/history")
def api_history():
    return jsonify(db.recent(200, request.args.get("label")))


@app.route("/api/history/clear", methods=["POST"])
def history_clear():
    db.clear()
    return jsonify({"ok": True})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/metrics")
def api_metrics():
    try:
        with open(METRICS_PATH) as f:
            return jsonify(json.load(f))
    except OSError:
        return jsonify({"error": "metrics not found, run train.py"}), 404


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url") or "").strip()
    t = _threshold(data)
    if not url or len(url) > MAX_URL_LEN:
        return jsonify({"error": f"Provide a URL (max {MAX_URL_LEN} chars)"}), 400
    if t is None:
        return jsonify({"error": "threshold must be a number between 0 and 1"}), 400
    r = predict(url, t)
    db.add(r)
    return jsonify(r)


@app.route("/api/batch", methods=["POST"])
def batch():
    data = request.get_json(silent=True) or {}
    urls = data.get("urls")
    t = _threshold(data)
    if not isinstance(urls, list) or not urls or len(urls) > MAX_BATCH:
        return jsonify({"error": f"'urls' must be a list of 1-{MAX_BATCH} URLs"}), 400
    if t is None:
        return jsonify({"error": "threshold must be a number between 0 and 1"}), 400
    urls = [str(u).strip() for u in urls]
    if any(not u or len(u) > MAX_URL_LEN for u in urls):
        return jsonify({"error": f"Every URL must be 1-{MAX_URL_LEN} chars"}), 400
    results = [predict(u, t) for u in urls]
    for r in results:
        db.add(r)
    return jsonify({"count": len(results),
                    "phishing": sum(r["label"] == "PHISHING" for r in results),
                    "results": results})


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)
