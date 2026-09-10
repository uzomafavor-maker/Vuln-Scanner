"""
app.py — Flask backend for the vulnerability assessment tool.

The browser never sees the VirusTotal API key. Every scan goes:

    Bootstrap page  ->  this Flask app  ->  VirusTotal API v3

Run locally:   python app.py
Run in prod:   gunicorn app:app
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request

# Load a local .env file if one exists, so the key can live in a file instead of
# being exported by hand every time. Real environment variables always win, which
# is what lets Render/Railway/Docker override it in production.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv not installed — env vars still work
    pass

import store
from vt_client import (
    MAX_UPLOAD_BYTES,
    SCHEME_RE,
    VirusTotalClient,
    VTError,
    normalize,
    sha256_of,
    valid_domain,
    valid_hash,
    valid_ip,
    valid_url,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + (1024 * 1024)
app.config["JSON_SORT_KEYS"] = False

vt = VirusTotalClient()
store.init_db()


def _startup_key_check() -> None:
    """Explain a missing key in the terminal, including the common .env.example mix-up."""
    if vt.configured:
        return
    print("\n" + "=" * 68)
    print("  NO API KEY LOADED — scanning is disabled.")

    example = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env.example")
    dotenv = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    key_in_example = False
    if os.path.exists(example):
        try:
            with open(example, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip().startswith("VT_API_KEY="):
                        value = line.split("=", 1)[1].strip().strip("\"'")
                        key_in_example = len(value) > 20 and "paste" not in value.lower()
        except OSError:
            pass

    if key_in_example and not os.path.exists(dotenv):
        print("\n  Your key appears to be in .env.example — the app reads .env.")
        print("  Fix:    cp .env.example .env        (Windows: copy .env.example .env)")
        print("  Then:   put the placeholder back in .env.example, because that file")
        print("          IS committed to git and .env is not.")
    elif not os.path.exists(dotenv):
        print("\n  No .env file found. Create one:")
        print("    cp .env.example .env             (Windows: copy .env.example .env)")
        print("  then paste your key on the VT_API_KEY= line and restart.")
    else:
        print("\n  A .env file exists but no VT_API_KEY was read from it.")
        print("  Check for:  a missing or misspelled VT_API_KEY= line;")
        print("              the line still commented out with a leading '#';")
        print("              the file saved as .env.txt (Windows hides extensions).")
    print("=" * 68 + "\n")


_startup_key_check()

# Per-visitor throttle. The VirusTotal quota is shared by everyone using this
# deployment, so one impatient tab must not be able to drain it.
_VISITOR_LIMIT = int(os.environ.get("VISITOR_LIMIT_PER_WINDOW", 20))
_VISITOR_WINDOW = int(os.environ.get("VISITOR_WINDOW_SECONDS", 300))
_visitors: dict[str, deque] = defaultdict(deque)
_visitor_lock = threading.Lock()


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return (forwarded.split(",")[0].strip() if forwarded else request.remote_addr) or "?"


def _throttle_visitor() -> None:
    ip = _client_ip()
    now = time.time()
    with _visitor_lock:
        hits = _visitors[ip]
        while hits and now - hits[0] > _VISITOR_WINDOW:
            hits.popleft()
        if len(hits) >= _VISITOR_LIMIT:
            raise VTError(
                f"You have made {_VISITOR_LIMIT} requests in the last "
                f"{_VISITOR_WINDOW // 60} minutes. Please slow down.",
                status=429,
                retry_after=int(_VISITOR_WINDOW - (now - hits[0])),
            )
        hits.append(now)


def _fail(exc: VTError):
    body = {"ok": False, "error": exc.message}
    if exc.retry_after:
        body["retry_after"] = exc.retry_after
    return jsonify(body), exc.status


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------


@app.get("/")
def index():
    # `configured` is a boolean. The key itself is deliberately not passed in.
    return render_template("index.html", configured=vt.configured)


@app.get("/health")
def health():
    return jsonify({"ok": True, "key_configured": vt.configured, "version": "1.0.0"})


# --------------------------------------------------------------------------
# Lookups: IP, domain, file hash — all read-only, all cacheable
# --------------------------------------------------------------------------


@app.post("/api/lookup")
def api_lookup():
    body = request.get_json(silent=True) or {}
    kind = str(body.get("kind", "")).strip().lower()
    value = str(body.get("value", "")).strip()

    validators = {
        "ip": (valid_ip, "That is not a valid IPv4 or IPv6 address."),
        "domain": (valid_domain, "That is not a valid domain name (try example.com)."),
        "hash": (valid_hash, "A file hash must be 32, 40 or 64 hexadecimal characters."),
    }
    if kind not in validators:
        return jsonify({"ok": False, "error": "Unknown lookup type."}), 400
    check, message = validators[kind]
    if not value or not check(value):
        return jsonify({"ok": False, "error": message}), 400

    if kind == "hash":
        value = value.lower()
    cache_key = f"{kind}:{value.lower()}"
    cached = store.cache_get(cache_key)
    if cached:
        return jsonify(cached)

    try:
        _throttle_visitor()
        if kind == "ip":
            payload = vt.get_ip_report(value)
        elif kind == "domain":
            payload = vt.get_domain_report(value)
        else:
            payload = vt.get_file_report(value)
    except VTError as exc:
        return _fail(exc)

    if payload is None:
        noun = {"ip": "IP address", "domain": "domain", "hash": "file hash"}[kind]
        return jsonify({
            "ok": False,
            "error": f"VirusTotal has no record for that {noun}.",
            "not_found": True,
        }), 404

    report = normalize("file" if kind == "hash" else kind, value, payload)
    store.cache_put(cache_key, report)
    store.history_add(report)
    return jsonify(report)


# --------------------------------------------------------------------------
# URL scanning
# --------------------------------------------------------------------------


@app.post("/api/scan/url")
def api_scan_url():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()
    rescan = bool(body.get("rescan"))

    # Convenience: "example.com" -> "http://example.com". But only when there is
    # no scheme at all, so "javascript:..." is never smuggled through as a host.
    if url and not SCHEME_RE.match(url):
        url = "http://" + url
    if not valid_url(url):
        return jsonify({
            "ok": False,
            "error": "Enter a valid http:// or https:// URL.",
        }), 400

    cache_key = f"url:{url}"
    if not rescan:
        cached = store.cache_get(cache_key)
        if cached:
            return jsonify(cached)

    try:
        _throttle_visitor()
        if not rescan:
            # Cheapest path: VirusTotal usually already holds a report.
            payload = vt.get_url_report(url)
            if payload is not None:
                report = normalize("url", url, payload)
                store.cache_put(cache_key, report)
                store.history_add(report)
                return jsonify(report)
        # Nothing on file, or the user asked for a fresh scan.
        analysis_id = vt.submit_url(url)
    except VTError as exc:
        return _fail(exc)

    return jsonify({
        "ok": True,
        "queued": True,
        "analysis_id": analysis_id,
        "kind": "url",
        "target": url,
        "message": "Submitted to VirusTotal. Waiting for the engines to report back.",
    })


# --------------------------------------------------------------------------
# File scanning
# --------------------------------------------------------------------------


@app.post("/api/scan/file")
def api_scan_file():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"ok": False, "error": "No file was attached."}), 400

    content = upload.read()
    if not content:
        return jsonify({"ok": False, "error": "That file is empty."}), 400
    if len(content) > MAX_UPLOAD_BYTES:
        return jsonify({
            "ok": False,
            "error": "That file is larger than 32 MB, the direct-upload limit.",
        }), 413

    digest = sha256_of(content)
    cache_key = f"file:{digest}"
    cached = store.cache_get(cache_key)
    if cached:
        return jsonify(cached)

    try:
        _throttle_visitor()
        # Hash first: if VirusTotal has already analysed this exact file we get
        # the full report for one request instead of an upload plus polling.
        payload = vt.get_file_report(digest)
        if payload is not None:
            report = normalize("file", digest, payload)
            report["meta"]["submitted_name"] = upload.filename
            store.cache_put(cache_key, report)
            store.history_add(report)
            return jsonify(report)
        analysis_id = vt.submit_file(upload.filename, content)
    except VTError as exc:
        return _fail(exc)

    return jsonify({
        "ok": True,
        "queued": True,
        "analysis_id": analysis_id,
        "kind": "file",
        "target": digest,
        "filename": upload.filename,
        "message": "Uploaded to VirusTotal. Analysis usually takes under a minute.",
    })


# --------------------------------------------------------------------------
# Polling an in-flight analysis
# --------------------------------------------------------------------------


@app.get("/api/analysis/<analysis_id>")
def api_analysis(analysis_id: str):
    kind = request.args.get("kind", "url")
    target = request.args.get("target", "")
    if kind not in ("url", "file"):
        kind = "url"
    try:
        _throttle_visitor()
        payload = vt.get_analysis(analysis_id)
    except VTError as exc:
        return _fail(exc)

    if payload is None:
        return jsonify({"ok": False, "error": "That analysis id is unknown."}), 404

    attrs = (payload.get("data") or {}).get("attributes", {}) or {}
    status = attrs.get("status", "queued")
    if status != "completed":
        return jsonify({
            "ok": True,
            "queued": True,
            "analysis_id": analysis_id,
            "status": status,
            "message": "VirusTotal is still running the engines.",
        })

    # A completed analysis object also tells us what it was run against.
    meta_item = (payload.get("meta") or {}).get(
        "url_info" if kind == "url" else "file_info", {}
    ) or {}
    resolved = target or meta_item.get("url") or meta_item.get("sha256") or analysis_id

    report = normalize(kind, resolved, payload)
    store.cache_put(f"{kind}:{resolved}", report)
    store.history_add(report)
    return jsonify(report)


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------


@app.get("/api/history")
def api_history():
    return jsonify({"ok": True, "items": store.history_list(limit=50)})


@app.get("/api/history/<int:item_id>")
def api_history_item(item_id: int):
    report = store.history_get(item_id)
    if not report:
        return jsonify({"ok": False, "error": "No such history entry."}), 404
    report["from_history"] = True
    return jsonify(report)


# --------------------------------------------------------------------------
# Error handlers — always JSON for /api, so the frontend never parses HTML
# --------------------------------------------------------------------------


@app.errorhandler(413)
def _too_large(_):
    return jsonify({"ok": False, "error": "That upload exceeds the 32 MB limit."}), 413


@app.errorhandler(404)
def _not_found(err):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Unknown endpoint."}), 404
    return render_template("index.html", configured=vt.configured), 200


@app.errorhandler(500)
def _server_error(_):
    return jsonify({"ok": False, "error": "Unexpected server error."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
