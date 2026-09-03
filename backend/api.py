#!/usr/bin/env python3
"""
api.py
------
Flask backend for the Malware Static Analysis Workbench.

STATIC ANALYSIS ONLY: this server never executes an uploaded file, never
runs any string/command extracted from a sample, and never contacts any
URL/IP/domain extracted from a sample. Uploaded files are analyzed once
and then deleted -- they are never served back out or executed.

Run:
    cd backend
    python api.py
Then open http://127.0.0.1:5000 in a browser (or the phone's own browser
if running under Termux).
"""

import os
import io
import uuid
import time

from flask import Flask, request, jsonify, send_from_directory, Response, abort
from werkzeug.utils import secure_filename

import malware
import database
from report import build_html_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
UPLOAD_DIR = os.path.join(PROJECT_ROOT, "uploads")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB -- generous for a mini-project, bounded for safety

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

database.init_db()


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def frontend_assets(filename):
    # Only ever serve the known static asset names -- never an arbitrary
    # path, and never anything from uploads/ or samples/.
    allowed = {"style.css", "app.js"}
    if filename not in allowed:
        abort(404)
    return send_from_directory(FRONTEND_DIR, filename)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _safe_upload_path(original_filename: str) -> str:
    """Builds a collision-safe, path-traversal-safe destination path
    inside UPLOAD_DIR for an incoming upload."""
    safe_name = secure_filename(original_filename) or "upload.bin"
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    dest = os.path.join(UPLOAD_DIR, unique_name)
    # Defense in depth: confirm the resolved path is still inside UPLOAD_DIR.
    if os.path.commonpath([os.path.abspath(dest), os.path.abspath(UPLOAD_DIR)]) != os.path.abspath(UPLOAD_DIR):
        raise ValueError("unsafe upload path")
    return dest


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "file" not in request.files:
        return jsonify({"error": "no file provided (expected multipart field 'file')"}), 400

    upload = request.files["file"]
    if upload.filename == "":
        return jsonify({"error": "empty filename"}), 400

    try:
        dest_path = _safe_upload_path(upload.filename)
        upload.save(dest_path)
    except Exception as e:
        return jsonify({"error": f"could not save upload: {e}"}), 400

    try:
        # The original (user-supplied) filename is preserved in the result
        # for display purposes even though the file is stored under a
        # randomized name on disk.
        result = malware.analyze_file(dest_path, quiet=True)
        result["file"]["name"] = secure_filename(upload.filename) or result["file"]["name"]
    except Exception as e:
        # The engine itself already catches expected failure modes; this
        # is a last-resort guard so the server never 500s on a weird file.
        return jsonify({"error": f"analysis failed unexpectedly: {e}"}), 500
    finally:
        # Never retain uploaded executables on disk longer than needed
        # for analysis.
        try:
            os.remove(dest_path)
        except OSError:
            pass

    history_id = None
    try:
        history_id = database.save_analysis(result)
    except Exception:
        pass  # history is a convenience feature; don't fail the request over it

    result["history_id"] = history_id
    return jsonify(result)


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------
@app.route("/api/history", methods=["GET"])
def api_history():
    limit = request.args.get("limit", default=20, type=int)
    limit = max(1, min(limit, 100))
    return jsonify(database.get_recent(limit=limit))


@app.route("/api/history/<int:analysis_id>", methods=["GET"])
def api_history_detail(analysis_id):
    record = database.get_by_id(analysis_id)
    if record is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(record)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
@app.route("/api/report/<int:analysis_id>", methods=["GET"])
def api_report(analysis_id):
    record = database.get_by_id(analysis_id)
    if record is None:
        return jsonify({"error": "not found"}), 404

    html_report = build_html_report(record["result"])

    # Save a copy under reports/ for the "generate report" audit trail
    report_filename = f"report_{analysis_id}_{int(time.time())}.html"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_report)
    except OSError:
        pass

    return Response(
        html_report,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="{report_filename}"'},
    )


# ---------------------------------------------------------------------------
# Error handlers -- keep the server from ever crashing on bad input
# ---------------------------------------------------------------------------
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"file too large (limit is {MAX_UPLOAD_BYTES // (1024*1024)} MB)"}), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404


def _open_browser(url, delay=1.2):
    """Opens the dashboard in the default browser shortly after the server
    starts listening. Tries termux-open-url first (works reliably inside
    Termux, where the plain webbrowser module often can't reach a real
    browser), then falls back to the standard library's webbrowser module
    on desktop/normal environments. Never raises -- worst case, the user
    just opens the printed URL manually.
    """
    import time
    time.sleep(delay)

    is_termux = "com.termux" in os.environ.get("PREFIX", "")
    if is_termux:
        try:
            if os.system(f"termux-open-url '{url}' >/dev/null 2>&1") == 0:
                return
        except Exception:
            pass

    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass  # URL is already printed to the console either way


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    import threading

    BIND_HOST = "0.0.0.0"    # listen on all interfaces (e.g. reachable from another device on the same network)
    OPEN_HOST = "127.0.0.1"  # always open the browser against localhost
    PORT = 5000
    url = f"http://{OPEN_HOST}:{PORT}"

    print("=" * 60)
    print("  Malware Static Analysis Workbench")
    print("  STATIC ANALYSIS ONLY -- no sample is ever executed")
    print("=" * 60)
    print(f"  Dashboard: {url}")
    print("  Press CTRL+C to stop the server")
    print("=" * 60)

    threading.Thread(target=_open_browser, args=(url,), daemon=True).start()

    app.run(host=BIND_HOST, port=PORT, debug=False)
