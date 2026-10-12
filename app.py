from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner import scan as run_scan
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

app = Flask(__name__, static_folder="frontend", static_url_path="")
CORS(app)


@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "app": "SiteAudit & SiteSentinel Unified Auditor"})


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = (data or {}).get("url", "").strip()

    if not url:
        return jsonify({"error": "Please provide a valid website URL"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = run_scan(url)
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
