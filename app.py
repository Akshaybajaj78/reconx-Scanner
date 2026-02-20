from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from urllib.parse import urlparse, urlunparse
from modules.port_scanner import scan_top_ports
from modules.subdomain_scanner import scan_subdomains
from modules.directory_scanner import scan_directories
from modules.header_checker import check_headers
from modules.cors_checker import check_cors
from modules.xss_tester import test_basic_xss
from report_generator import generate_report
import time
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
LEGACY_WEB = BASE_DIR / "web"
STATIC_DIR = FRONTEND_DIST if FRONTEND_DIST.exists() else LEGACY_WEB

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 3600
allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "*")
origins = [o.strip() for o in allowed_origins.split(",")] if allowed_origins != "*" else "*"
CORS(app, resources={r"/api/*": {"origins": origins}, r"/reports/*": {"origins": origins}})


@app.after_request
def disable_cache(response):
    if request.path == "/" or request.path.endswith(".html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or ""
    scheme = parsed.scheme or "http"
    port = f":{parsed.port}" if parsed.port else ""
    base_url = urlunparse((scheme, f"{host}{port}", "", "", "", ""))

    # Core scan modules
    open_ports = []
    subdomains = []
    discovered_paths = []
    missing_headers = []
    cors_issues = []
    xss_reflected = False
    test_url = target

    # Full scan for all targets (localhost and 127.0.0.1 included)
    # Normalize localhost for port scanning reliability
    port_target = "127.0.0.1" if host in ("localhost", "127.0.0.1", "::1") else host
    open_ports = scan_top_ports(port_target)

    # Subdomains for localhost are not meaningful; skip them
    subdomains = [] if host in ("localhost", "127.0.0.1", "::1") else scan_subdomains(base_url)

    discovered_paths = scan_directories(base_url, "wordlist.txt")
    missing_headers = check_headers(base_url)
    cors_issues = check_cors(base_url)
    xss_reflected, test_url = test_basic_xss(base_url)

    vulnerabilities = []
    if missing_headers:
        vulnerabilities.append("Missing Security Headers: " + ", ".join(missing_headers))
    if cors_issues:
        vulnerabilities.extend(cors_issues)
    if xss_reflected:
        vulnerabilities.append(f"Potential XSS reflection at {test_url}")

    # Generate a fresh report on every scan
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_name = f"reconx_report_{timestamp}.pdf"
    generate_report(
        output_path=report_name,
        target=target,
        open_ports=open_ports,
        vulnerabilities=vulnerabilities,
        discovered_paths=discovered_paths,
        subdomains=subdomains,
        possible_attacks=[],
    )

    return jsonify(
        {
            "target": target,
            "open_ports": open_ports,
            "subdomains": subdomains,
            "discovered_paths": discovered_paths,
            "vulnerabilities": vulnerabilities,
            "report": f"{request.host_url.rstrip('/')}/reports/{report_name}",
        }
    )


@app.get("/reports/<path:filename>")
def report_files(filename):
    return send_from_directory(".", filename)


@app.get("/assets/<path:filename>")
def assets_files(filename):
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        return send_from_directory(str(assets_dir), filename)
    # Legacy fallback when serving from /web
    return send_from_directory(str(LEGACY_WEB / "assets"), filename)


@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(str(STATIC_DIR), filename)


if __name__ == "__main__":
    app.run(debug=True)
