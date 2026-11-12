from flask import Flask, jsonify, request, send_from_directory
from urllib.parse import urlparse, urlunparse
from modules.port_scanner import scan_ports, scan_top_ports
from modules.subdomain_scanner import scan_subdomains
from modules.directory_scanner import scan_directories
from modules.header_checker import check_headers
from modules.cors_checker import check_cors
from modules.xss_tester import test_basic_xss
from modules.vulnerability_scanner import scan_vulnerabilities
from modules.tech_stack_detector import detect_tech_stack
from modules.takeover_scanner import scan_takeovers
from modules.js_endpoint_scanner import extract_js_endpoints
from report_generator import generate_report
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
STATIC_DIR = FRONTEND_DIST

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 3600


@app.after_request
def disable_cache(response):
    if request.path == "/" or request.path.endswith(".html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/")
def index():
    if not FRONTEND_DIST.exists():
        return (
            jsonify(
                {
                    "error": "React build not found. Run: cd frontend && npm install && npm run build"
                }
            ),
            500,
        )
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
    discovered_paths = []
    missing_headers = []
    cors_issues = []
    xss_reflected = False
    test_url = target

    # --- Advanced port scanning --------------------------------------- #
    scan_type = (payload.get("scan_type") or "standard").strip()
    custom_ports = payload.get("ports")  # str "22,80,443" or list[int]
    enable_os = bool(payload.get("enable_os", False))
    enable_scripts = bool(payload.get("enable_scripts", False))

    port_target = "127.0.0.1" if host in ("localhost", "127.0.0.1", "::1") else host

    port_result = scan_ports(
        port_target,
        scan_type=scan_type,
        ports=custom_ports,
        timeout=25,
        host_timeout="25s",
        timing="T4",
        enable_os=enable_os,
        enable_scripts=enable_scripts,
        grab_banners=True,
    )

    open_ports = [f"{p['port']}/{p['protocol']}" for p in port_result["ports"]]
    open_ports_detail = port_result["ports"]
    os_matches = port_result["os"]

    # --- Advanced subdomain scanning ---------------------------------- #
    subdomain_use_ctsh = bool(payload.get("subdomain_use_ctsh", True))
    subdomain_use_dns = bool(payload.get("subdomain_use_dns", True))
    subdomain_probe_live = bool(payload.get("subdomain_probe_live", True))

    subdomain_result = {}
    if host not in ("localhost", "127.0.0.1", "::1"):
        subdomain_result = scan_subdomains(
            host,
            timeout=12,
            use_ctsh=subdomain_use_ctsh,
            use_dns_brute=subdomain_use_dns,
            dns_timeout=2.0,
            http_timeout=4.0,
            max_dns_workers=100,
            max_http_workers=50,
            probe_live=subdomain_probe_live,
        )
    subdomains = subdomain_result.get("subdomains", [])
    subdomain_summary = subdomain_result.get("summary", {})

    # --- Subdomain takeover scanning ------------------------------------ #
    takeover_result = scan_takeovers(
        [s["subdomain"] for s in subdomains] if subdomains else [],
        timeout=8.0,
    )
    takeovers = takeover_result["takeovers"]
    takeover_summary = takeover_result.get("summary", {})

    # --- Advanced directory / API endpoint scanning ------------------- #
    path_use_api_docs = bool(payload.get("path_use_api_docs", True))
    path_aggressive = bool(payload.get("path_aggressive", False))
    path_methods_raw = payload.get("path_methods")  # e.g. "GET,HEAD,OPTIONS,POST"
    path_methods = None
    if path_methods_raw:
        path_methods = [m.strip().upper() for m in str(path_methods_raw).split(",") if m.strip()]

    path_result = scan_directories(
        base_url,
        wordlist_path="wordlist.txt",
        timeout=8.0,
        methods=path_methods,
        max_workers=60,
        aggressive=path_aggressive,
        probe_api_docs=path_use_api_docs,
    )

    discovered_paths = path_result["paths"]
    api_endpoints = path_result["api_endpoints"]
    api_docs = path_result["api_docs"]
    path_scan_summary = path_result["summary"]

    # Build simple string list for legacy display
    path_strings = [
        f"{p['method']} {p['path']} ({p['status_code']}) {p.get('content_type','')}"
        for p in discovered_paths
    ]

    # --- Comprehensive vulnerability scanning -------------------------- #
    vuln_result = scan_vulnerabilities(
        base_url,
        timeout=8.0,
    )

    vulnerabilities = vuln_result["vulnerabilities"]
    vuln_summary = vuln_result["summary"]

    cors_issues = check_cors(base_url)
    missing_headers = check_headers(base_url)
    xss_reflected, test_url = test_basic_xss(base_url)

    # --- Tech stack detection ------------------------------------------- #
    tech_result = detect_tech_stack(base_url, timeout=8.0)
    tech_stack = tech_result["technologies"]
    tech_by_category = tech_result["by_category"]
    tech_summary = tech_result["summary"]

    # Build human-readable tech stack lines for the PDF report.
    tech_report_lines = [
        f"{t['name']} ({t['category']}) — {t['description']}"
        for t in tech_stack
    ]

    # --- JavaScript endpoint & secret extraction ------------------------ #
    js_result = extract_js_endpoints(base_url, timeout=8.0)
    js_scripts = js_result["scripts"]
    js_endpoints = js_result["endpoints"]
    js_secrets = js_result["secrets"]
    js_source_maps = js_result["source_maps"]
    js_summary = js_result["summary"]

    # Build human-readable JS lines for the PDF report.
    js_endpoint_report_lines = [
        f"[{ep['type']}] {ep['value']} ({ep['source']})"
        for ep in js_endpoints
    ]
    js_secret_report_lines = [
        f"[{sec['type']}] {sec['value']} ({sec['source']})"
        for sec in js_secrets
    ]
    js_sourcemap_report_lines = [
        f"[SOURCE-MAP] {sm['url']} (from {sm['source']})"
        for sm in js_source_maps
    ]

    # Generate a fresh report on every scan
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_name = f"reconx_report_{timestamp}.pdf"
    # Build human-readable detail lines for the PDF report.
    port_detail_lines = [
        f"{p['port']}/{p['protocol']} - {p['service']} {p['product']} {p['version']} {p['extrainfo']}".strip()
        for p in open_ports_detail
    ]
    subdomain_report_lines = [
        f"{s['subdomain']} ({s.get('ip','')}) [{s.get('method','')}] status={s.get('status_code','-')} title={s.get('title','')}"
        for s in subdomains
    ]
    path_report_lines = [
        f"{p['method']} {p['path']} ({p['status_code']}) {p.get('content_type','')} {'[API]' if p['is_api'] else ''}{'[DOC]' if p['is_api_doc'] else ''}"
        for p in discovered_paths
    ]
    vuln_report_lines = [
        f"[{v.get('severity','info').upper()}] {v.get('title','')} — {v.get('description','')} [{v.get('category','General')}]"
        for v in vulnerabilities
    ]
    tech_report_lines = [
        f"{t.get('name','')} ({t.get('category','')}) — {t.get('description','')}"
        for t in tech_stack
    ]
    takeover_report_lines = [
        f"[{t.get('service','')}] {t.get('subdomain','')} -> {t.get('cname_target','')} (evidence: {t.get('evidence','')})"
        for t in takeovers
    ]
    generate_report(
        output_path=report_name,
        target=target,
        open_ports=port_detail_lines,
        vulnerabilities=vuln_report_lines,
        discovered_paths=path_report_lines,
        subdomains=subdomain_report_lines,
        tech_stack=tech_report_lines,
        takeovers=takeover_report_lines,
        js_endpoints=js_endpoint_report_lines,
        js_secrets=js_secret_report_lines,
        js_source_maps=js_sourcemap_report_lines,
        possible_attacks=[],
    )

    return jsonify(
        {
            "target": target,
            "open_ports": open_ports,
            "open_ports_detail": open_ports_detail,
            "os_matches": os_matches,
            "port_scan_summary": port_result["summary"],
            "subdomains": subdomains,
            "subdomain_summary": subdomain_summary,
            "discovered_paths": discovered_paths,
            "api_endpoints": api_endpoints,
            "api_docs": api_docs,
            "path_scan_summary": path_scan_summary,
            "vulnerabilities": vulnerabilities,
            "vuln_summary": vuln_summary,
            "tech_stack": tech_stack,
            "tech_by_category": tech_by_category,
            "tech_summary": tech_summary,
            "js_scripts": js_scripts,
            "js_endpoints": js_endpoints,
            "js_secrets": js_secrets,
            "js_source_maps": js_source_maps,
            "js_summary": js_summary,
            "takeovers": takeovers,
            "takeover_summary": takeover_summary,
            "cors_issues": cors_issues,
            "missing_headers": missing_headers,
            "xss_reflected": xss_reflected,
            "xss_test_url": test_url,
            "report": f"/reports/{report_name}",
        }
    )


@app.post("/api/takeover")
def api_takeover():
    """Scan a list of subdomains for takeover vulnerabilities."""
    payload = request.get_json(silent=True) or {}
    subdomains = payload.get("subdomains", [])
    if not subdomains or not isinstance(subdomains, list):
        return jsonify({"error": "subdomains list is required"}), 400

    timeout = float(payload.get("timeout", 5.0))
    result = scan_takeovers(subdomains, timeout=timeout)

    return jsonify(
        {
            "targets_scanned": result["targets_scanned"],
            "takeovers": result["takeovers"],
            "summary": result["summary"],
        }
    )


@app.post("/api/js-endpoints")
def api_js_endpoints():
    """Extract JavaScript endpoints and secrets from a target."""
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    parsed = urlparse(target if "://" in target else f"http://{target}")
    base_url = f"{parsed.scheme or 'http'}://{parsed.hostname}"
    port = f":{parsed.port}" if parsed.port else ""
    base_url = f"{base_url}{port}"

    timeout = float(payload.get("timeout", 8.0))
    result = extract_js_endpoints(base_url, timeout=timeout)

    return jsonify(
        {
            "target": result["target"],
            "scripts": result["scripts"],
            "endpoints": result["endpoints"],
            "secrets": result["secrets"],
            "source_maps": result["source_maps"],
            "summary": result["summary"],
        }
    )


@app.get("/reports/<path:filename>")
def report_files(filename):
    return send_from_directory(".", filename)


@app.get("/assets/<path:filename>")
def assets_files(filename):
    return send_from_directory(str(FRONTEND_DIST / "assets"), filename)


@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(str(STATIC_DIR), filename)


if __name__ == "__main__":
    app.run(debug=True, port=5001)
