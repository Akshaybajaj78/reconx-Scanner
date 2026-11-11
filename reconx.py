import argparse
from typing import Optional
from urllib.parse import urlparse

from colorama import init as colorama_init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.port_scanner import scan_ports
from modules.subdomain_scanner import scan_subdomains
from modules.directory_scanner import scan_directories
from modules.header_checker import check_headers
from modules.cors_checker import check_cors
from modules.xss_tester import test_basic_xss
from modules.vulnerability_scanner import scan_vulnerabilities
from modules.tech_stack_detector import detect_tech_stack
from modules.takeover_scanner import scan_takeovers
from report_generator import generate_report


console = Console()
colorama_init(autoreset=True)


def _normalize_url(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme:
        return target
    return f"http://{target}"


def _banner():
    banner_text = "ReconX CLI\nAutomated Reconnaissance & Vulnerability Scanner"
    console.print(Panel(banner_text, title="ReconX", subtitle="Academic Use Only"))


def _print_table(title: str, items: list):
    table = Table(title=title)
    table.add_column("Result")

    if not items:
        table.add_row("None")
    else:
        for item in items:
            table.add_row(str(item))

    console.print(table)


def run_scan(
    target: str,
    wordlist_path: str,
    output_pdf: str,
    timeout: int,
    scan_type: str = "standard",
    ports: Optional[str] = None,
    enable_os: bool = False,
    enable_scripts: bool = False,
    subdomain_use_ctsh: bool = True,
    subdomain_use_dns: bool = True,
    subdomain_probe_live: bool = True,
    path_use_api_docs: bool = True,
    path_aggressive: bool = False,
    path_methods: Optional[str] = None,
    vuln_use_tls: bool = True,
    vuln_check_methods: bool = True,
    vuln_check_default_pages: bool = True,
    vuln_check_error_disclosure: bool = True,
):
    _banner()

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")

    # Normalize localhost for port-scanning reliability (matches Flask API).
    port_target = "127.0.0.1" if target in ("localhost", "127.0.0.1", "::1") else target

    with console.status("Scanning ports..."):
        port_result = scan_ports(
            port_target,
            scan_type=scan_type,
            ports=ports,
            timeout=60,
            host_timeout="60s",
            timing="T4",
            enable_os=enable_os,
            enable_scripts=enable_scripts,
            grab_banners=True,
        )

    open_ports = [f"{p['port']}/{p['protocol']}" for p in port_result["ports"]]

    host_for_sub = target if target not in ("localhost", "127.0.0.1", "::1") else "127.0.0.1"
    with console.status("Scanning subdomains..."):
        subdomain_result = scan_subdomains(
            host_for_sub,
            timeout=20,
            use_ctsh=subdomain_use_ctsh,
            use_dns_brute=subdomain_use_dns,
            dns_timeout=2.0,
            http_timeout=4.0,
            max_dns_workers=100,
            max_http_workers=50,
            probe_live=subdomain_probe_live,
        )
    subdomains = subdomain_result["subdomains"]
    subdomain_summary = subdomain_result["summary"]

    # --- Takeover scanning on discovered subdomains --------------------- #
    with console.status("Checking for subdomain takeovers..."):
        takeover_result = scan_takeovers(
            [s["subdomain"] for s in subdomains] if subdomains else [],
            timeout=8.0,
        )
    takeovers = takeover_result["takeovers"]
    takeover_summary = takeover_result["summary"]

    base_url = _normalize_url(target)

    # Parse path methods
    parsed_path_methods = None
    if path_methods:
        parsed_path_methods = [m.strip().upper() for m in path_methods.split(",") if m.strip()]

    with console.status("Scanning directories & API endpoints..."):
        path_result = scan_directories(
            base_url,
            wordlist_path=wordlist_path,
            timeout=8.0,
            methods=parsed_path_methods,
            max_workers=60,
            aggressive=path_aggressive,
            probe_api_docs=path_use_api_docs,
        )
    discovered_paths = path_result["paths"]
    api_endpoints = path_result["api_endpoints"]
    api_docs = path_result["api_docs"]
    path_summary = path_result["summary"]

    with console.status("Running comprehensive vulnerability checks..."):
        vuln_result = scan_vulnerabilities(
            base_url,
            timeout=8.0,
        )
    vulnerabilities = vuln_result["vulnerabilities"]
    vuln_summary = vuln_result["summary"]

    missing_headers = check_headers(base_url, timeout=timeout)
    cors_issues = check_cors(base_url, timeout=timeout)
    xss_reflected, test_url = test_basic_xss(base_url, timeout=timeout)

    with console.status("Detecting technology stack..."):
        tech_result = detect_tech_stack(base_url, timeout=8.0)
    tech_stack = tech_result["technologies"]
    tech_by_category = tech_result["by_category"]
    tech_summary = tech_result["summary"]

    # Passive/indicative list only (no active exploitation)
    possible_attacks = [
        "SQL Injection (manual/authorized testing only)",
        "OS Command Injection (manual/authorized testing only)",
        "Broken Authentication (requires credential testing)",
        "Brute Force (active attack, not performed)",
        "Advanced XSS payloads (not performed)",
        "CORS Misconfiguration (checked above)",
        "Denial of Service (active attack, not performed)",
        "Man-in-the-Middle (requires network position, not performed)",
        "JWT Token Security (requires token analysis, not performed)",
    ]

    console.print("\n[bold green]Scan Results[/bold green]")

    # Detailed port table
    port_table = Table(title="Open Ports")
    port_table.add_column("Port", style="cyan")
    port_table.add_column("Proto", style="magenta")
    port_table.add_column("Service", style="green")
    port_table.add_column("Product / Version", style="yellow")
    port_table.add_column("Banner", style="white")
    if port_result["ports"]:
        for p in port_result["ports"]:
            pv = f"{p['product']} {p['version']} {p['extrainfo']}".strip() or "—"
            banner = (p["banner"] or "—")[:60]
            port_table.add_row(str(p["port"]), p["protocol"], p["service"], pv, banner)
    else:
        port_table.add_row("—", "—", "—", "—", "—")
    console.print(port_table)

    if port_result["os"]:
        os_table = Table(title="OS Fingerprint Matches")
        os_table.add_column("Name", style="cyan")
        os_table.add_column("Accuracy", style="magenta")
        for om in port_result["os"]:
            os_table.add_row(om["name"], str(om["accuracy"]))
        console.print(os_table)

    # Subdomain table
    sub_table = Table(title="Discovered Subdomains")
    sub_table.add_column("Subdomain", style="cyan")
    sub_table.add_column("IP", style="magenta")
    sub_table.add_column("Type", style="green")
    sub_table.add_column("Method", style="yellow")
    sub_table.add_column("Status", style="white")
    sub_table.add_column("Title", style="white")
    if subdomains:
        for s in subdomains:
            sub_table.add_row(
                s["subdomain"],
                s.get("ip", "") or "—",
                s.get("record_type", "") or "—",
                s.get("method", "") or "—",
                str(s.get("status_code") or "—"),
                (s.get("title") or "")[:50],
            )
    else:
        sub_table.add_row("—", "—", "—", "—", "—", "—")
    console.print(sub_table)
    console.print(
        f"[bold blue]Subdomain summary:[/bold blue] {subdomain_summary.get('total', 0)} found "
        f"({', '.join(f'{k}={v}' for k, v in subdomain_summary.get('methods', {}).items()) or 'none'})"
    )

    # Paths / API endpoints table
    path_table = Table(title="Discovered Paths & API Endpoints")
    path_table.add_column("Method", style="cyan")
    path_table.add_column("Path", style="green")
    path_table.add_column("Status", style="magenta")
    path_table.add_column("Content-Type", style="yellow")
    path_table.add_column("Size", style="white")
    path_table.add_column("Type", style="white")
    if discovered_paths:
        for p in discovered_paths:
            ptype = []
            if p["is_api_doc"]:
                ptype.append("API-DOC")
            if p["is_api"]:
                ptype.append("API")
            ptype_str = "/".join(ptype) if ptype else "—"
            path_table.add_row(
                p["method"],
                p["path"],
                str(p["status_code"]),
                p.get("content_type", "") or "—",
                p.get("content_length", "") or "—",
                ptype_str,
            )
    else:
        path_table.add_row("—", "—", "—", "—", "—", "—")
    console.print(path_table)

    console.print(
        f"[bold blue]Path summary:[/bold blue] {path_summary.get('total', 0)} found "
        f"({path_summary.get('api_count', 0)} API endpoints, "
        f"{path_summary.get('docs_count', 0)} API docs) "
        f"methods={','.join(path_summary.get('methods_used', []))}"
    )

    if api_docs:
        doc_table = Table(title="API Documentation Endpoints")
        doc_table.add_column("Method", style="cyan")
        doc_table.add_column("Path", style="green")
        doc_table.add_column("Status", style="magenta")
        for d in api_docs[:20]:
            doc_table.add_row(d["method"], d["path"], str(d["status_code"]))
        console.print(doc_table)

    # Vulnerabilities table
    vuln_table = Table(title="Vulnerability Findings")
    vuln_table.add_column("Severity", style="red")
    vuln_table.add_column("Title", style="cyan")
    vuln_table.add_column("Category", style="green")
    vuln_table.add_column("Evidence", style="white")
    if vulnerabilities:
        for v in vulnerabilities:
            sev = v.get("severity", "info")
            sev_style = {
                "high": "bold red",
                "medium": "bold orange3",
                "low": "bold yellow",
                "info": "bold blue",
            }.get(sev, "white")
            vuln_table.add_row(
                f"[{sev.upper()}]",
                v.get("title", "—")[:60],
                v.get("category", "General")[:30],
                (v.get("evidence", "") or "—")[:50],
            )
    else:
        vuln_table.add_row("[none]", "—", "—", "—")
    console.print(vuln_table)

    console.print(
        f"[bold blue]Vuln summary:[/bold blue] {vuln_summary.get('total', 0)} found "
        f"(high={vuln_summary.get('by_severity',{}).get('high',0)}, "
        f"medium={vuln_summary.get('by_severity',{}).get('medium',0)}, "
        f"low={vuln_summary.get('by_severity',{}).get('low',0)}, "
        f"info={vuln_summary.get('by_severity',{}).get('info',0)})"
    )

    # Takeover table
    takeover_table = Table(title="Subdomain Takeover Findings")
    takeover_table.add_column("Subdomain", style="cyan")
    takeover_table.add_column("Service", style="green")
    takeover_table.add_column("CNAME Target", style="magenta")
    takeover_table.add_column("Evidence", style="white")
    if takeovers:
        for t in takeovers:
            takeover_table.add_row(
                t.get("subdomain", "—"),
                t.get("service", "—"),
                t.get("cname_target", "—"),
                t.get("evidence", "—")[:50],
            )
    else:
        takeover_table.add_row("—", "—", "—", "—")
    console.print(takeover_table)

    console.print(
        f"[bold blue]Takeover summary:[/bold blue] {takeover_summary.get('total', 0)} found "
        f"({', '.join(f'{k}={v}' for k, v in takeover_summary.get('by_service', {}).items()) or 'none'})"
    )

    # Technology stack table
    tech_table = Table(title="Technology Stack")
    tech_table.add_column("Technology", style="cyan")
    tech_table.add_column("Category", style="green")
    tech_table.add_column("Confidence", style="magenta")
    tech_table.add_column("Description", style="white")
    if tech_stack:
        for t in tech_stack:
            tech_table.add_row(
                t.get("name", "—"),
                t.get("category", "—"),
                t.get("confidence", "—"),
                t.get("description", "—")[:70],
            )
    else:
        tech_table.add_row("—", "—", "—", "—")
    console.print(tech_table)

    console.print(
        f"[bold blue]Tech summary:[/bold blue] {tech_summary.get('total', 0)} technologies detected "
        f"({tech_summary.get('categories', 0)} categories)"
    )

    _print_table("Potential Attack Areas (Not Tested)", possible_attacks)

    # Build human-readable path lines for the PDF report.
    path_report_lines = [
        f"{p['method']} {p['path']} ({p['status_code']}) {p.get('content_type','')} {'[API]' if p['is_api'] else ''}{'[DOC]' if p['is_api_doc'] else ''}"
        for p in discovered_paths
    ]
    # Build human-readable subdomain lines for the PDF report.
    subdomain_report_lines = [
        f"{s['subdomain']} ({s.get('ip','')}) [{s.get('method','')}] status={s.get('status_code','-')} title={s.get('title','')}"
        for s in subdomains
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
        output_path=output_pdf,
        target=target,
        open_ports=open_ports,
        vulnerabilities=vuln_report_lines,
        discovered_paths=path_report_lines,
        subdomains=subdomain_report_lines,
        tech_stack=tech_report_lines,
        takeovers=takeover_report_lines,
        possible_attacks=possible_attacks,
    )

    console.print(f"\n[bold yellow]Report saved to:[/bold yellow] {output_pdf}")


def main():
    parser = argparse.ArgumentParser(description="ReconX CLI - Automated Reconnaissance Scanner")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument(
        "--wordlist",
        default="wordlist.txt",
        help="Path to directory wordlist (default: wordlist.txt)",
    )
    parser.add_argument(
        "--report",
        default="reconx_report.pdf",
        help="Output PDF report (default: reconx_report.pdf)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="HTTP request timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--scan-type",
        default="standard",
        choices=["quick", "standard", "comprehensive", "udp", "custom"],
        help="Port scan type (default: standard)",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated ports for --scan-type custom (e.g. 22,80,443,8080)",
    )
    parser.add_argument(
        "--os",
        action="store_true",
        default=False,
        help="Enable OS fingerprinting (may require root)",
    )
    parser.add_argument(
        "--scripts",
        action="store_true",
        default=False,
        help="Run nmap NSE scripts (banner, vuln, safe)",
    )
    parser.add_argument(
        "--no-ctsh",
        action="store_true",
        default=False,
        help="Disable Certificate Transparency (crt.sh) subdomain lookup",
    )
    parser.add_argument(
        "--no-dns-brute",
        action="store_true",
        default=False,
        help="Disable DNS brute-force subdomain discovery",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        default=False,
        help="Disable HTTP/HTTPS liveness probing of discovered subdomains",
    )
    parser.add_argument(
        "--no-api-docs",
        action="store_true",
        default=False,
        help="Disable API documentation endpoint probing",
    )
    parser.add_argument(
        "--path-aggressive",
        action="store_true",
        default=False,
        help="Enable aggressive path scanning (includes POST method)",
    )
    parser.add_argument(
        "--path-methods",
        default=None,
        help="Comma-separated HTTP methods for path scanning (e.g. GET,HEAD,OPTIONS,POST)",
    )
    parser.add_argument(
        "--no-tls",
        action="store_true",
        default=False,
        help="Disable TLS/SSL vulnerability checks",
    )
    parser.add_argument(
        "--no-http-methods",
        action="store_true",
        default=False,
        help="Disable dangerous HTTP method checks",
    )
    parser.add_argument(
        "--no-default-pages",
        action="store_true",
        default=False,
        help="Disable default/admin page checks",
    )
    parser.add_argument(
        "--no-error-disclosure",
        action="store_true",
        default=False,
        help="Disable error message disclosure checks",
    )

    args = parser.parse_args()
    run_scan(
        args.target,
        args.wordlist,
        args.report,
        args.timeout,
        scan_type=args.scan_type,
        ports=args.ports,
        enable_os=args.os,
        enable_scripts=args.scripts,
        subdomain_use_ctsh=not args.no_ctsh,
        subdomain_use_dns=not args.no_dns_brute,
        subdomain_probe_live=not args.no_probe,
        path_use_api_docs=not args.no_api_docs,
        path_aggressive=args.path_aggressive,
        path_methods=args.path_methods,
        vuln_use_tls=not args.no_tls,
        vuln_check_methods=not args.no_http_methods,
        vuln_check_default_pages=not args.no_default_pages,
        vuln_check_error_disclosure=not args.no_error_disclosure,
    )


if __name__ == "__main__":
    main()
