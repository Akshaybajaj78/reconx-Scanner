import argparse
from urllib.parse import urlparse

from colorama import init as colorama_init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.port_scanner import scan_top_ports
from modules.subdomain_scanner import scan_subdomains
from modules.directory_scanner import scan_directories
from modules.header_checker import check_headers
from modules.cors_checker import check_cors
from modules.xss_tester import test_basic_xss
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


def run_scan(target: str, wordlist_path: str, output_pdf: str, timeout: int):
    _banner()

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")

    with console.status("Scanning ports..."):
        open_ports = scan_top_ports(target)

    with console.status("Scanning subdomains..."):
        subdomains = scan_subdomains(target, timeout=timeout)

    base_url = _normalize_url(target)

    with console.status("Scanning directories..."):
        discovered_paths = scan_directories(base_url, wordlist_path, timeout=timeout)

    with console.status("Checking security headers..."):
        missing_headers = check_headers(base_url, timeout=timeout)

    with console.status("Checking CORS configuration..."):
        cors_issues = check_cors(base_url, timeout=timeout)

    with console.status("Testing for basic XSS..."):
        xss_reflected, test_url = test_basic_xss(base_url, timeout=timeout)

    vulnerabilities = []
    if missing_headers:
        vulnerabilities.append("Missing Security Headers: " + ", ".join(missing_headers))
    if cors_issues:
        vulnerabilities.extend(cors_issues)
    if xss_reflected:
        vulnerabilities.append(f"Potential XSS reflection at {test_url}")

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
    _print_table("Open Ports", open_ports)
    _print_table("Subdomains", subdomains)
    _print_table("Discovered Paths", discovered_paths)
    _print_table("Vulnerabilities", vulnerabilities)
    _print_table("Potential Attack Areas (Not Tested)", possible_attacks)

    generate_report(
        output_path=output_pdf,
        target=target,
        open_ports=open_ports,
        vulnerabilities=vulnerabilities,
        discovered_paths=discovered_paths,
        subdomains=subdomains,
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

    args = parser.parse_args()
    run_scan(args.target, args.wordlist, args.report, args.timeout)


if __name__ == "__main__":
    main()
