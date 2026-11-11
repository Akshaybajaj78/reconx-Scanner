"""
Advanced subdomain discovery module for ReconX.

Techniques
----------
1. Certificate Transparency logs (crt.sh) — discovers real subdomains
   found in SSL/TLS certificates.  Usually the most accurate source.
2. DNS brute force — resolves a large built-in wordlist (~250 names)
   via socket.getaddrinfo (works without root or extra Python packages).
3. HTTP/HTTPS probing — verifies which discovered subdomains are live
   and captures status code, page title, and server header.

Public API
----------
scan_subdomains(target, timeout=5, use_ctsh=True, use_dns_brute=True,
                wordlist=None, dns_timeout=2.0, http_timeout=4.0,
                max_dns_workers=100, max_http_workers=50, probe_live=True)
    -> dict with rich subdomain objects.
scan_subdomains_legacy(target, timeout=5)
    -> list[str]  (backward-compatible list of live URLs)
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Sequence, Set
from urllib.parse import urlparse

import requests

# Silence InsecureRequestWarning for HTTPS probing with verify=False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

DEFAULT_SUBDOMAIN_WORDLIST: List[str] = [
    # Core infrastructure
    "www", "mail", "webmail", "ns1", "ns2", "dns", "dns1", "dns2", "dns3", "dns4",
    "ftp", "smtp", "pop", "pop3", "imap", "mx", "mx1", "mx2",
    # Development / environments
    "dev", "develop", "development", "test", "testing", "staging", "stage",
    "uat", "qa", "quality", "debug", "sandbox", "preview", "temp", "tmp",
    "dev1", "dev2", "test1", "test2", "stage1", "stage2",
    # API / application
    "api", "api-v1", "api-v2", "api-v3", "api-dev", "api-staging", "api-test",
    "api-prod", "app", "apps", "app-dev", "app-staging", "app-test", "app-prod",
    "web", "web-dev", "web-staging", "web-test", "web-prod",
    "www1", "www2", "www3", "www-dev", "www-staging", "www-test", "www-prod",
    # Admin / management
    "admin", "administrator", "root", "manager", "control", "panel", "cpanel",
    "portal", "vpn", "remote", "remote-access", "ssh", "rdp",
    "git", "gitlab", "github", "bitbucket", "svn", "jenkins", "jira",
    "confluence", "wiki", "docs", "documentation",
    # Content / media
    "blog", "news", "forum", "support", "help", "status", "monitor",
    "metrics", "health", "ping", "uptime", "cdn", "static", "media",
    "assets", "img", "images", "video", "files", "download", "upload",
    "store", "shop", "cart", "pay", "payment", "billing", "invoice",
    # Cloud / container / databases
    "k8s", "kubernetes", "docker", "registry", "prometheus", "grafana",
    "kibana", "elastic", "elasticsearch", "logstash", "redis", "mysql",
    "postgres", "mongo", "mongodb", "rabbitmq", "kafka", "zabbix",
    "nagios", "icinga", "cacti", "munin", "observium",
    "db", "database", "sql", "oracle", "mariadb", "fileserver",
    "file", "nas", "storage", "repo", "repository", "backup", "backups",
    "bak", "archive", "archived",
    # Corporate / internal
    "internal", "intranet", "extranet", "corp", "corporate", "employees",
    "staff", "user", "users", "client", "clients", "customer", "customers",
    "partner", "partners", "vendor", "vendors", "supplier", "suppliers",
    # Common single words / environments
    "alpha", "beta", "gamma", "delta", "omega", "sigma", "lambda", "zeta",
    "new", "old", "demo", "demo1", "demo2", "m", "mobile", "wap",
    "exchange", "owa", "outlook", "sharepoint", "teams", "zoom", "webinar",
    # Misc services
    "irc", "xmpp", "jabber", "voip", "sip", "rtsp", "cvs", "hg", "bzr",
    "build", "ci", "cd", "deploy", "deployment", "release",
    "monitoring", "logging", "logs", "stats", "statistics",
    "auth", "authentication", "sso", "saml", "oidc", "ldap",
    "ad", "active-directory", "radius", "tacacs",
    "ssl", "secure", "secure1", "secure2", "extranet", "partner-portal",
    "client-portal", "customer-portal",
]

CTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"

# Characters that are NOT valid in a hostname/subdomain
_INVALID_HOST_CHARS = set(" @#$%^&*()+={}[]|\\;',\"!?`~")


def _is_valid_subdomain(sub: str, domain: str) -> bool:
    """Validate that a CT.sh entry looks like a real subdomain."""
    sub = sub.strip().lower()
    if not sub:
        return False
    # Must end with the target domain (or be the domain itself)
    if sub != domain and not sub.endswith(f".{domain}"):
        return False
    # No invalid characters
    if any(ch in _INVALID_HOST_CHARS for ch in sub):
        return False
    # No '@' (email addresses in certs)
    if "@" in sub:
        return False
    # Must not start with a dot or hyphen
    if sub.startswith(".") or sub.startswith("-"):
        return False
    # Each label must be valid length
    labels = sub.split(".")
    if any(len(label) == 0 or len(label) > 63 for label in labels):
        return False
    return True

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _extract_host(target: str) -> str:
    """Pull a bare hostname/IP out of a URL, host:port, or plain string."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.netloc or target
    return host.split(":")[0].strip()


def _resolve_dns(host: str, timeout: float = 3.0) -> Optional[tuple]:
    """Resolve a hostname to IP. Returns (ip, record_type) or None."""
    try:
        infos = socket.getaddrinfo(host, None, timeout=timeout)
        for info in infos:
            family = info[0]
            addr = info[4][0]
            if family == socket.AF_INET:
                return addr, "A"
            if family == socket.AF_INET6:
                return addr, "AAAA"
        return None
    except Exception:
        return None


def _http_probe(url: str, timeout: float = 5.0) -> Optional[Dict]:
    """Probe a URL and return status code, title, server header."""
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True, verify=False
        )
        return {
            "status_code": resp.status_code,
            "title": _extract_title(resp.text) or "",
            "server": resp.headers.get("Server", "") or "",
            "final_url": resp.url,
        }
    except requests.RequestException:
        return None


def _extract_title(html: str) -> str:
    try:
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:120]
    except Exception:
        pass
    return ""


# --------------------------------------------------------------------------- #
# Technique 1: Certificate Transparency (crt.sh)
# --------------------------------------------------------------------------- #

def _fetch_ctsh(domain: str, timeout: int = 15) -> List[str]:
    """Query crt.sh for subdomains found in certificate transparency logs."""
    found: Set[str] = set()
    url = CTSH_URL.format(domain=domain)
    try:
        resp = requests.get(
            url, timeout=timeout, headers={"Accept": "application/json"}, verify=False
        )
        if resp.status_code != 200:
            return list(found)
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "") or ""
            for line in name_value.split("\n"):
                line = line.strip().lower()
                if not line:
                    continue
                if line.startswith("*."):
                    line = line[2:]
                if _is_valid_subdomain(line, domain):
                    found.add(line)
    except Exception:
        pass
    return list(found)


# --------------------------------------------------------------------------- #
# Technique 2: DNS brute force
# --------------------------------------------------------------------------- #

def _dns_brute_force(
    domain: str,
    wordlist: Sequence[str],
    timeout: float = 2.0,
    max_workers: int = 100,
) -> List[Dict]:
    """Brute force subdomains via DNS resolution (A/AAAA records)."""
    found: List[Dict] = []
    lock = threading.Lock()

    def check(sub: str) -> None:
        subdomain = f"{sub}.{domain}"
        result = _resolve_dns(subdomain, timeout=timeout)
        if result:
            ip, rtype = result
            entry = {
                "subdomain": subdomain,
                "url": f"https://{subdomain}",
                "ip": ip,
                "record_type": rtype,
                "method": "dns_brute_force",
                "status_code": None,
                "title": "",
                "server": "",
            }
            with lock:
                found.append(entry)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, sub): sub for sub in wordlist}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass

    return found


# --------------------------------------------------------------------------- #
# Technique 3: HTTP/HTTPS probing
# --------------------------------------------------------------------------- #

def _probe_subdomains(
    subdomains: List[Dict],
    timeout: float = 5.0,
    max_workers: int = 50,
) -> None:
    """Probe discovered subdomains over HTTP/HTTPS to check liveness (in-place)."""

    def probe(entry: Dict) -> None:
        subdomain = entry["subdomain"]
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            probe_result = _http_probe(url, timeout=timeout)
            if probe_result:
                entry["url"] = url
                entry["status_code"] = probe_result["status_code"]
                entry["title"] = probe_result["title"]
                entry["server"] = probe_result["server"]
                entry["scheme"] = scheme
                break

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe, e): e for e in subdomains}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Unified public API
# --------------------------------------------------------------------------- #

def scan_subdomains(
    target: str,
    timeout: int = 5,
    use_ctsh: bool = True,
    use_dns_brute: bool = True,
    wordlist: Optional[Sequence[str]] = None,
    dns_timeout: float = 2.0,
    http_timeout: float = 4.0,
    max_dns_workers: int = 100,
    max_http_workers: int = 50,
    probe_live: bool = True,
) -> Dict:
    """
    Advanced subdomain discovery.

    Parameters
    ----------
    target : str
        Domain to scan (URL, host, or bare domain).
    timeout : int
        Soft time budget (seconds) used for CRT.sh and DNS brute force.
    use_ctsh : bool
        Query crt.sh Certificate Transparency logs.
    use_dns_brute : bool
        Brute force subdomains via DNS resolution.
    wordlist : list[str] | None
        Custom wordlist (defaults to built-in ~250 subdomains).
    dns_timeout : float
        Per-DNS-query timeout.
    http_timeout : float
        Per-HTTP-probe timeout.
    max_dns_workers : int
        DNS brute-force concurrency.
    max_http_workers : int
        HTTP probing concurrency.
    probe_live : bool
        Whether to HTTP/HTTPS probe discovered subdomains.

    Returns
    -------
    dict
        {
            "target": str,
            "host": str,
            "domain": str,
            "subdomains": [ {...}, ... ],
            "summary": { "total": int, "methods": {...} },
        }
    """
    host = _extract_host(target)
    domain = host[4:] if host.startswith("www.") else host

    found: List[Dict] = []
    seen: Set[str] = set()
    methods: Dict[str, int] = {}

    def _add(entry: Dict, method: str) -> None:
        sub = entry["subdomain"].lower()
        if sub in seen:
            return
        seen.add(sub)
        entry["method"] = method
        methods[method] = methods.get(method, 0) + 1
        found.append(entry)

    # 1. Certificate Transparency
    if use_ctsh:
        try:
            ctsh_subs = _fetch_ctsh(domain, timeout=timeout)
            for sub in ctsh_subs:
                ip_result = _resolve_dns(sub, timeout=dns_timeout)
                entry = {
                    "subdomain": sub,
                    "url": f"https://{sub}",
                    "ip": ip_result[0] if ip_result else "",
                    "record_type": ip_result[1] if ip_result else "",
                    "status_code": None,
                    "title": "",
                    "server": "",
                }
                _add(entry, "ct_sh")
        except Exception:
            pass

    # 2. DNS brute force
    if use_dns_brute:
        wordlist_to_use = list(wordlist) if wordlist else list(DEFAULT_SUBDOMAIN_WORDLIST)
        try:
            dns_found = _dns_brute_force(
                domain,
                wordlist_to_use,
                timeout=dns_timeout,
                max_workers=max_dns_workers,
            )
            for entry in dns_found:
                _add(entry, "dns_brute_force")
        except Exception:
            pass

    # 3. HTTP/HTTPS probing to verify liveness
    if probe_live and found:
        to_probe = found[:300]
        _probe_subdomains(to_probe, timeout=http_timeout, max_workers=max_http_workers)

    # Sort: CT.sh results first, then DNS brute, then alphabetically
    found.sort(key=lambda e: (e["method"] != "ct_sh", e["subdomain"]))

    return {
        "target": target,
        "host": host,
        "domain": domain,
        "subdomains": found,
        "summary": {
            "total": len(found),
            "methods": methods,
        },
    }


# --------------------------------------------------------------------------- #
# Backward-compatible wrapper (legacy API returns list[str])
# --------------------------------------------------------------------------- #

def scan_subdomains_legacy(target: str, timeout: int = 5) -> List[str]:
    """Legacy helper returning a list of live subdomain URLs."""
    result = scan_subdomains(target, timeout=timeout, probe_live=True)
    urls: List[str] = []
    for entry in result["subdomains"]:
        url = entry.get("url") or f"https://{entry['subdomain']}"
        if url not in urls:
            urls.append(url)
    return urls
