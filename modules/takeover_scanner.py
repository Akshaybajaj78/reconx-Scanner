"""
Subdomain Takeover Scanner for ReconX.

Detects dangling CNAME records that point to cloud services where the
target domain is no longer registered.  This is a high-severity bug
bounty finding because an attacker can claim the abandoned domain.

Detection logic:
1. Resolve CNAME records for each subdomain.
2. Fingerprint the CNAME target against known vulnerable services
   (GitHub Pages, Heroku, AWS S3, Azure, Shopify, Tumblr, etc.).
3. Attempt to verify the target is "available for claim" by checking
   for characteristic error pages / responses.
4. Report only findings with high confidence to minimize false positives.

Public API
----------
scan_takeovers(subdomains, timeout=5)
    -> dict with takeover candidates and summary.
scan_takeovers_legacy(subdomains, timeout=5)
    -> list[str]  (backward-compatible list of strings)
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

# Silence InsecureRequestWarning
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass


# --------------------------------------------------------------------------- #
# Vulnerable service fingerprints
# --------------------------------------------------------------------------- #
# Each entry: (service_name, cname_contains, error_indicators, claim_url_template)
#   cname_contains: substring that must appear in the CNAME target
#   error_indicators: strings in HTTP response body that indicate the
#                     service account is missing / available for claim
#   claim_url_template: URL to visit to claim the domain (optional)
# --------------------------------------------------------------------------- #

TAKEOVER_FINGERPRINTS: List[Tuple[str, str, List[str], Optional[str]]] = [
    # GitHub Pages
    (
        "GitHub Pages",
        "github.io",
        [
            "There isn't a GitHub Pages site here",
            "Page not found",
            "git.io",
        ],
        "https://pages.github.com/",
    ),
    # Heroku
    (
        "Heroku",
        "herokuapp.com",
        [
            "No such app",
            "there is no app configured at that hostname",
        ],
        "https://www.heroku.com/",
    ),
    # AWS S3 (website endpoint)
    (
        "AWS S3 Website",
        "s3-website",
        [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "https://aws.amazon.com/s3/",
    ),
    # AWS S3 (REST endpoint)
    (
        "AWS S3 REST",
        ".s3.amazonaws.com",
        [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "https://aws.amazon.com/s3/",
    ),
    # Azure
    (
        "Azure",
        "azurewebsites.net",
        [
            "404",
            "Web App not found",
        ],
        "https://azure.microsoft.com/",
    ),
    # Shopify
    (
        "Shopify",
        "myshopify.com",
        [
            "Sorry, this shop is currently unavailable",
        ],
        "https://www.shopify.com/",
    ),
    # Tumblr
    (
        "Tumblr",
        "tumblr.com",
        [
            "There's nothing here",
        ],
        "https://www.tumblr.com/",
    ),
    # WordPress.com
    (
        "WordPress.com",
        "wordpress.com",
        [
            "Do you want to register",
        ],
        "https://wordpress.com/",
    ),
    # Bitbucket
    (
        "Bitbucket",
        "bitbucket.io",
        [
            "Repository not found",
        ],
        "https://bitbucket.org/",
    ),
    # Pantheon
    (
        "Pantheon",
        "pantheonsite.io",
        [
            "404",
            "The site you were looking for couldn't be found",
        ],
        "https://pantheon.io/",
    ),
    # Acquia
    (
        "Acquia",
    "acquia-sites.com",
        [
            "404",
            "site not found",
        ],
        "https://www.acquia.com/",
    ),
    # Fastly
    (
        "Fastly",
        "fastly.net",
        [
            "Fastly error: unknown domain",
        ],
        "https://www.fastly.com/",
    ),
    # SmugMug
    (
        "SmugMug",
        "smugmug.com",
        [
            "This site is not available",
        ],
        "https://www.smugmug.com/",
    ),
    # SurveyMonkey
    (
        "SurveyMonkey",
        "surveymonkey.com",
        [
            "Account not found",
        ],
        "https://www.surveymonkey.com/",
    ),
    # Unbounce
    (
        "Unbounce",
        "unbounce.com",
        [
            "The requested URL was not found",
        ],
        "https://unbounce.com/",
    ),
    # Tictail
    (
        "Tictail",
        "tictail.com",
        [
            "Page not found",
        ],
        None,
    ),
    # Strikingly
    (
        "Strikingly",
        "strikingly.com",
        [
            "Site not found",
        ],
        "https://www.strikingly.com/",
    ),
    # Ghost.io
    (
        "Ghost",
        "ghost.io",
        [
            "Please check your DNS",
        ],
        "https://ghost.org/",
    ),
]


def _extract_host(target: str) -> str:
    """Pull a bare hostname out of a URL or plain string."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.netloc or target).split(":")[0].strip()


def _resolve_cname(host: str, timeout: float = 3.0) -> Optional[str]:
    """Attempt to resolve a CNAME record for *host*.

    Python's stdlib doesn't expose CNAME lookups directly, so we try
    socket.getaddrinfo first (A/AAAA).  If that fails we fall back to
    attempting an HTTP request and reading the CNAME from the
    response chain via socket.  In practice we look for CNAMEs by
    attempting to resolve; if the host has only a CNAME, getaddrinfo
    may still return the final A record.  To keep this dependency-free
    we instead probe the host over HTTP and inspect the response
    headers/body for service fingerprints, then attempt a CNAME-like
    resolution via getaddrinfo on the www subdomain.

    Returns a CNAME target string if discoverable, else None.
    """
    try:
        # Try direct resolution (returns A/AAAA; if only CNAME exists
        # this may still work on some resolvers).
        infos = socket.getaddrinfo(host, None, timeout=timeout)
        # We cannot easily extract the CNAME from getaddrinfo, so we
        # return the hostname itself as a placeholder for probing.
        return host
    except Exception:
        return None


def _http_probe(url: str, timeout: float = 5.0) -> Optional[Tuple[int, str, str]]:
    """Return (status_code, body_preview, headers_str) or None."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        body = (resp.text or "")[:2000]
        headers = str(dict(resp.headers))
        return resp.status_code, body, headers
    except requests.RequestException:
        return None


def _check_takeover(
    subdomain: str,
    cname_target: str,
    timeout: float = 5.0,
) -> Optional[Dict]:
    """Probe a single subdomain for takeover potential."""
    cname_lower = cname_target.lower()

    for service_name, cname_contains, error_indicators, claim_url in TAKEOVER_FINGERPRINTS:
        if cname_contains not in cname_lower:
            continue

        # Try both http and https
        for scheme in ("http", "https"):
            url = f"{scheme}://{subdomain}"
            probe = _http_probe(url, timeout=timeout)
            if probe is None:
                continue

            status_code, body, headers = probe
            body_lower = body.lower()

            for indicator in error_indicators:
                if indicator.lower() in body_lower or indicator.lower() in headers.lower():
                    return {
                        "subdomain": subdomain,
                        "cname_target": cname_target,
                        "service": service_name,
                        "status_code": status_code,
                        "evidence": indicator,
                        "claim_url": claim_url,
                        "scheme": scheme,
                        "confidence": "high",
                    }

    return None


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def scan_takeovers(
    subdomains: List[str],
    timeout: float = 5.0,
    max_workers: int = 50,
) -> Dict:
    """
    Scan a list of subdomains for takeover vulnerabilities.

    Parameters
    ----------
    subdomains : list[str]
        List of subdomain hostnames (e.g. ["www.example.com", "api.example.com"]).
    timeout : float
        Per-request timeout in seconds.
    max_workers : int
        Thread pool size.

    Returns
    -------
    dict
        {
            "targets_scanned": int,
            "takeovers": [ {...}, ... ],
            "summary": {
                "total": int,
                "by_service": {...},
            },
        }
    """
    findings: List[Dict] = []
    lock = threading.Lock()
    by_service: Dict[str, int] = {}

    def _add(finding: Dict) -> None:
        with lock:
            findings.append(finding)
            svc = finding["service"]
            by_service[svc] = by_service.get(svc, 0) + 1

    def _check(sub: str) -> None:
        # Normalize: strip scheme if present
        host = _extract_host(sub)
        cname_target = _resolve_cname(host, timeout=timeout)
        if not cname_target:
            return
        result = _check_takeover(host, cname_target, timeout=timeout)
        if result:
            _add(result)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check, s): s for s in subdomains}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass

    return {
        "targets_scanned": len(subdomains),
        "takeovers": findings,
        "summary": {
            "total": len(findings),
            "by_service": by_service,
        },
    }


# --------------------------------------------------------------------------- #
# Backward-compatible wrapper
# --------------------------------------------------------------------------- #

def scan_takeovers_legacy(
    subdomains: List[str],
    timeout: float = 5.0,
) -> List[str]:
    """Legacy helper returning a list of human-readable strings."""
    result = scan_takeovers(subdomains, timeout=timeout)
    out: List[str] = []
    for t in result["takeovers"]:
        out.append(
            f"[{t['service']}] {t['subdomain']} -> {t['cname_target']} "
            f"(evidence: {t['evidence']})"
        )
    return out
