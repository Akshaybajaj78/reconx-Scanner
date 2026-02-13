import requests
from urllib.parse import urlparse


DEFAULT_SUBDOMAINS = [
    "www",
    "mail",
    "api",
    "dev",
    "test",
    "staging",
    "beta",
    "blog",
    "admin",
    "portal",
]


def _extract_host(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        return parsed.netloc
    return target.split("/")[0]


def scan_subdomains(target: str, timeout: int = 5):
    """
    Brute-force a small list of subdomains and return the valid ones.
    """
    host = _extract_host(target)
    found = []

    for sub in DEFAULT_SUBDOMAINS:
        subdomain = f"{sub}.{host}"
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                # Any HTTP response means the host exists (even 401/403/404)
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
                if resp.status_code < 500:
                    found.append(url)
                    break
            except requests.RequestException:
                continue

    return found
