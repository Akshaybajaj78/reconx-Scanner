import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
]


def check_headers(url: str, timeout: int = 5):
    """
    Return a list of missing security headers.
    """
    missing = []
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header in SECURITY_HEADERS:
            if header.lower() not in headers:
                missing.append(header)
    except requests.RequestException:
        return missing

    return missing
