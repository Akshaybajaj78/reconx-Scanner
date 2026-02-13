import requests


EVIL_ORIGIN = "https://evil.example"


def check_cors(url: str, timeout: int = 5):
    """
    Detect common CORS misconfigurations.
    Returns list of issues.
    """
    issues = []
    headers = {"Origin": EVIL_ORIGIN}

    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "")

        if allow_origin == "*":
            issues.append("Access-Control-Allow-Origin allows wildcard (*)")

        if allow_origin == EVIL_ORIGIN:
            issues.append("Access-Control-Allow-Origin reflects arbitrary Origin")

        if allow_origin == "*" and allow_creds.lower() == "true":
            issues.append("Wildcard ACAO with credentials enabled")
    except requests.RequestException:
        return issues

    return issues
