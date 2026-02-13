import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


XSS_PAYLOAD = "<script>alert(1)</script>"


def _inject_payload(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if not query:
        query = {"q": XSS_PAYLOAD}
    else:
        for key in query:
            query[key] = XSS_PAYLOAD

    new_query = urlencode(query, doseq=True)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def test_basic_xss(url: str, timeout: int = 5):
    """
    Inject a test payload and check for reflection.
    Returns (is_reflected: bool, test_url: str)
    """
    test_url = _inject_payload(url)
    try:
        resp = requests.get(test_url, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")
        if XSS_PAYLOAD in resp.text or XSS_PAYLOAD in soup.prettify():
            return True, test_url
    except requests.RequestException:
        return False, test_url

    return False, test_url
