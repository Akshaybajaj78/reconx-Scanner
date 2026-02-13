import requests
from urllib.parse import urljoin


def scan_directories(base_url: str, wordlist_path: str, timeout: int = 5):
    """
    Scan common directories from a wordlist.
    Returns discovered paths.
    """
    found = []

    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return found

    for word in words:
        path = f"{word.strip('/')}/"
        url = urljoin(base_url.rstrip("/") + "/", path)
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            if resp.status_code < 400:
                found.append(url)
        except requests.RequestException:
            continue

    return found
