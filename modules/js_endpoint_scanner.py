"""
JavaScript Endpoint & Secret Extractor for ReconX.

Extracts JavaScript files from a target website and scans them for:
- Hidden API endpoints (/api/v1/users, /internal/admin, etc.)
- Exposed secrets (API keys, AWS keys, JWT tokens, Firebase config, etc.)
- Source map references (.map files that leak full source code)
- Debug/test endpoints

Designed for bug bounty hunters — finds endpoints and secrets that
are often missed by passive scanning.

Public API
----------
extract_js_endpoints(base_url, html=None, timeout=5)
    -> dict with endpoints, secrets, source_maps, scripts and summary.
extract_js_endpoints_legacy(base_url, html=None, timeout=5)
    -> list[str]  (backward-compatible list of strings)
"""

from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

# Silence InsecureRequestWarning
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Regex patterns for endpoint detection in JS
ENDPOINT_PATTERNS: List[Tuple[str, str, str]] = [
    # API paths
    ("api_endpoint", r'["\'](/api/[^"\']+)["\']', "API endpoint path"),
    ("api_endpoint_v1", r'["\'](/v1/[^"\']+)["\']', "API v1 endpoint path"),
    ("api_endpoint_v2", r'["\'](/v2/[^"\']+)["\']', "API v2 endpoint path"),
    ("api_endpoint_v3", r'["\'](/v3/[^"\']+)["\']', "API v3 endpoint path"),
    ("api_endpoint_graphql", r'["\'](/graphql[^"\']*)["\']', "GraphQL endpoint"),
    ("api_endpoint_rest", r'["\'](/rest/[^"\']+)["\']', "REST endpoint path"),
    ("api_endpoint_internal", r'["\'](/internal/[^"\']+)["\']', "Internal endpoint path"),
    ("api_endpoint_admin", r'["\'](/admin/[^"\']+)["\']', "Admin endpoint path"),
    ("api_endpoint_dev", r'["\'](/dev/[^"\']+)["\']', "Dev endpoint path"),
    ("api_endpoint_test", r'["\'](/test/[^"\']+)["\']', "Test endpoint path"),
    ("api_endpoint_staging", r'["\'](/staging/[^"\']+)["\']', "Staging endpoint path"),
    ("api_endpoint_webhook", r'["\'](/webhook[^"\']*)["\']', "Webhook endpoint"),
    ("api_endpoint_callback", r'["\'](/callback[^"\']*)["\']', "Callback endpoint"),
    ("api_endpoint_oauth", r'["\'](/oauth[^"\']*)["\']', "OAuth endpoint"),
    ("api_endpoint_sso", r'["\'](/sso[^"\']*)["\']', "SSO endpoint"),
    ("api_endpoint_upload", r'["\'](/upload[^"\']*)["\']', "File upload endpoint"),
    ("api_endpoint_download", r'["\'](/download[^"\']*)["\']', "File download endpoint"),
    ("api_endpoint_payment", r'["\'](/payment[^"\']*)["\']', "Payment endpoint"),
    ("api_endpoint_cart", r'["\'](/cart[^"\']*)["\']', "Shopping cart endpoint"),
    ("api_endpoint_order", r'["\'](/order[^"\']*)["\']', "Order endpoint"),
    ("api_endpoint_user", r'["\'](/user[s]?/[^"\']*)["\']', "User endpoint"),
    ("api_endpoint_auth", r'["\'](/auth[^"\']*)["\']', "Authentication endpoint"),
    ("api_endpoint_login", r'["\'](/login[^"\']*)["\']', "Login endpoint"),
    ("api_endpoint_logout", r'["\'](/logout[^"\']*)["\']', "Logout endpoint"),
    ("api_endpoint_register", r'["\'](/register[^"\']*)["\']', "Register endpoint"),
    ("api_endpoint_token", r'["\'](/token[^"\']*)["\']', "Token endpoint"),
    ("api_endpoint_keys", r'["\'](/keys[^"\']*)["\']', "Keys endpoint"),
    ("api_endpoint_config", r'["\'](/config[^"\']*)["\']', "Config endpoint"),
    ("api_endpoint_settings", r'["\'](/settings[^"\']*)["\']', "Settings endpoint"),
    ("api_endpoint_debug", r'["\'](/debug[^"\']*)["\']', "Debug endpoint"),
    ("api_endpoint_swagger", r'["\'](/swagger[^"\']*)["\']', "Swagger/OpenAPI docs"),
    ("api_endpoint_openapi", r'["\'](/openapi[^"\']*)["\']', "OpenAPI spec"),
    # Full URLs
    ("full_url_http", r'https?://[^"\'\s<>&]+', "Full HTTP(S) URL"),
]

# Regex patterns for secret detection in JS
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    ("aws_access_key", r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    ("aws_secret_key", r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Access Key"),
    ("aws_session_token", r'(?i)aws[_-]?session[_-]?token["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{100,})["\']', "AWS Session Token"),
    ("github_token", r'(?i)github[_-]?token["\']?\s*[:=]\s*["\'](gh[p|o|u|s]_[A-Za-z0-9_]{36,})["\']', "GitHub Token"),
    ("gitlab_token", r'(?i)gitlab[_-]?token["\']?\s*[:=]\s*["\'](glpat-[A-Za-z0-9_-]{20,})["\']', "GitLab Token"),
    ("slack_token", r'(?i)slack[_-]?token["\']?\s*[:=]\s*["\'](xox[b|a|o|r]-[A-Za-z0-9-]{10,})["\']', "Slack Token"),
    ("stripe_key", r'(?i)stripe[_-]?(secret|publishable)?[_-]?key["\']?\s*[:=]\s*["\'](sk|pk)_(live|test)_[A-Za-z0-9]{24,}', "Stripe API Key"),
    ("paypal_key", r'(?i)paypal[_-]?(client|secret)[_-]?(id|key)?["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']', "PayPal API Key"),
    ("twilio_key", r'(?i)twilio[_-]?(account|auth)[_-]?(sid|token)?["\']?\s*[:=]\s*["\'](AC|SK)[A-Za-z0-9_-]{32,}', "Twilio Credentials"),
    ("sendgrid_key", r'(?i)sendgrid[_-]?key["\']?\s*[:=]\s*["\'](SG\.[A-Za-z0-9_-]{22,})["\']', "SendGrid API Key"),
    ("mailgun_key", r'(?i)mailgun[_-]?key["\']?\s*[:=]\s*["\'](key-[A-Za-z0-9]{32,})["\']', "Mailgun API Key"),
    ("firebase_config", r'(?i)firebase[_-]?config["\']?\s*[:=]\s*\{[^}]*apiKey["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{30,})', "Firebase Config (apiKey)"),
    ("firebase_database_url", r'(?i)databaseURL["\']?\s*[:=]\s*["\'](https://[^"\']+\.firebaseio\.com)["\']', "Firebase Database URL"),
    ("firebase_project_id", r'(?i)projectId["\']?\s*[:=]\s*["\']([a-z0-9-]{10,})["\']', "Firebase Project ID"),
    ("google_api_key", r'(?i)google[_-]?api[_-]?key["\']?\s*[:=]\s*["\'](AIza[0-9A-Za-z_-]{35,})["\']', "Google API Key"),
    ("google_oauth_client", r'(?i)google[_-]?oauth[_-]?client[_-]?(id|secret)["\']?\s*[:=]\s*["\']([0-9]+-[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com)["\']', "Google OAuth Client"),
    ("aws_s3_bucket", r'(?i)s3[_-]?bucket[_-]?name["\']?\s*[:=]\s*["\']([a-z0-9][a-z0-9.-]{1,60}[a-z0-9])["\']', "AWS S3 Bucket Name"),
    ("heroku_api_key", r'(?i)heroku[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', "Heroku API Key"),
    ("sendinblue_key", r'(?i)sendinblue[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32,})["\']', "Sendinblue API Key"),
    ("mailchimp_key", r'(?i)mailchimp[_-]?key["\']?\s*[:=]\s*["\']([a-z0-9]{32}-us[0-9]{1,2})["\']', "Mailchimp API Key"),
    ("generic_api_key", r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']', "Generic API Key"),
    ("generic_secret", r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']', "Generic Secret Key"),
    ("generic_password", r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "Generic Password"),
    ("jwt_secret", r'(?i)jwt[_-]?secret["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{16,})["\']', "JWT Secret"),
    ("encryption_key", r'(?i)encryption[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=]{16,})["\']', "Encryption Key"),
    ("database_url", r'(?i)(database|db)[_-]?url["\']?\s*[:=]\s*["\']((?:postgres|mysql|mongodb|redis)://[^"\']+)["\']', "Database Connection URL"),
    ("redis_url", r'(?i)redis[_-]?url["\']?\s*[:=]\s*["\'](redis://[^"\']+)["\']', "Redis Connection URL"),
    ("elasticsearch_url", r'(?i)elasticsearch[_-]?url["\']?\s*[:=]\s*["\'](https?://[^"\']+)["\']', "Elasticsearch URL"),
    ("basic_auth", r'(?i)authorization["\']?\s*[:=]\s*["\']Basic\s+[A-Za-z0-9+/=]+["\']', "Basic Auth Header"),
    ("bearer_token", r'(?i)(?:authorization|token)["\']?\s*[:=]\s*["\'](?:Bearer\s+)?([A-Za-z0-9\-._~+/]+=*)["\']', "Bearer Token"),
    ("private_key", r'-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END [A-Z ]*PRIVATE KEY-----', "Private Key"),
    ("aws_role_arn", r'arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@-]+', "AWS IAM Role ARN"),
]


def _extract_host(target: str) -> str:
    """Pull a bare hostname out of a URL or plain string."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.netloc or target).split(":")[0].strip()


def _normalize_base(base_url: str) -> str:
    return base_url.rstrip("/")


def _fetch(url: str, timeout: float = 5.0) -> Optional[str]:
    """Fetch a URL and return its text content, or None on failure."""
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True, verify=False
        )
        return resp.text
    except requests.RequestException:
        return None


def _extract_script_urls(html: str, base_url: str) -> List[str]:
    """Extract all script src URLs from HTML and resolve them against base_url."""
    script_urls: List[str] = []
    # Match <script src="..."> tags
    for match in re.finditer(
        r'<script[^>]+src\s*=\s*["\']([^"\']+)["\'][^>]*>',
        html,
        re.IGNORECASE,
    ):
        src = match.group(1)
        absolute = urljoin(base_url, src)
        script_urls.append(absolute)
    # Also detect inline scripts with source map references
    return script_urls


def _extract_inline_scripts(html: str) -> List[str]:
    """Extract inline script content from HTML."""
    scripts: List[str] = []
    for match in re.finditer(
        r'<script[^>]*>(.*?)</script>',
        html,
        re.IGNORECASE | re.DOTALL,
    ):
        content = match.group(1)
        if content and content.strip():
            scripts.append(content.strip())
    return scripts


def _extract_endpoints(text: str) -> List[Dict]:
    """Extract endpoint-like strings from JavaScript text."""
    found: List[Dict] = []
    seen: Set[str] = set()

    for pattern_name, pattern, description in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(0)
            # Clean up trailing punctuation
            value = value.rstrip(";,)}'\"`")
            if value in seen:
                continue
            seen.add(value)
            found.append(
                {
                    "type": pattern_name,
                    "value": value,
                    "description": description,
                }
            )
    return found


def _extract_secrets(text: str) -> List[Dict]:
    """Extract secret-like strings from JavaScript text."""
    found: List[Dict] = []
    seen: Set[str] = set()

    for pattern_name, pattern, description in SECRET_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            # For patterns with groups, capture the meaningful part
            groups = match.groups()
            value = groups[0] if groups else match.group(0)
            value = value.strip("\"'")
            if not value or value in seen:
                continue
            seen.add(value)
            found.append(
                {
                    "type": pattern_name,
                    "value": value,
                    "description": description,
                }
            )
    return found


def _extract_source_maps(text: str) -> List[str]:
    """Extract source map URLs from JavaScript text (//# sourceMappingURL=...)."""
    source_maps: List[str] = []
    for match in re.finditer(
        r'//#\s*sourceMappingURL\s*=\s*([^\s]+)',
        text,
        re.IGNORECASE,
    ):
        source_maps.append(match.group(1).strip())
    return source_maps


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def extract_js_endpoints(
    base_url: str,
    html: Optional[str] = None,
    timeout: float = 5.0,
    max_workers: int = 30,
) -> Dict:
    """
    Extract JavaScript endpoints and secrets from a target website.

    Parameters
    ----------
    base_url : str
        The target URL (e.g. https://example.com).
    html : str | None
        Pre-fetched HTML content.  If None, the homepage is fetched.
    timeout : float
        Per-request timeout in seconds.
    max_workers : int
        Thread pool size for fetching JS files.

    Returns
    -------
    dict
        {
            "target": str,
            "scripts": [ {...}, ... ],         # script metadata
            "endpoints": [ {...}, ... ],        # discovered endpoints
            "secrets": [ {...}, ... ],           # discovered secrets
            "source_maps": [ {...}, ... ],       # source map references
            "summary": { ... },
        }
    """
    base_url = _normalize_base(base_url)

    if html is None:
        html = _fetch(base_url, timeout=timeout) or ""

    script_urls = _extract_script_urls(html, base_url)
    inline_scripts = _extract_inline_scripts(html)

    scripts: List[Dict] = []
    all_endpoints: List[Dict] = []
    all_secrets: List[Dict] = []
    all_source_maps: List[Dict] = []
    seen_script_urls: Set[str] = set()
    seen_endpoint_values: Set[str] = set()
    seen_secret_values: Set[str] = set()

    lock = threading.Lock()

    def _add_script(script: Dict) -> None:
        nonlocal seen_script_urls
        with lock:
            if script["url"] not in seen_script_urls:
                seen_script_urls.add(script["url"])
                scripts.append(script)

    def _add_endpoint(endpoint: Dict) -> None:
        nonlocal seen_endpoint_values
        with lock:
            if endpoint["value"] not in seen_endpoint_values:
                seen_endpoint_values.add(endpoint["value"])
                all_endpoints.append(endpoint)

    def _add_secret(secret: Dict) -> None:
        nonlocal seen_secret_values
        with lock:
            if secret["value"] not in seen_secret_values:
                seen_secret_values.add(secret["value"])
                all_secrets.append(secret)

    def _add_source_map(source_map: Dict) -> None:
        with lock:
            all_source_maps.append(source_map)

    # Process inline scripts first
    for idx, inline_content in enumerate(inline_scripts):
        script_url = f"{base_url}#inline-{idx}"
        _add_script(
            {
                "url": script_url,
                "type": "inline",
                "status_code": 200,
                "content_length": len(inline_content),
                "is_external": False,
            }
        )

        endpoints = _extract_endpoints(inline_content)
        for ep in endpoints:
            _add_endpoint(
                {
                    "type": ep["type"],
                    "value": ep["value"],
                    "description": ep["description"],
                    "source": f"inline-{idx}",
                    "method": "GET",
                }
            )

        secrets = _extract_secrets(inline_content)
        for sec in secrets:
            _add_secret(
                {
                    "type": sec["type"],
                    "value": sec["value"],
                    "description": sec["description"],
                    "source": f"inline-{idx}",
                }
            )

        source_maps = _extract_source_maps(inline_content)
        for sm in source_maps:
            absolute_sm = urljoin(base_url, sm)
            _add_source_map(
                {
                    "url": absolute_sm,
                    "source": f"inline-{idx}",
                }
            )

    # Fetch external JS files concurrently
    def _fetch_and_analyze(script_url: str) -> None:
        content = _fetch(script_url, timeout=timeout)
        if content is None:
            return

        # Try to get status code and content length from headers
        status_code = 200
        content_length = len(content)
        try:
            resp = requests.head(
                script_url, timeout=timeout, allow_redirects=True, verify=False
            )
            status_code = resp.status_code
            content_length = int(resp.headers.get("Content-Length", content_length) or content_length)
        except requests.RequestException:
            pass

        script_entry = {
            "url": script_url,
            "type": "external",
            "status_code": status_code,
            "content_length": content_length,
            "is_external": True,
        }
        _add_script(script_entry)

        endpoints = _extract_endpoints(content)
        for ep in endpoints:
            _add_endpoint(
                {
                    "type": ep["type"],
                    "value": ep["value"],
                    "description": ep["description"],
                    "source": script_url,
                    "method": "GET",
                }
            )

        secrets = _extract_secrets(content)
        for sec in secrets:
            _add_secret(
                {
                    "type": sec["type"],
                    "value": sec["value"],
                    "description": sec["description"],
                    "source": script_url,
                }
            )

        source_maps = _extract_source_maps(content)
        for sm in source_maps:
            absolute_sm = urljoin(script_url, sm)
            _add_source_map(
                {
                    "url": absolute_sm,
                    "source": script_url,
                }
            )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch_and_analyze, url): url for url in script_urls}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass

    # Build summary
    endpoint_types: Dict[str, int] = {}
    for ep in all_endpoints:
        t = ep["type"]
        endpoint_types[t] = endpoint_types.get(t, 0) + 1

    secret_types: Dict[str, int] = {}
    for sec in all_secrets:
        t = sec["type"]
        secret_types[t] = secret_types.get(t, 0) + 1

    summary = {
        "total_scripts": len(scripts),
        "external_scripts": sum(1 for s in scripts if s["is_external"]),
        "inline_scripts": sum(1 for s in scripts if not s["is_external"]),
        "total_endpoints": len(all_endpoints),
        "total_secrets": len(all_secrets),
        "total_source_maps": len(all_source_maps),
        "endpoint_types": endpoint_types,
        "secret_types": secret_types,
    }

    return {
        "target": base_url,
        "scripts": scripts,
        "endpoints": all_endpoints,
        "secrets": all_secrets,
        "source_maps": all_source_maps,
        "summary": summary,
    }


# --------------------------------------------------------------------------- #
# Backward-compatible wrapper
# --------------------------------------------------------------------------- #

def extract_js_endpoints_legacy(
    base_url: str,
    html: Optional[str] = None,
    timeout: float = 5.0,
) -> List[str]:
    """Legacy helper returning a list of human-readable strings."""
    result = extract_js_endpoints(base_url, html=html, timeout=timeout)
    out: List[str] = []

    for ep in result["endpoints"]:
        out.append(f"[ENDPOINT] {ep['type']}: {ep['value']} ({ep['source']})")

    for sec in result["secrets"]:
        out.append(f"[SECRET] {sec['type']}: {sec['value']} ({sec['source']})")

    for sm in result["source_maps"]:
        out.append(f"[SOURCE-MAP] {sm['url']} (from {sm['source']})")

    return out
