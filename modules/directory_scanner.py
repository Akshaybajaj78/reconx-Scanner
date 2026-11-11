"""
Advanced directory & API endpoint discovery module for ReconX.

Discovers hidden directories, API endpoints, documentation endpoints,
and sensitive files by probing common paths with multiple HTTP methods.

Techniques
----------
1. Large API-focused wordlist (REST, GraphQL, SOAP, internal APIs).
2. Multi-method probing: GET, POST, HEAD, OPTIONS to catch method-gated
   endpoints.
3. API documentation detection (Swagger/OpenAPI, GraphQL playground,
   Postman collections, etc.).
4. Parallel scanning with ThreadPoolExecutor.
5. Status code + content-type + response-size fingerprinting.

Public API
----------
scan_directories(base_url, wordlist_path=None, timeout=5, methods=None,
                 max_workers=50, aggressive=False, probe_api_docs=True)
    -> dict with rich path objects and summary.
scan_directories_legacy(base_url, wordlist_path, timeout=5)
    -> list[str]  (backward-compatible list of discovered URLs)
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Sequence, Set
from urllib.parse import urljoin

import requests

# Silence InsecureRequestWarning for HTTPS probing
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass


# --------------------------------------------------------------------------- #
# Comprehensive API & directory wordlist
# --------------------------------------------------------------------------- #

API_DIRECTORY_WORDLIST: List[str] = [
    # === Root / common ===
    "/", "/index", "/index.html", "/index.php", "/default", "/home",
    "/about", "/contact", "/login", "/logout", "/signup", "/register",
    "/dashboard", "/admin", "/administrator", "/manage", "/management",
    "/control", "/panel", "/cpanel", "/wp-admin", "/wp-login",
    # === REST API ===
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
    "/api/v3", "/api/v3/", "/api/v4", "/api/v4/", "/api/v5", "/api/v5/",
    "/api/public", "/api/private", "/api/internal", "/api/external",
    "/api/rest", "/api/rest/v1", "/api/rest/v2", "/api/json",
    "/api/xml", "/api/users", "/api/user", "/api/auth", "/api/login",
    "/api/logout", "/api/register", "/api/token", "/api/oauth",
    "/api/oauth2", "/api/sso", "/api/saml", "/api/oidc",
    "/api/products", "/api/product", "/api/items", "/api/item",
    "/api/orders", "/api/order", "/api/cart", "/api/checkout",
    "/api/payment", "/api/payments", "/api/invoice", "/api/invoices",
    "/api/search", "/api/query", "/api/data", "/api/files",
    "/api/upload", "/api/download", "/api/image", "/api/images",
    "/api/video", "/api/videos", "/api/document", "/api/documents",
    "/api/settings", "/api/config", "/api/configuration",
    "/api/profile", "/api/profiles", "/api/account", "/api/accounts",
    "/api/role", "/api/roles", "/api/permission", "/api/permissions",
    "/api/group", "/api/groups", "/api/team", "/api/teams",
    "/api/organization", "/api/org", "/api/tenant", "/api/tenants",
    "/api/health", "/api/healthz", "/api/ping", "/api/status",
    "/api/version", "/api/versions", "/api/info", "/api/meta",
    "/api/metrics", "/api/stats", "/api/statistics", "/api/analytics",
    "/api/report", "/api/reports", "/api/export", "/api/import",
    "/api/log", "/api/logs", "/api/audit", "/api/audit-log",
    "/api/event", "/api/events", "/api/notification", "/api/notifications",
    "/api/alert", "/api/alerts", "/api/message", "/api/messages",
    "/api/mail", "/api/email", "/api/sms", "/api/push",
    "/api/webhook", "/api/webhooks", "/api/callback", "/api/hooks",
    "/api/subscribe", "/api/unsubscribe", "/api/verify", "/api/verify-email",
    "/api/reset", "/api/forgot", "/api/forgot-password", "/api/reset-password",
    "/api/change-password", "/api/2fa", "/api/mfa", "/api/totp",
    "/api/device", "/api/devices", "/api/session", "/api/sessions",
    "/api/cookie", "/api/cookies", "/api/header", "/api/headers",
    "/api/ip", "/api/ip-address", "/api/geo", "/api/location",
    "/api/time", "/api/date", "/api/calendar", "/api/schedule",
    "/api/weather", "/api/currency", "/api/price", "/api/quote",
    "/api/stock", "/api/crypto", "/api/token-price", "/api/balance",
    "/api/wallet", "/api/transaction", "/api/transactions",
    "/api/deposit", "/api/withdraw", "/api/transfer", "/api/send",
    "/api/receive", "/api/address", "/api/addresses", "/api/kyc",
    "/api/aml", "/api/compliance", "/api/legal", "/api/terms",
    "/api/privacy", "/api/cookie-policy", "/api/disclaimer",
    "/api/support", "/api/help", "/api/faq", "/api/knowledge-base",
    "/api/ticket", "/api/tickets", "/api/issue", "/api/issues",
    "/api/feedback", "/api/comment", "/api/comments", "/api/review",
    "/api/reviews", "/api/rating", "/api/ratings", "/api/like",
    "/api/likes", "/api/follow", "/api/followers", "/api/following",
    "/api/friend", "/api/friends", "/api/block", "/api/blocked",
    "/api/report-user", "/api/report-content", "/api/moderate",
    "/api/moderation", "/api/ban", "/api/unban", "/api/mute",
    "/api/unmute", "/api/verify-user", "/api/verify-account",
    "/api/invite", "/api/invites", "/api/invitation", "/api/referral",
    "/api/referrals", "/api/promo", "/api/coupon", "/api/discount",
    "/api/subscription", "/api/subscriptions", "/api/plan", "/api/plans",
    "/api/billing", "/api/pricing", "/api/invoice", "/api/invoices",
    "/api/receipt", "/api/receipts", "/api/payment-method",
    "/api/payment-methods", "/api/card", "/api/cards", "/api/bank",
    "/api/bank-account", "/api/bank-accounts", "/api/paypal",
    "/api/stripe", "/api/square", "/api/venmo", "/api/cash-app",
    # === GraphQL ===
    "/graphql", "/graphql/", "/graphql/console", "/graphql/playground",
    "/graphql/voyager", "/graphiql", "/graphiql/", "/graphql-explorer",
    "/gql", "/query", "/mutation", "/subscription",
    # === Swagger / OpenAPI ===
    "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html",
    "/swagger-ui/index.html", "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api-docs/", "/api-docs/swagger.json",
    "/openapi", "/openapi/", "/openapi.json", "/openapi.yaml",
    "/openapi/v1", "/openapi/v1/", "/openapi/v2", "/openapi/v2/",
    "/v3/api-docs", "/v3/api-docs/", "/v2/api-docs", "/v2/api-docs/",
    "/api/openapi.json", "/api/openapi.yaml",
    "/docs", "/docs/", "/documentation", "/documentation/",
    "/api/docs", "/api/docs/", "/api/documentation", "/api/documentation/",
    "/redoc", "/redoc/", "/api/redoc", "/api/redoc/",
    "/rapidoc", "/rapidoc/", "/api/rapidoc", "/api/rapidoc/",
    # === SOAP / XML ===
    "/soap", "/soap/", "/wsdl", "/wsdl/", "/service.asmx",
    "/service.asmx/", "/api.asmx", "/api.asmx/", "/webservices",
    "/webservices/", "/services", "/services/", "/axis2",
    "/axis2/services", "/jaxws", "/jaxws/services",
    # === Internal / debug ===
    "/debug", "/debug/", "/dev", "/dev/", "/development", "/staging",
    "/staging/", "/test", "/test/", "/testing", "/qa", "/qa/",
    "/uat", "/uat/", "/beta", "/beta/", "/alpha", "/alpha/",
    "/internal", "/internal/", "/intranet", "/intranet/",
    "/private", "/private/", "/secret", "/secret/", "/hidden",
    "/hidden/", "/backup", "/backup/", "/backups", "/backups/",
    "/bak", "/bak/", "/old", "/old/", "/archive", "/archive/",
    "/tmp", "/tmp/", "/temp", "/temp/", "/cache", "/cache/",
    "/logs", "/logs/", "/log", "/log/", "/log.txt", "/access.log",
    "/error.log", "/debug.log", "/system.log", "/app.log",
    # === Config / sensitive files ===
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.test", "/config", "/config/",
    "/config.json", "/config.yaml", "/config.yml", "/config.xml",
    "/config.ini", "/config.cfg", "/settings.json", "/settings.yaml",
    "/settings.yml", "/settings.xml", "/settings.ini", "/settings.cfg",
    "/.git", "/.git/", "/.git/config", "/.git/HEAD", "/.svn",
    "/.svn/", "/.hg", "/.hg/", "/.bzr", "/.bzr/",
    "/.dockerignore", "/Dockerfile", "/docker-compose.yml",
    "/docker-compose.yaml", "/.htaccess", "/.htpasswd",
    "/web.config", "/.npmrc", "/.yarnrc", "/package.json",
    "/composer.json", "/Gemfile", "/Gemfile.lock", "/requirements.txt",
    "/package-lock.json", "/yarn.lock", "/Makefile", "/Vagrantfile",
    # === Common files ===
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/sitemap1.xml", "/sitemap2.xml", "/sitemap.php", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/favicon.ico", "/favicon.png",
    "/apple-touch-icon.png", "/manifest.json", "/browserconfig.xml",
    "/.well-known", "/.well-known/", "/.well-known/security.txt",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    "/.well-known/openid-configuration", "/.well-known/webfinger",
    "/security.txt", "/security", "/security/", "/privacy", "/privacy/",
    "/terms", "/terms/", "/terms-of-service", "/terms-of-use",
    "/license", "/license/", "/legal", "/legal/", "/copyright",
    "/sitemap", "/sitemap/", "/rss", "/rss/", "/feed", "/feed/",
    "/atom", "/atom/", "/json", "/json/", "/xml", "/xml/",
    # === CMS / e-commerce ===
    "/wp-content", "/wp-content/", "/wp-includes", "/wp-includes/",
    "/wp-json", "/wp-json/", "/wp-json/wp/v2", "/wp-json/wp/v2/",
    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages", "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/media", "/wp-json/wp/v2/comments", "/wp-json/wp/v2/types",
    "/wp-json/wp/v2/statuses", "/wp-json/wp/v2/taxonomies",
    "/wp-json/wp/v2/search", "/wp-json/oembed/1.0/embed",
    "/xmlrpc.php", "/xmlrpc.php/", "/wordpress", "/wordpress/",
    "/joomla", "/joomla/", "/drupal", "/drupal/",
    "/magento", "/magento/", "/shopify", "/shopify/",
    "/prestashop", "/prestashop/", "/opencart", "/opencart/",
    # === Cloud / container ===
    "/.aws", "/.aws/", "/.azure", "/.azure/", "/.gcp", "/.gcp/",
    "/metadata", "/metadata/", "/metadata/v1", "/metadata/v1/",
    "/instance-identity", "/instance-identity/", "/dynamic",
    "/dynamic/", "/latest", "/latest/", "/latest/meta-data",
    "/latest/meta-data/", "/latest/user-data", "/latest/user-data/",
    "/.well-known/metadata", "/.well-known/metadata/",
    # === Common misc ===
    "/404", "/404.html", "/500", "/500.html", "/error", "/error/",
    "/maintenance", "/maintenance/", "/coming-soon", "/coming-soon/",
    "/under-construction", "/under-construction/", "/beta",
    "/changelog", "/changelog/", "/release", "/release/",
    "/roadmap", "/roadmap/", "/status", "/status/", "/uptime",
    "/uptime/", "/health-check", "/health-check/", "/alive",
    "/alive/", "/ready", "/ready/", "/live", "/live/",
    "/version.txt", "/version.json", "/version", "/version/",
    "/build", "/build/", "/deploy", "/deploy/", "/deployment",
    "/deployment/", "/ci", "/ci/", "/jenkins", "/jenkins/",
    "/teamcity", "/teamcity/", "/circleci", "/circleci/",
    "/travis", "/travis/", "/gitlab-ci", "/gitlab-ci/",
    "/actions", "/actions/", "/workflow", "/workflow/",
    # === Common API path patterns ===
    "/api/v1/users", "/api/v1/user", "/api/v1/auth", "/api/v1/login",
    "/api/v1/logout", "/api/v1/register", "/api/v1/token",
    "/api/v1/oauth", "/api/v1/oauth2", "/api/v1/products",
    "/api/v1/product", "/api/v1/orders", "/api/v1/order",
    "/api/v1/cart", "/api/v1/checkout", "/api/v1/payment",
    "/api/v1/payments", "/api/v1/invoice", "/api/v1/invoices",
    "/api/v1/search", "/api/v1/data", "/api/v1/files",
    "/api/v1/upload", "/api/v1/download", "/api/v1/image",
    "/api/v1/images", "/api/v1/video", "/api/v1/videos",
    "/api/v1/document", "/api/v1/documents", "/api/v1/settings",
    "/api/v1/config", "/api/v1/profile", "/api/v1/profiles",
    "/api/v1/account", "/api/v1/accounts", "/api/v1/role",
    "/api/v1/roles", "/api/v1/permission", "/api/v1/permissions",
    "/api/v1/group", "/api/v1/groups", "/api/v1/team",
    "/api/v1/teams", "/api/v1/health", "/api/v1/status",
    "/api/v1/version", "/api/v1/info", "/api/v1/metrics",
    "/api/v1/stats", "/api/v1/report", "/api/v1/reports",
    "/api/v1/log", "/api/v1/logs", "/api/v1/audit",
    "/api/v1/event", "/api/v1/events", "/api/v1/message",
    "/api/v1/messages", "/api/v1/webhook", "/api/v1/webhooks",
    "/api/v2/users", "/api/v2/user", "/api/v2/auth",
    "/api/v2/login", "/api/v2/logout", "/api/v2/register",
    "/api/v2/token", "/api/v2/oauth", "/api/v2/products",
    "/api/v2/product", "/api/v2/orders", "/api/v2/order",
    "/api/v2/cart", "/api/v2/checkout", "/api/v2/payment",
    "/api/v2/payments", "/api/v2/invoice", "/api/v2/invoices",
    "/api/v2/search", "/api/v2/data", "/api/v2/files",
    "/api/v2/upload", "/api/v2/download", "/api/v2/image",
    "/api/v2/images", "/api/v2/video", "/api/v2/videos",
    "/api/v2/document", "/api/v2/documents", "/api/v2/settings",
    "/api/v2/config", "/api/v2/profile", "/api/v2/profiles",
    "/api/v2/account", "/api/v2/accounts", "/api/v2/role",
    "/api/v2/roles", "/api/v2/permission", "/api/v2/permissions",
    "/api/v2/group", "/api/v2/groups", "/api/v2/team",
    "/api/v2/teams", "/api/v2/health", "/api/v2/status",
    "/api/v2/version", "/api/v2/info", "/api/v2/metrics",
    "/api/v2/stats", "/api/v2/report", "/api/v2/reports",
    "/api/v2/log", "/api/v2/logs", "/api/v2/audit",
    "/api/v2/event", "/api/v2/events", "/api/v2/message",
    "/api/v2/messages", "/api/v2/webhook", "/api/v2/webhooks",
]


# Well-known API path patterns (for detection)
API_PATH_PATTERNS = [
    "/api", "/graphql", "/swagger", "/openapi", "/api-docs",
    "/docs", "/soap", "/wsdl", "/rest", "/xmlrpc", "/wp-json",
    "/.well-known", "/webhook", "/oauth", "/sso", "/saml",
    "/oidc", "/auth", "/token", "/login", "/logout", "/register",
]


def _is_api_path(path: str) -> bool:
    """Check if a path looks like an API endpoint."""
    path_lower = path.lower()
    for pattern in API_PATH_PATTERNS:
        if path_lower.startswith(pattern) or pattern in path_lower:
            return True
    # Common API indicators
    api_indicators = ["/api/", "/graphql", "/swagger", "/openapi",
                      "/rest/", "/soap/", "/v1/", "/v2/", "/v3/",
                      "/wp-json/", "/webhook/"]
    for indicator in api_indicators:
        if indicator in path_lower:
            return True
    return False


def _looks_like_api_response(resp: requests.Response) -> bool:
    """Detect if a response looks like an API response."""
    content_type = (resp.headers.get("Content-Type", "") or "").lower()
    api_ct = ["application/json", "application/xml", "application/soap+xml",
              "text/xml", "application/graphql", "application/vnd.api+json",
              "application/yaml", "text/yaml"]
    for ct in api_ct:
        if ct in content_type:
            return True
    # GraphQL / Swagger body hints
    body = resp.text[:500].lower()
    api_hints = ["swagger", "openapi", "graphql", '"paths"',
                 '"definitions"', '"info"', '"servers"', '"components"',
                 '"query"', '"mutation"', '"subscription"',
                 '"access_token"', '"token_type"', '"expires_in"',
                 '"user"', '"id"', '"email"', '"status"']
    for hint in api_hints:
        if hint in body:
            return True
    return False


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _normalize_base(base_url: str) -> str:
    return base_url.rstrip("/")


def _probe_url(
    base_url: str,
    path: str,
    method: str,
    timeout: float,
) -> Optional[Dict]:
    """Probe a single URL with a given method."""
    url = urljoin(base_url + "/", path.lstrip("/"))
    try:
        if method == "GET":
            resp = requests.get(url, timeout=timeout, allow_redirects=False,
                                verify=False)
        elif method == "HEAD":
            resp = requests.head(url, timeout=timeout, allow_redirects=False,
                                 verify=False)
        elif method == "OPTIONS":
            resp = requests.options(url, timeout=timeout, allow_redirects=False,
                                    verify=False)
        elif method == "POST":
            resp = requests.post(url, timeout=timeout, allow_redirects=False,
                                 verify=False, json={})
        else:
            resp = requests.get(url, timeout=timeout, allow_redirects=False,
                                verify=False)

        status = resp.status_code
        content_type = resp.headers.get("Content-Type", "") or ""
        content_length = resp.headers.get("Content-Length", "") or ""
        body = resp.text[:200]

        # Consider it "found" if status is 2xx, 3xx, or 401/403 (exists but protected)
        is_found = status < 500 and status != 404
        if not is_found:
            return None

        entry: Dict = {
            "path": path,
            "url": url,
            "method": method,
            "status_code": status,
            "content_type": content_type,
            "content_length": content_length,
            "is_api": _is_api_path(path) or _looks_like_api_response(resp),
            "is_api_doc": any(d in path.lower() for d in
                              ["swagger", "openapi", "api-docs", "/docs",
                               "/graphql", "/graphiql", "/redoc", "/rapidoc",
                               "/wp-json/", "/.well-known"]),
            "body_preview": body[:100].replace("\n", " ").strip(),
            "server": resp.headers.get("Server", "") or "",
        }
        return entry
    except requests.RequestException:
        return None


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def scan_directories(
    base_url: str,
    wordlist_path: Optional[str] = None,
    timeout: float = 5.0,
    methods: Optional[Sequence[str]] = None,
    max_workers: int = 60,
    aggressive: bool = False,
    probe_api_docs: bool = True,
) -> Dict:
    """
    Advanced directory & API endpoint discovery.

    Parameters
    ----------
    base_url : str
        Base URL to scan (e.g. ``https://example.com``).
    wordlist_path : str | None
        Path to a custom wordlist file.  If omitted, the built-in
        API-focused wordlist is used.
    timeout : float
        Per-request timeout in seconds.
    methods : list[str] | None
        HTTP methods to try.  Defaults to ``["GET", "HEAD", "OPTIONS"]``.
        When ``aggressive=True``, ``POST`` is added.
    max_workers : int
        Thread pool size for concurrent scanning.
    aggressive : bool
        Include POST method and more aggressive detection.
    probe_api_docs : bool
        Prioritize API documentation endpoints.

    Returns
    -------
    dict
        {
            "target": str,
            "paths": [ {...}, ... ],          # rich path objects
            "api_endpoints": [ {...}, ... ],   # subset flagged as API
            "api_docs": [ {...}, ... ],        # API documentation endpoints
            "summary": {
                "total": int,
                "api_count": int,
                "docs_count": int,
                "methods_used": [...],
                "status_codes": {code: count},
            },
        }
    """
    base_url = _normalize_base(base_url)

    # Load wordlist
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                words = [line.strip() for line in f
                         if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            words = list(API_DIRECTORY_WORDLIST)
    else:
        words = list(API_DIRECTORY_WORDLIST)

    # Deduplicate and normalize paths
    seen_paths: Set[str] = set()
    unique_words: List[str] = []
    for w in words:
        p = w.strip("/")
        if not p or p in seen_paths:
            continue
        seen_paths.add(p)
        unique_words.append(p)

    # Methods to try
    if methods is None:
        methods = ["GET", "HEAD", "OPTIONS"]
        if aggressive:
            methods.append("POST")
    methods = list(methods)

    found: List[Dict] = []
    lock = threading.Lock()

    def check(path: str, method: str) -> None:
        entry = _probe_url(base_url, path, method, timeout)
        if entry:
            with lock:
                found.append(entry)

    # Build work items
    work_items: List[tuple] = []
    # Prioritize API docs first if requested
    ordered_words = list(unique_words)
    if probe_api_docs:
        api_docs_first = [
            w for w in unique_words
            if any(d in w.lower() for d in [
                "swagger", "openapi", "api-docs", "/docs", "/graphql",
                "/graphiql", "/redoc", "/rapidoc", "/wp-json/",
                "/.well-known",
            ])
        ]
        rest = [w for w in unique_words if w not in set(api_docs_first)]
        ordered_words = api_docs_first + rest

    for path in ordered_words:
        for method in methods:
            work_items.append((path, method))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, p, m): (p, m) for p, m in work_items}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass

    # Deduplicate by URL (keep the best method result)
    url_seen: Set[str] = set()
    deduped: List[Dict] = []
    for entry in found:
        url = entry["url"]
        if url in url_seen:
            continue
        url_seen.add(url)
        deduped.append(entry)

    # Sort: API docs first, then API endpoints, then others
    deduped.sort(key=lambda e: (
        not e["is_api_doc"],
        not e["is_api"],
        e["path"],
    ))

    api_endpoints = [e for e in deduped if e["is_api"] and not e["is_api_doc"]]
    api_docs = [e for e in deduped if e["is_api_doc"]]

    # Status code distribution
    status_codes: Dict[int, int] = {}
    for e in deduped:
        sc = e["status_code"]
        status_codes[sc] = status_codes.get(sc, 0) + 1

    summary = {
        "total": len(deduped),
        "api_count": len(api_endpoints),
        "docs_count": len(api_docs),
        "methods_used": methods,
        "status_codes": status_codes,
    }

    return {
        "target": base_url,
        "paths": deduped,
        "api_endpoints": api_endpoints,
        "api_docs": api_docs,
        "summary": summary,
    }


# --------------------------------------------------------------------------- #
# Backward-compatible wrapper
# --------------------------------------------------------------------------- #

def scan_directories_legacy(
    base_url: str,
    wordlist_path: str,
    timeout: int = 5,
) -> List[str]:
    """Legacy helper returning a list of discovered URLs."""
    result = scan_directories(
        base_url,
        wordlist_path=wordlist_path,
        timeout=timeout,
        methods=["GET"],
        max_workers=30,
        aggressive=False,
        probe_api_docs=False,
    )
    return [e["url"] for e in result["paths"]]
