"""
Tech stack detection module for ReconX.

Detects the technologies a website is built on by analysing HTTP
headers, HTML content, meta tags, generator tags, cookies, and
common file paths.  Every detected technology includes a plain-English
description of what it is used for.

All checks are passive — no exploitation, no credential testing.

Public API
----------
detect_tech_stack(base_url, timeout=5)
    -> dict with detected technologies grouped by category and a
       human-readable summary.
detect_tech_stack_legacy(base_url, timeout=5)
    -> list[str]  (backward-compatible list of strings)
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

# Silence InsecureRequestWarning for HTTPS probing
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass


# --------------------------------------------------------------------------- #
# Technology definition format
# --------------------------------------------------------------------------- #
# Each entry: (detection_name, category, description, confidence)
#   category:  "web_server", "cms", "language", "framework",
#              "javascript_library", "analytics", "cdn", "security",
#              "database", "cache", "other"
#   confidence: "high" | "medium" | "low"

TECH_SIGNATURES: List[Tuple[str, str, str, str]] = [
    # === Web servers ===
    ("Apache", "web_server",
     "The Apache HTTP Server is a popular open-source web server used to serve websites and web applications.",
     "high"),
    ("nginx", "web_server",
     "nginx is a high-performance web server and reverse proxy commonly used for serving static content and load balancing.",
     "high"),
    ("Microsoft-IIS", "web_server",
     "Internet Information Services (IIS) is Microsoft's web server for hosting ASP.NET and Windows-based web applications.",
     "high"),
    ("LiteSpeed", "web_server",
     "LiteSpeed Web Server is a high-performance, Apache-compatible web server often used for WordPress hosting.",
     "high"),
    ("Cloudflare", "cdn",
     "Cloudflare is a content delivery network and DDoS protection service that sits between visitors and the origin server.",
     "high"),
    ("Akamai", "cdn",
     "Akamai is a global content delivery network (CDN) and cloud service provider for website acceleration and security.",
     "medium"),
    ("Fastly", "cdn",
     "Fastly is an edge cloud platform and CDN used to deliver content quickly to users worldwide.",
     "medium"),

    # === CMS ===
    ("WordPress", "cms",
     "WordPress is a content management system (CMS) used to create and manage websites, blogs, and e-commerce stores.",
     "high"),
    ("Joomla", "cms",
     "Joomla is an open-source CMS for building websites and online applications.",
     "high"),
    ("Drupal", "cms",
     "Drupal is a flexible CMS platform used for complex, content-heavy websites and enterprise portals.",
     "high"),
    ("Magento", "cms",
     "Magento is an e-commerce platform used to build online stores and manage product catalogs, orders, and payments.",
     "high"),
    ("Shopify", "cms",
     "Shopify is a hosted e-commerce platform for creating online retail stores and selling products.",
     "high"),
    ("PrestaShop", "cms",
     "PrestaShop is an open-source e-commerce solution for online merchants.",
     "medium"),
    ("OpenCart", "cms",
     "OpenCart is a free open-source e-commerce platform for online stores.",
     "medium"),
    ("Wix", "cms",
     "Wix is a cloud-based website builder that lets users create sites with drag-and-drop tools.",
     "medium"),
    ("Squarespace", "cms",
     "Squarespace is a website building and hosting platform for portfolios, blogs, and small business sites.",
     "medium"),
    ("Ghost", "cms",
     "Ghost is a modern publishing platform for professional blogs and news sites.",
     "medium"),

    # === Programming languages ===
    ("PHP", "language",
     "PHP is a server-side scripting language used to build dynamic web pages and web applications.",
     "high"),
    ("Python", "language",
     "Python is a general-purpose programming language used for web backends, APIs, scripting, and data processing.",
     "high"),
    ("Ruby", "language",
     "Ruby is a dynamic programming language often used with the Rails framework for web development.",
     "high"),
    ("Node.js", "language",
     "Node.js is a JavaScript runtime that allows developers to run JavaScript on the server side.",
     "high"),
    ("ASP.NET", "language",
     "ASP.NET is Microsoft's server-side web framework for building dynamic web applications and APIs.",
     "high"),
    ("Java", "language",
     "Java is a widely-used programming language for enterprise web applications and backend services.",
     "medium"),
    ("Go", "language",
     "Go (Golang) is a compiled language developed by Google, used for high-performance web servers and microservices.",
     "medium"),

    # === Web frameworks ===
    ("Laravel", "framework",
     "Laravel is a PHP framework for building modern, elegant web applications with expressive syntax.",
     "high"),
    ("Symfony", "framework",
     "Symfony is a PHP framework and set of reusable components for web applications.",
     "high"),
    ("Django", "framework",
     "Django is a high-level Python web framework that encourages rapid development and clean design.",
     "high"),
    ("Flask", "framework",
     "Flask is a lightweight Python micro-framework for building web applications and APIs.",
     "high"),
    ("Ruby on Rails", "framework",
     "Ruby on Rails is a server-side web application framework written in Ruby, following the MVC pattern.",
     "high"),
    ("Express", "framework",
     "Express is a minimal Node.js web framework for building APIs and web applications.",
     "high"),
    ("Spring", "framework",
     "Spring is a Java framework for building enterprise-grade web applications and microservices.",
     "medium"),
    ("ASP.NET Core", "framework",
     "ASP.NET Core is Microsoft's cross-platform framework for building modern cloud-based web applications.",
     "high"),

    # === JavaScript libraries & frontend frameworks ===
    ("React", "javascript_library",
     "React is a JavaScript library for building interactive user interfaces and single-page applications (SPAs).",
     "high"),
    ("Vue.js", "javascript_library",
     "Vue.js is a progressive JavaScript framework for building user interfaces and SPAs.",
     "high"),
    ("Angular", "javascript_library",
     "Angular is a TypeScript-based web application framework led by Google for building SPAs.",
     "high"),
    ("jQuery", "javascript_library",
     "jQuery is a fast, small JavaScript library that simplifies HTML DOM manipulation and event handling.",
     "high"),
    ("Bootstrap", "javascript_library",
     "Bootstrap is a front-end framework for responsive, mobile-first websites using HTML, CSS, and JavaScript.",
     "high"),
    ("Next.js", "javascript_library",
     "Next.js is a React framework for server-side rendered and statically generated web applications.",
     "high"),
    ("Nuxt.js", "javascript_library",
     "Nuxt.js is a Vue.js framework for universal and statically generated applications.",
     "medium"),
    ("Svelte", "javascript_library",
     "Svelte is a compiler-based frontend framework for building fast web applications.",
     "medium"),
    ("Ember.js", "javascript_library",
     "Ember.js is a JavaScript framework for ambitious web applications with strong conventions.",
     "medium"),

    # === Analytics & tracking ===
    ("Google Analytics", "analytics",
     "Google Analytics is a web analytics service that tracks and reports website traffic and user behaviour.",
     "high"),
    ("Google Tag Manager", "analytics",
     "Google Tag Manager is a tag management system that lets you deploy marketing and analytics tags without editing code.",
     "high"),
    ("Facebook Pixel", "analytics",
     "Facebook Pixel is an analytics tool used to measure ad effectiveness and build targeted audiences.",
     "medium"),
    ("Hotjar", "analytics",
     "Hotjar is a behaviour analytics tool that provides heatmaps, session recordings, and feedback polls.",
     "medium"),

    # === Security / WAF ===
    ("Cloudflare WAF", "security",
     "Cloudflare Web Application Firewall filters and blocks malicious traffic before it reaches your server.",
     "high"),
    ("Sucuri", "security",
     "Sucuri is a website security platform offering malware scanning, firewall, and monitoring services.",
     "medium"),
    ("ModSecurity", "security",
     "ModSecurity is an open-source web application firewall (WAF) that protects against common web attacks.",
     "medium"),
]

# --------------------------------------------------------------------------- #
# Detection helpers
# --------------------------------------------------------------------------- #

def _extract_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.netloc or target).split(":")[0].strip()


def _normalize_base(base_url: str) -> str:
    return base_url.rstrip("/")


def _fetch(url: str, timeout: float = 5.0) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=True, verify=False
        )
    except requests.RequestException:
        return None


def _match_patterns(text: str, patterns: List[str]) -> bool:
    text_lower = text.lower()
    for p in patterns:
        if re.search(re.escape(p.lower()), text_lower):
            return True
    return False


# --------------------------------------------------------------------------- #
# Detection logic
# --------------------------------------------------------------------------- #

def _detect_from_headers(headers: Dict[str, str]) -> List[Dict]:
    found: List[Dict] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    server = headers_lower.get("server", "")
    x_powered = headers_lower.get("x-powered-by", "")
    via = headers_lower.get("via", "")

    combined = f"{server} {x_powered} {via}".lower()

    # Web servers
    if "cloudflare" in combined:
        found.append(_tech("Cloudflare", "cdn", "high"))
    if "nginx" in combined:
        found.append(_tech("nginx", "web_server", "high"))
    if "apache" in combined:
        found.append(_tech("Apache", "web_server", "high"))
    if "microsoft-iis" in combined or "iis" in combined:
        found.append(_tech("Microsoft-IIS", "web_server", "high"))
    if "litespeed" in combined:
        found.append(_tech("LiteSpeed", "web_server", "medium"))

    # Languages / frameworks from headers
    if "php" in x_powered.lower():
        found.append(_tech("PHP", "language", "high"))
    if "asp.net" in x_powered.lower():
        found.append(_tech("ASP.NET", "language", "high"))
    if "express" in combined:
        found.append(_tech("Express", "framework", "high"))

    # CDN via headers
    if "cloudflare" in via.lower() or "cf-ray" in headers_lower:
        found.append(_tech("Cloudflare", "cdn", "high"))

    return found


def _detect_from_html(html: str, url: str) -> List[Dict]:
    found: List[Dict] = []
    html_lower = html.lower()

    # Generator / CMS meta tags
    cms_patterns: Dict[str, List[str]] = {
        "WordPress": ["wp-content", "wordpress", "wp-includes", "wp-json"],
        "Joomla": ["joomla", "/components/com_"],
        "Drupal": ["drupal", "sites/default", "drupal.settings"],
        "Magento": ["magento", "mage/"],
        "Shopify": ["shopify", "cdn.shopify.com"],
        "PrestaShop": ["prestashop"],
        "OpenCart": ["opencart"],
        "Wix": ["wix.com", "wixcode"],
        "Squarespace": ["squarespace"],
        "Ghost": ["ghost", "ghost.org"],
    }

    for cms, patterns in cms_patterns.items():
        if _match_patterns(html_lower, patterns):
            found.append(_tech(cms, "cms", "high"))
            break  # Usually only one CMS

    # JavaScript libraries / frameworks
    js_patterns: Dict[str, List[str]] = {
        "React": ["react", "_react", "reactdom"],
        "Vue.js": ["vue.js", "vuejs", "__vue__"],
        "Angular": ["ng-app", "angular", "angular.js"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "Next.js": ["next.js", "__next__"],
        "Nuxt.js": ["nuxt.js", "__nuxt__"],
        "Svelte": ["svelte"],
        "Ember.js": ["ember"],
    }

    for lib, patterns in js_patterns.items():
        if _match_patterns(html_lower, patterns):
            found.append(_tech(lib, "javascript_library", "medium"))

    # Analytics
    analytics_patterns: Dict[str, List[str]] = {
        "Google Analytics": ["google-analytics.com/analytics.js", "googletagmanager.com/gtag.js", "ga("],
        "Google Tag Manager": ["googletagmanager.com/gtm.js"],
        "Facebook Pixel": ["facebook.com/tr", "fbevents.js"],
        "Hotjar": ["hotjar.com"],
    }

    for tool, patterns in analytics_patterns.items():
        if _match_patterns(html_lower, patterns):
            found.append(_tech(tool, "analytics", "medium"))

    # WordPress version from generator
    gen_match = re.search(r'<meta name="generator" content="([^"]+)"', html_lower)
    if gen_match:
        gen = gen_match.group(1)
        if "wordpress" in gen:
            found.append(_tech("WordPress", "cms", "high"))
        elif "joomla" in gen:
            found.append(_tech("Joomla", "cms", "high"))
        elif "drupal" in gen:
            found.append(_tech("Drupal", "cms", "high"))

    # Common WordPress paths hinted in HTML
    if "/wp-content/" in html_lower or "/wp-includes/" in html_lower:
        if not any(t["name"] == "WordPress" for t in found):
            found.append(_tech("WordPress", "cms", "medium"))

    return found


def _detect_from_cookies(cookies: str) -> List[Dict]:
    found: List[Dict] = []
    cookies_lower = (cookies or "").lower()

    if "wordpress" in cookies_lower or "wp_" in cookies_lower:
        found.append(_tech("WordPress", "cms", "medium"))
    if "session" in cookies_lower and "php" in cookies_lower:
        found.append(_tech("PHP", "language", "medium"))
    if "asp.net" in cookies_lower or "aspx" in cookies_lower:
        found.append(_tech("ASP.NET", "language", "medium"))

    return found


def _detect_from_urls(html: str, base_url: str) -> List[Dict]:
    """Detect technologies from common URL paths referenced in HTML."""
    found: List[Dict] = []
    html_lower = html.lower()

    if "/wp-json/" in html_lower:
        found.append(_tech("WordPress", "cms", "high"))
    if "/xmlrpc.php" in html_lower:
        found.append(_tech("WordPress", "cms", "medium"))
    if "/wp-admin/" in html_lower:
        found.append(_tech("WordPress", "cms", "medium"))
    if "/administrator/" in html_lower:
        found.append(_tech("Joomla", "cms", "medium"))
    if "/sites/default/" in html_lower:
        found.append(_tech("Drupal", "cms", "medium"))
    if "/cdn.shopify.com" in html_lower:
        found.append(_tech("Shopify", "cms", "high"))

    return found


def _tech(name: str, category: str, confidence: str) -> Dict:
    # Look up description from signature list
    description = ""
    for sig_name, sig_cat, sig_desc, _ in TECH_SIGNATURES:
        if sig_name.lower() == name.lower():
            description = sig_desc
            category = sig_cat  # Use canonical category
            break

    return {
        "name": name,
        "category": category,
        "description": description,
        "confidence": confidence,
    }


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def detect_tech_stack(base_url: str, timeout: float = 5.0) -> Dict:
    """
    Detect the technology stack of a website.

    Parameters
    ----------
    base_url : str
        The target URL (e.g. https://example.com).
    timeout : float
        Per-request timeout in seconds.

    Returns
    -------
    dict
        {
            "target": str,
            "technologies": [ {...}, ... ],   # flat list with duplicates removed
            "by_category": { "web_server": [...], "cms": [...], ... },
            "summary": { "total": int, "categories": int },
        }
    """
    parsed = urlparse(base_url if "://" in base_url else f"http://{base_url}")
    host = parsed.hostname or base_url
    scheme = parsed.scheme or "http"
    port = f":{parsed.port}" if parsed.port else ""
    base_url = f"{scheme}://{host}{port}"

    found_tech: List[Dict] = []
    seen_keys: set = set()

    def _add(tech: Dict) -> None:
        key = f"{tech['name']}|{tech['category']}"
        if key not in seen_keys:
            seen_keys.add(key)
            found_tech.append(tech)

    resp = _fetch(base_url, timeout=timeout)

    if resp:
        # From response headers
        for t in _detect_from_headers(dict(resp.headers)):
            _add(t)

        # From HTML
        html = resp.text or ""
        for t in _detect_from_html(html, base_url):
            _add(t)

        # From cookies
        for t in _detect_from_cookies(resp.headers.get("Set-Cookie", "")):
            _add(t)

        # From URL patterns in HTML
        for t in _detect_from_urls(html, base_url):
            _add(t)

    # Fallback: if nothing detected, label as unknown
    if not found_tech:
        found_tech.append(_tech("Unknown / Not Detected", "other", "low"))

    # Group by category
    by_category: Dict[str, List[Dict]] = {}
    for t in found_tech:
        cat = t["category"]
        by_category.setdefault(cat, []).append(t)

    summary = {
        "total": len(found_tech),
        "categories": len(by_category),
        "category_counts": {k: len(v) for k, v in by_category.items()},
    }

    return {
        "target": base_url,
        "technologies": found_tech,
        "by_category": by_category,
        "summary": summary,
    }


# --------------------------------------------------------------------------- #
# Backward-compatible wrapper
# --------------------------------------------------------------------------- #

def detect_tech_stack_legacy(base_url: str, timeout: float = 5.0) -> List[str]:
    """Legacy helper returning a list of human-readable strings."""
    result = detect_tech_stack(base_url, timeout=timeout)
    out: List[str] = []
    for t in result["technologies"]:
        out.append(
            f"{t['name']} ({t['category']}) — {t['description']}"
        )
    return out
