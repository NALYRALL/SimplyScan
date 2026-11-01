import ipaddress
import os
import re
import socket
import time
from collections import Counter
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlparse, urldefrag, urlunparse

import requests
from bs4 import BeautifulSoup, Comment
from flask import Flask, jsonify, request


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

app = Flask(__name__)

MAX_PAGES = 5
MAX_LINK_CHECKS = 10
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 10
LINK_TIMEOUT = 4
MAX_RESPONSE_BYTES = 2_000_000
USER_AGENT = "SimplyScan/1.0"

# Set this in production to your frontend origin, for example:
# FRONTEND_ORIGIN=https://simplyscan.vercel.app
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "*")

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Controls which resources a page is allowed to load.",
        "recommendation": "Configure a Content-Security-Policy appropriate for the application.",
        "severity": "low",
    },
    "X-Frame-Options": {
        "description": "Helps control whether the page can be embedded in a frame.",
        "recommendation": "Set X-Frame-Options or use CSP frame-ancestors.",
        "severity": "low",
    },
    "X-Content-Type-Options": {
        "description": "Helps prevent browsers from MIME-sniffing responses.",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
        "severity": "low",
    },
    "Strict-Transport-Security": {
        "description": "Instructs browsers to use HTTPS for future requests.",
        "recommendation": "Configure HSTS with an appropriate max-age.",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information browsers send.",
        "recommendation": "Configure an appropriate Referrer-Policy.",
        "severity": "low",
    },
    "Permissions-Policy": {
        "description": "Controls access to browser features and APIs.",
        "recommendation": "Configure Permissions-Policy according to application requirements.",
        "severity": "low",
    },
}

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Private Key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "JWT": re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\."
        r"[A-Za-z0-9_-]{8,}\."
        r"[A-Za-z0-9_-]{8,}\b"
    ),
    "Generic API Key": re.compile(
        r"""(?i)\b(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_-]{12,}['"]"""
    ),
}

SENSITIVE_COOKIE_PATTERN = re.compile(
    r"(session|sess|auth|token|jwt|login|user|account|csrf|xsrf|password)",
    re.IGNORECASE,
)

SENSITIVE_PATH_PATTERN = re.compile(
    r"/(account|profile|dashboard|admin|billing|payment|checkout|"
    r"settings|user|users|orders|api/private)(/|$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------
# URL validation and safe HTTP requests
# ---------------------------------------------------------------------

def normalize_url(value):
    """Normalize an HTTP(S) URL and remove its fragment."""
    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlparse(value)
    except ValueError:
        return None

    if parsed.scheme.lower() not in ("http", "https"):
        return None

    if not parsed.hostname or parsed.username or parsed.password:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    if port is not None and not (1 <= port <= 65535):
        return None

    host = parsed.hostname.rstrip(".").lower()
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port:
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    normalized = urlunparse(
        (parsed.scheme.lower(), netloc, path, "", parsed.query, "")
    )
    return urldefrag(normalized)[0]


def host_without_port(netloc):
    parsed = urlparse("//" + netloc)
    return (parsed.hostname or "").rstrip(".").lower()


def is_public_host(hostname):
    """
    Reject localhost, private, loopback, link-local, reserved and multicast
    destinations. This is an important minimum SSRF safeguard.
    """
    hostname = (hostname or "").rstrip(".").lower()

    if not hostname or hostname == "localhost" or hostname.endswith(".localhost"):
        return False

    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_global
    except ValueError:
        pass

    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    if not records:
        return False

    for record in records:
        address = record[4][0]
        try:
            if not ipaddress.ip_address(address).is_global:
                return False
        except ValueError:
            return False

    return True


def validate_public_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    return is_public_host(parsed.hostname)


def safe_fetch(url, session, timeout=REQUEST_TIMEOUT):
    """
    Fetch a public URL while validating every redirect destination.
    Response body is capped to MAX_RESPONSE_BYTES.
    """
    current_url = url
    redirects = []

    for _ in range(MAX_REDIRECTS + 1):
        normalized = normalize_url(current_url)
        if not normalized or not validate_public_url(normalized):
            raise ValueError("URL resolves to a non-public or invalid destination")

        response = session.get(
            normalized,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            status_code = response.status_code
            response.close()

            if not location:
                raise requests.exceptions.RequestException(
                    "Redirect response did not include a Location header"
                )

            next_url = normalize_url(urljoin(normalized, location))
            if not next_url:
                raise ValueError("Redirect contains an invalid URL")

            redirects.append({
                "url": normalized,
                "status_code": status_code,
                "location": next_url,
            })
            current_url = next_url
            continue

        started_reading = time.time()
        try:
            body = response.raw.read(
                MAX_RESPONSE_BYTES + 1,
                decode_content=True,
            )
        except Exception:
            response.close()
            raise

        truncated = len(body) > MAX_RESPONSE_BYTES
        body = body[:MAX_RESPONSE_BYTES]
        response._content = body
        response._content_consumed = True
        response.close()

        response.simplyscan_truncated = truncated
        response.simplyscan_redirects = redirects
        response.simplyscan_read_time = round(time.time() - started_reading, 3)
        response.url = normalized
        return response

    raise requests.exceptions.TooManyRedirects(
        f"More than {MAX_REDIRECTS} redirects"
    )


def safe_response_text(response):
    raw = response.content[:MAX_RESPONSE_BYTES]
    encoding = response.encoding or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def is_html_response(response):
    content_type = response.headers.get("Content-Type", "").lower()
    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
    )


def same_domain(url, target_host):
    parsed = urlparse(url)
    return (
        parsed.scheme in ("http", "https")
        and host_without_port(parsed.netloc) == target_host
    )


# ---------------------------------------------------------------------
# Findings helpers
# ---------------------------------------------------------------------

def add_finding(findings, finding):
    findings.append(finding)


def deduplicate_findings(findings):
    unique = []
    seen = set()

    for finding in findings:
        key = (
            finding.get("type"),
            finding.get("status"),
            finding.get("url"),
            finding.get("cookie"),
            finding.get("header"),
            finding.get("secret_type"),
            finding.get("tag"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique


def finding(
    finding_type,
    check,
    severity,
    status,
    description,
    recommendation,
    **extra,
):
    result = {
        "type": finding_type,
        "check": check,
        "severity": severity,
        "status": status,
        "description": description,
        "recommendation": recommendation,
    }
    result.update(extra)
    return result


# ---------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------

def analyze_security_headers(response, requested_url):
    findings = []
    headers = response.headers
    is_https = requested_url.lower().startswith("https://")

    csp = headers.get("Content-Security-Policy", "")
    has_frame_ancestors = bool(
        re.search(r"(?:^|;)\s*frame-ancestors\s+", csp, re.IGNORECASE)
    )

    for header_name, metadata in SECURITY_HEADERS.items():
        value = headers.get(header_name)

        if header_name == "Strict-Transport-Security" and not is_https:
            continue

        if header_name == "X-Frame-Options" and has_frame_ancestors:
            continue

        if not value:
            add_finding(findings, finding(
                "missing_security_header",
                "Security Headers",
                metadata["severity"],
                "missing",
                f"{header_name} header is not present.",
                metadata["recommendation"],
                header=header_name,
            ))
            continue

        if header_name == "X-Content-Type-Options":
            if value.strip().lower() != "nosniff":
                add_finding(findings, finding(
                    "weak_security_header",
                    "Security Headers",
                    "low",
                    "weak",
                    "X-Content-Type-Options is present but is not set to nosniff.",
                    "Set X-Content-Type-Options to nosniff.",
                    header=header_name,
                    value=value,
                ))

        elif header_name == "Strict-Transport-Security":
            if not re.search(r"(?:^|;)\s*max-age\s*=\s*\d+", value, re.I):
                add_finding(findings, finding(
                    "weak_security_header",
                    "Security Headers",
                    "medium",
                    "weak",
                    "HSTS is present but does not contain a valid max-age directive.",
                    "Configure an appropriate HSTS max-age after confirming HTTPS works across the site.",
                    header=header_name,
                    value=value,
                ))

    return findings


def analyze_cookies(response, requested_url, sensitive=False):
    findings = []
    is_https = requested_url.lower().startswith("https://")

    try:
        raw_cookie_headers = response.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw_cookie_headers = []

    if not raw_cookie_headers:
        header_value = response.headers.get("Set-Cookie")
        if header_value:
            raw_cookie_headers = [header_value]

    for raw_cookie in raw_cookie_headers:
        parsed_cookie = SimpleCookie()
        try:
            parsed_cookie.load(raw_cookie)
        except Exception:
            continue

        for name, morsel in parsed_cookie.items():
            is_sensitive = (
                sensitive or bool(SENSITIVE_COOKIE_PATTERN.search(name))
            )
            secure = bool(morsel["secure"])
            httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"].strip().lower()

            severity = "medium" if is_sensitive else "low"

            if is_https and not secure:
                add_finding(findings, finding(
                    "cookie_security",
                    "Cookie Security",
                    severity,
                    "missing_secure",
                    f"Cookie '{name}' is sent over HTTPS but does not have the Secure attribute.",
                    "Set the Secure attribute so the cookie is only transmitted over HTTPS.",
                    cookie=name,
                ))

            if not httponly:
                add_finding(findings, finding(
                    "cookie_security",
                    "Cookie Security",
                    severity,
                    "missing_httponly",
                    f"Cookie '{name}' does not have the HttpOnly attribute.",
                    "Set HttpOnly for cookies that do not need to be accessed by client-side JavaScript.",
                    cookie=name,
                ))

            if not samesite:
                add_finding(findings, finding(
                    "cookie_security",
                    "Cookie Security",
                    severity,
                    "missing_samesite",
                    f"Cookie '{name}' does not explicitly define a SameSite policy.",
                    "Set SameSite=Lax or SameSite=Strict where appropriate.",
                    cookie=name,
                ))
            elif samesite == "none" and not secure:
                add_finding(findings, finding(
                    "cookie_security",
                    "Cookie Security",
                    "medium",
                    "samesite_none_without_secure",
                    f"Cookie '{name}' uses SameSite=None without the Secure attribute.",
                    "Cookies using SameSite=None should also have the Secure attribute.",
                    cookie=name,
                ))

    return findings


def analyze_cors(response, sensitive=False):
    findings = []
    origin = response.headers.get("Access-Control-Allow-Origin")
    credentials = response.headers.get("Access-Control-Allow-Credentials")

    if not origin:
        return findings

    origin = origin.strip()
    credentials_enabled = (
        credentials is not None
        and credentials.strip().lower() == "true"
    )

    if origin == "*":
        if credentials_enabled:
            severity = "medium"
            status = "wildcard_with_credentials"
            description = (
                "The response declares wildcard CORS together with credentials. "
                "Browsers reject credentialed wildcard-origin access, but this "
                "combination indicates a potentially unsafe configuration."
            )
        elif sensitive:
            severity = "medium"
            status = "wildcard_sensitive"
            description = (
                "The response allows requests from any origin on a potentially "
                "sensitive resource."
            )
        else:
            severity = "info"
            status = "wildcard"
            description = (
                "The response allows requests from any origin. This may be "
                "intentional for public resources."
            )

        add_finding(findings, finding(
            "permissive_cors",
            "CORS",
            severity,
            status,
            description,
            "Use an explicit trusted origin when the resource contains non-public or user-specific data.",
            header="Access-Control-Allow-Origin",
            value=origin,
        ))

    return findings


def analyze_cache_control(response, sensitive=False):
    findings = []
    if not sensitive:
        return findings

    cache_control = response.headers.get("Cache-Control")
    if not cache_control:
        add_finding(findings, finding(
            "cache_control",
            "Cache-Control",
            "medium",
            "missing",
            "The response may contain sensitive or user-specific content but does not define Cache-Control directives.",
            "Use appropriate directives such as private or no-store for sensitive responses.",
            header="Cache-Control",
        ))
        return findings

    directives = {
        part.strip().lower()
        for part in cache_control.split(",")
        if part.strip()
    }
    has_private = "private" in directives
    has_no_store = "no-store" in directives
    has_public = "public" in directives

    if has_public and not has_private and not has_no_store:
        add_finding(findings, finding(
            "cache_control",
            "Cache-Control",
            "medium",
            "public_sensitive_content",
            "The response appears sensitive but is explicitly marked as publicly cacheable.",
            "Use private or no-store for responses containing user-specific or sensitive information.",
            header="Cache-Control",
            value=cache_control,
        ))
    elif not has_private and not has_no_store:
        add_finding(findings, finding(
            "cache_control",
            "Cache-Control",
            "low",
            "weak",
            "The response may contain sensitive information but does not explicitly use private or no-store.",
            "Consider using private or no-store for sensitive responses.",
            header="Cache-Control",
            value=cache_control,
        ))

    return findings


def analyze_sri(soup, page_url):
    findings = []
    seen_resources = set()
    page_host = host_without_port(urlparse(page_url).netloc)

    for tag in soup.find_all(["script", "link"]):
        if tag.name == "script":
            resource = tag.get("src")
        else:
            rel = tag.get("rel", [])
            if isinstance(rel, str):
                rel = [rel]
            rel_values = [str(item).lower() for item in rel]
            if "stylesheet" not in rel_values:
                continue
            resource = tag.get("href")

        if not resource:
            continue

        resource_url = urljoin(page_url, resource.strip())
        parsed = urlparse(resource_url)

        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue

        resource_host = host_without_port(parsed.netloc)
        if resource_host == page_host:
            continue

        # Google Fonts stylesheets are dynamically generated and commonly
        # do not provide stable SRI hashes.
        if resource_host == "fonts.googleapis.com":
            continue

        normalized = urldefrag(resource_url)[0]
        if normalized in seen_resources:
            continue
        seen_resources.add(normalized)

        if tag.get("integrity"):
            continue

        add_finding(findings, finding(
            "missing_sri",
            "Subresource Integrity",
            "low",
            "missing",
            "Cross-origin script or stylesheet does not declare a Subresource Integrity hash.",
            "Consider SRI for externally hosted scripts and stylesheets that support stable integrity hashes.",
            tag=tag.name,
            url=resource_url,
        ))

    return findings


def analyze_forms(soup, page_url):
    findings = []
    is_https = page_url.lower().startswith("https://")

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "get").lower()
        absolute_action = urljoin(page_url, action) if action else page_url
        parsed_action = urlparse(absolute_action)

        has_password = bool(form.find(
            "input", attrs={"type": re.compile(r"^password$", re.I)}
        ))

        if is_https and parsed_action.scheme.lower() == "http":
            add_finding(findings, finding(
                "insecure_form",
                "Form Security",
                "medium",
                "http_form_action",
                "HTTPS page submits a form to an HTTP destination.",
                "Submit forms over HTTPS and verify the destination is trusted.",
                url=absolute_action,
                method=method,
            ))

        if has_password and parsed_action.scheme.lower() != "https":
            add_finding(findings, finding(
                "insecure_password_form",
                "Form Security",
                "high",
                "password_form_without_https",
                "A form containing a password field does not submit to an HTTPS destination.",
                "Transmit passwords only to a trusted HTTPS endpoint.",
                url=absolute_action,
                method=method,
            ))

    return findings


def analyze_links(soup, page_url):
    discovered = []
    seen = set()

    for tag in soup.find_all("a", href=True):
        href = tag.get("href", "").strip()
        if not href or href.startswith((
            "#", "mailto:", "tel:", "javascript:", "data:"
        )):
            continue

        absolute = urldefrag(urljoin(page_url, href))[0]
        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue

        if absolute not in seen:
            seen.add(absolute)
            discovered.append(absolute)

    return discovered


def analyze_broken_links(urls, session):
    findings = []

    for url in urls[:MAX_LINK_CHECKS]:
        if not validate_public_url(url):
            continue

        try:
            response = session.head(
                url,
                timeout=LINK_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            )
            status = response.status_code
            response.close()

            if status == 429:
                status_name = "rate_limited"
                severity = "info"
                description = "The destination rate-limited the link check; this is not classified as a broken link."
            elif status in (401, 403):
                status_name = "blocked"
                severity = "info"
                description = "The destination blocked the link check; its availability could not be confirmed."
            elif status >= 400:
                status_name = "broken"
                severity = "low"
                description = f"The link returned HTTP {status} during a HEAD request."
            else:
                continue

            add_finding(findings, finding(
                "link_status",
                "Link Check",
                severity,
                status_name,
                description,
                "Verify the destination in a browser. Some servers handle HEAD requests differently from GET requests.",
                url=url,
                status_code=status,
            ))

        except requests.RequestException:
            add_finding(findings, finding(
                "link_status",
                "Link Check",
                "info",
                "unreachable",
                "The link could not be checked because the destination did not respond successfully.",
                "Verify the destination independently; network restrictions and bot protection can affect automated checks.",
                url=url,
            ))

    return findings


def analyze_mixed_content(soup, page_url):
    findings = []
    if not page_url.lower().startswith("https://"):
        return findings

    resource_attributes = {
        "script": "src",
        "img": "src",
        "iframe": "src",
        "audio": "src",
        "video": "src",
        "source": "src",
        "link": "href",
        "object": "data",
    }
    seen = set()

    for tag_name, attribute in resource_attributes.items():
        for tag in soup.find_all(tag_name):
            resource = (tag.get(attribute) or "").strip()
            if not resource or resource.startswith((
                "#", "data:", "javascript:", "mailto:", "tel:", "blob:"
            )):
                continue

            absolute = urljoin(page_url, resource)
            parsed = urlparse(absolute)

            if parsed.scheme.lower() != "http":
                continue

            normalized = urldefrag(absolute)[0]
            if normalized in seen:
                continue
            seen.add(normalized)

            add_finding(findings, finding(
                "mixed_content",
                "Mixed Content",
                "medium",
                "mixed_content",
                "HTTPS page references a resource over HTTP.",
                "Serve referenced resources over HTTPS.",
                url=absolute,
                tag=tag_name,
            ))

    return findings


def analyze_comments(soup):
    findings = []
    keywords = re.compile(
        r"(password|secret|api[_-]?key|token|private key|todo|debug|"
        r"internal|temporary|credential)",
        re.IGNORECASE,
    )

    for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
        content = str(comment).strip()
        if content and keywords.search(content):
            add_finding(findings, finding(
                "sensitive_html_comment",
                "HTML Comments",
                "low",
                "potential_sensitive_comment",
                "An HTML comment contains a keyword that may indicate internal or sensitive information.",
                "Review the comment and remove internal notes or sensitive values before publishing.",
            ))

    return findings


def analyze_exposure(page_source):
    findings = []

    for name, pattern in SECRET_PATTERNS.items():
        matches = pattern.findall(page_source)
        if not matches:
            continue

        severity = "high" if name == "Private Key" else "medium"
        add_finding(findings, finding(
            "potential_secret",
            "Potential Secret Exposure",
            severity,
            "potential_exposure",
            f"Potential {name} pattern found in publicly returned page content.",
            "Verify whether the value is a real credential. If it is real, revoke or rotate it and remove it from public content.",
            secret_type=name,
            count=len(matches),
        ))

    return findings


def analyze_response(response, requested_url):
    page_url = response.url
    page_source = safe_response_text(response)
    content_type = response.headers.get("Content-Type")
    parsed = urlparse(page_url)
    path = parsed.path or "/"

    sensitive = (
        bool(SENSITIVE_PATH_PATTERN.search(path))
        or bool(re.search(r"password|email|token|account|profile", page_source, re.I))
    )

    findings = []
    findings.extend(analyze_security_headers(response, page_url))
    findings.extend(analyze_cookies(response, page_url, sensitive))
    findings.extend(analyze_cors(response, sensitive))
    findings.extend(analyze_cache_control(response, sensitive))

    html_analysis = {
        "title": None,
        "forms": 0,
        "links": 0,
        "scripts": 0,
        "images": 0,
    }
    discovered = []

    if is_html_response(response):
        soup = BeautifulSoup(page_source, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else None

        html_analysis = {
            "title": title,
            "forms": len(soup.find_all("form")),
            "links": len(soup.find_all("a", href=True)),
            "scripts": len(soup.find_all("script")),
            "images": len(soup.find_all("img")),
        }

        discovered = analyze_links(soup, page_url)
        findings.extend(analyze_sri(soup, page_url))
        findings.extend(analyze_forms(soup, page_url))
        findings.extend(analyze_mixed_content(soup, page_url))
        findings.extend(analyze_comments(soup))
        findings.extend(analyze_exposure(page_source))

    server_info = {
        "server": response.headers.get("Server"),
        "content_type": content_type,
        "content_length": response.headers.get("Content-Length"),
        "x_powered_by": response.headers.get("X-Powered-By"),
    }

    security_headers = {
        name: response.headers.get(name)
        for name in SECURITY_HEADERS
    }
    security_headers["Strict-Transport-Security"] = (
        response.headers.get("Strict-Transport-Security")
    )

    page = {
        "url": requested_url,
        "final_url": page_url,
        "status_code": response.status_code,
        "response_time": None,
        "content_type": content_type,
        "https": page_url.lower().startswith("https://"),
        "redirects": getattr(response, "simplyscan_redirects", []),
        "security_headers": security_headers,
        "server_info": server_info,
        "html_analysis": html_analysis,
        "cookies": [
            cookie.get("cookie")
            for cookie in findings
            if cookie.get("type") == "cookie_security"
        ],
        "findings": deduplicate_findings(findings),
        "truncated": bool(getattr(response, "simplyscan_truncated", False)),
    }

    return page, discovered


# ---------------------------------------------------------------------
# Summary and scan route
# ---------------------------------------------------------------------

def generate_summary(pages):
    summary = {
        "pages_scanned": len(pages),
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "errors": 0,
    }

    for page in pages:
        if page.get("error"):
            summary["errors"] += 1

        for item in page.get("findings", []):
            severity = item.get("severity")
            if severity in ("info", "low", "medium", "high"):
                summary[severity] += 1

    return summary


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = FRONTEND_ORIGIN
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Vary"] = "Origin"
    return response


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "SimplyScan scanner is running",
        "mode": "passive",
        "max_pages": MAX_PAGES,
        "status": "healthy",
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "simplyscan-scanner"})


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request body is required"}), 400

    supplied_url = data.get("url")
    if not isinstance(supplied_url, str) or not supplied_url.strip():
        return jsonify({"error": "URL is required"}), 400

    target_url = normalize_url(supplied_url)
    if not target_url:
        return jsonify({
            "error": "A valid HTTP or HTTPS URL is required"
        }), 400

    if not validate_public_url(target_url):
        return jsonify({
            "error": "Only publicly accessible HTTP or HTTPS websites can be scanned"
        }), 400

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    pages = []
    queue = [target_url]
    visited = set()
    target_host = host_without_port(urlparse(target_url).netloc)

    try:
        while queue and len(pages) < MAX_PAGES:
            current_url = queue.pop(0)

            if current_url in visited:
                continue
            visited.add(current_url)

            started = time.time()

            try:
                response = safe_fetch(current_url, session)
                page, discovered = analyze_response(response, current_url)
                page["response_time"] = round(time.time() - started, 3)

                # Check a small number of discovered links. This is a
                # lightweight availability check, not a vulnerability test.
                link_candidates = [
                    item for item in discovered
                    if item not in visited
                ][:MAX_LINK_CHECKS]

                page["findings"].extend(
                    analyze_broken_links(link_candidates, session)
                )
                page["findings"] = deduplicate_findings(page["findings"])
                pages.append(page)

                for discovered_url in discovered:
                    normalized = normalize_url(discovered_url)
                    if (
                        normalized
                        and same_domain(normalized, target_host)
                        and normalized not in visited
                        and normalized not in queue
                        and len(queue) + len(pages) < MAX_PAGES
                    ):
                        queue.append(normalized)

            except requests.exceptions.Timeout:
                pages.append({
                    "url": current_url,
                    "final_url": current_url,
                    "status_code": None,
                    "response_time": round(time.time() - started, 3),
                    "content_type": None,
                    "findings": [finding(
                        "page_timeout",
                        "Page Request",
                        "low",
                        "timeout",
                        "Page request timed out.",
                        "Verify the target independently.",
                    )],
                    "error": "Request timed out",
                })

            except Exception as error:
                app.logger.exception("Scanner failed while analysing %s", current_url)
                pages.append({
                    "url": current_url,
                    "final_url": current_url,
                    "status_code": None,
                    "response_time": round(time.time() - started, 3),
                    "content_type": None,
                    "findings": [finding(
                        "scanner_error",
                        "Scanner",
                        "info",
                        "error",
                        "Scanner could not complete analysis of this page.",
                        "Check the scanner logs and retry the scan.",
                    )],
                    "error": str(error),
                })

    finally:
        session.close()

    return jsonify({
        "target": target_url,
        "summary": generate_summary(pages),
        "pages": pages,
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=False)
