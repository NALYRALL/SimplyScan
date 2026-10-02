from flask import Flask, request, jsonify
import requests
import time
import re

from bs4 import BeautifulSoup, Comment
from urllib.parse import urlparse, urljoin, urldefrag


app = Flask(__name__)


# =========================================================
# CONFIGURATION
# =========================================================

MAX_PAGES = 5
REQUEST_TIMEOUT = 10

USER_AGENT = "SimplyScan/1.0"


# =========================================================
# URL VALIDATION
# =========================================================

def validate_url(url):

    if not url:
        return False, "URL is required"

    if not isinstance(url, str):
        return False, "URL must be a string"

    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"

    parsed = urlparse(url)

    if not parsed.netloc:
        return False, "Invalid URL"

    return True, None


# =========================================================
# URL CANONICALIZATION
# =========================================================

def canonicalize_url(url):

    # Remove #fragment
    url, _ = urldefrag(url)

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""

    # Preserve port when present
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    else:
        netloc = hostname

    path = parsed.path

    if not path:
        path = "/"

    # Remove trailing slash except root
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    return parsed._replace(
        scheme=scheme,
        netloc=netloc,
        path=path
    ).geturl()


# =========================================================
# SECURITY HEADERS
# =========================================================

def analyze_security_headers(url, headers):

    findings = []

    header_rules = {

        "Content-Security-Policy": {
            "severity": "low",
            "description":
                "Helps control which resources a page is allowed to load.",
            "recommendation":
                "Configure a Content-Security-Policy appropriate for the application."
        },

        "X-Frame-Options": {
            "severity": "low",
            "description":
                "Controls whether the page can be embedded in a frame.",
            "recommendation":
                "Configure X-Frame-Options or an appropriate CSP frame-ancestors policy."
        },

        "X-Content-Type-Options": {
            "severity": "low",
            "description":
                "Helps prevent browsers from MIME-sniffing responses.",
            "recommendation":
                "Set X-Content-Type-Options to nosniff."
        },

        "Strict-Transport-Security": {
            "severity": "medium",
            "description":
                "Instructs browsers to use HTTPS for future requests.",
            "recommendation":
                "Configure HSTS for the HTTPS application."
        },

        "Referrer-Policy": {
            "severity": "low",
            "description":
                "Controls how much referrer information browsers send.",
            "recommendation":
                "Configure an appropriate Referrer-Policy."
        },

        "Permissions-Policy": {
            "severity": "low",
            "description":
                "Controls access to browser features and APIs.",
            "recommendation":
                "Configure Permissions-Policy according to the application's requirements."
        }
    }

    for header, rule in header_rules.items():

        if header in headers:

            findings.append({
                "check": "Security Header",
                "type": "security_header",
                "header": header,
                "severity": "info",
                "status": "present"
            })

        else:

            # HSTS is meaningful for HTTPS
            if header == "Strict-Transport-Security":
                if not url.startswith("https://"):
                    continue

            findings.append({
                "check": "Security Header",
                "type": "security_header",
                "header": header,
                "severity": rule["severity"],
                "status": "missing",
                "description": rule["description"],
                "recommendation": rule["recommendation"]
            })

    return findings


# =========================================================
# COOKIE SECURITY
# =========================================================

def analyze_cookies(url, response):

    findings = []

    set_cookie_headers = response.raw.headers.get_all(
        "Set-Cookie"
    )

    if not set_cookie_headers:
        return findings

    for cookie_header in set_cookie_headers:

        parts = [
            part.strip()
            for part in cookie_header.split(";")
        ]

        if not parts:
            continue

        cookie_name = parts[0].split(
            "=",
            1
        )[0].strip()

        attributes = {
            part.split("=", 1)[0].strip().lower()
            for part in parts[1:]
        }

        secure = "secure" in attributes
        httponly = "httponly" in attributes
        samesite = any(
            attr.startswith("samesite")
            for attr in attributes
        )

        if url.startswith("https://") and not secure:

            findings.append({
                "check": "Cookie Security",
                "type": "cookie",
                "severity": "medium",
                "status": "missing_secure",
                "cookie": cookie_name,
                "description":
                    "Cookie does not have the Secure attribute.",
                "recommendation":
                    "Set the Secure attribute for sensitive cookies."
            })

        if not httponly:

            findings.append({
                "check": "Cookie Security",
                "type": "cookie",
                "severity": "low",
                "status": "missing_httponly",
                "cookie": cookie_name,
                "description":
                    "Cookie does not have the HttpOnly attribute.",
                "recommendation":
                    "Use HttpOnly for cookies that do not need JavaScript access."
            })

        if not samesite:

            findings.append({
                "check": "Cookie Security",
                "type": "cookie",
                "severity": "low",
                "status": "missing_samesite",
                "cookie": cookie_name,
                "description":
                    "Cookie does not explicitly define SameSite.",
                "recommendation":
                    "Configure an appropriate SameSite attribute."
            })

    return findings


# =========================================================
# HTML ANALYSIS
# =========================================================

def analyze_html(url, response, soup):

    findings = []

    form_findings = []
    link_findings = []
    mixed_content_findings = []
    exposure_findings = []

    # -----------------------------------------------------
    # BASIC HTML INFORMATION
    # -----------------------------------------------------

    title = None

    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    forms = soup.find_all("form")
    links = soup.find_all("a", href=True)
    scripts = soup.find_all("script")
    images = soup.find_all("img")

    # -----------------------------------------------------
    # FORMS
    # -----------------------------------------------------

    for form in forms:

        action = form.get(
            "action",
            ""
        )

        absolute_action = canonicalize_url(
            urljoin(url, action)
        )

        if absolute_action.startswith("http://"):

            form_findings.append({
                "check": "Form Security",
                "type": "insecure_form",
                "severity": "medium",
                "status": "insecure",
                "url": absolute_action,
                "description":
                    "Form submits data over HTTP.",
                "recommendation":
                    "Use HTTPS for form submissions."
            })

        else:

            form_findings.append({
                "check": "Form Security",
                "type": "secure_form",
                "severity": "info",
                "status": "secure",
                "url": absolute_action,
                "description":
                    "Form submission uses HTTPS."
            })

    # -----------------------------------------------------
    # LINKS
    # -----------------------------------------------------

    discovered_links = []

    base_domain = urlparse(url).netloc.lower()

    for link in links:

        href = link.get("href")

        if not href:
            continue

        absolute_url = urljoin(
            url,
            href
        )

        parsed = urlparse(
            absolute_url
        )

        if parsed.scheme not in (
            "http",
            "https"
        ):
            continue

        absolute_url = canonicalize_url(
            absolute_url
        )

        discovered_links.append(
            absolute_url
        )

        # HTTP link on HTTPS page
        if (
            url.startswith("https://")
            and absolute_url.startswith("http://")
        ):

            link_findings.append({
                "check": "Link Security",
                "type": "insecure_link",
                "severity": "medium",
                "status": "insecure",
                "url": absolute_url,
                "description":
                    "HTTPS page contains an HTTP link.",
                "recommendation":
                    "Use HTTPS links wherever possible."
            })

        # External link
        elif parsed.netloc.lower() != base_domain:

            link_findings.append({
                "check": "External Link",
                "type": "external_link",
                "severity": "info",
                "status": "external",
                "url": absolute_url,
                "description":
                    "External link detected."
            })

    # Remove duplicate links
    discovered_links = list(
        dict.fromkeys(discovered_links)
    )

    # -----------------------------------------------------
    # MIXED CONTENT
    # -----------------------------------------------------

    resource_tags = [
        ("script", "src"),
        ("img", "src"),
        ("iframe", "src"),
        ("link", "href"),
        ("audio", "src"),
        ("video", "src"),
        ("source", "src")
    ]

    for tag_name, attribute in resource_tags:

        elements = soup.find_all(
            tag_name
        )

        for element in elements:

            resource = element.get(
                attribute
            )

            if not resource:
                continue

            absolute_resource = urljoin(
                url,
                resource
            )

            if (
                url.startswith("https://")
                and absolute_resource.startswith("http://")
            ):

                mixed_content_findings.append({
                    "check": "Mixed Content",
                    "type": "mixed_content",
                    "severity": "medium",
                    "status": "insecure",
                    "url": absolute_resource,
                    "description":
                        "HTTPS page loads a resource over HTTP.",
                    "recommendation":
                        "Load all resources over HTTPS."
                })

    # -----------------------------------------------------
    # HTML COMMENTS
    # -----------------------------------------------------

    comments = soup.find_all(
        string=lambda text: isinstance(
            text,
            Comment
        )
    )

    for comment in comments:

        comment_text = str(
            comment
        ).strip()

        if comment_text:

            findings.append({
                "check": "HTML Comment",
                "type": "html_comment",
                "severity": "info",
                "status": "exposed",
                "description":
                    "HTML comment exposed in page source.",
                "content":
                    comment_text[:200]
            })

    # -----------------------------------------------------
    # POTENTIAL SECRET EXPOSURE
    # -----------------------------------------------------

    page_text = response.text

    exposure_patterns = {

        "AWS Access Key":
            r"\bAKIA[0-9A-Z]{16}\b",

        "Private Key":
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",

        "JWT Token":
            r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",

        "API Key":
            r"""(?i)\b(?:api[_-]?key|apikey)\b\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]"""
    }

    for name, pattern in exposure_patterns.items():

        matches = re.findall(
            pattern,
            page_text
        )

        if matches:

            exposure_findings.append({
                "check": "Potential Secret Exposure",
                "type": "potential_secret",
                "severity": "high",
                "status": "detected",
                "name": name,
                "description":
                    f"Potential {name} found in page source.",
                "recommendation":
                    "Review the source and remove secrets or sensitive credentials."
            })

    # -----------------------------------------------------
    # RETURN HTML DATA
    # -----------------------------------------------------

    return {

        "title": title,

        "forms": len(forms),

        "links": len(links),

        "scripts": len(scripts),

        "images": len(images),

        "form_findings": form_findings,

        "link_findings": link_findings,

        "mixed_content_findings": mixed_content_findings,

        "exposure_findings": exposure_findings,

        "_discovered_links": discovered_links
    }


# =========================================================
# BROKEN LINK CHECK
# =========================================================

def check_link(url):

    try:

        response = requests.head(
            url,
            timeout=5,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        status = response.status_code

        # Some servers reject HEAD.
        # Fall back to GET.
        if status in (
            405,
            403
        ):

            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                headers={
                    "User-Agent": USER_AGENT
                },
                stream=True
            )

            status = response.status_code

        return status

    except requests.RequestException:

        return None


def analyze_broken_links(
    links,
    base_url
):

    findings = []

    base_domain = urlparse(
        base_url
    ).netloc.lower()

    checked = set()

    for link in links:

        parsed = urlparse(link)

        # Only check same-domain links
        if parsed.netloc.lower() != base_domain:
            continue

        if link in checked:
            continue

        checked.add(link)

        status = check_link(
            link
        )

        if status is None:

            findings.append({
                "check": "Broken Link",
                "type": "broken_link",
                "severity": "low",
                "status": "unreachable",
                "url": link,
                "description":
                    "Link could not be reached during the check.",
                "recommendation":
                    "Verify that the resource is available."
            })

        elif status >= 400:

            findings.append({
                "check": "Broken Link",
                "type": "broken_link",
                "severity": "medium",
                "status": "broken",
                "url": link,
                "status_code": status,
                "description":
                    f"Link returned HTTP status {status}.",
                "recommendation":
                    "Verify or remove the broken link."
            })

    return findings


# =========================================================
# COLLECT ALL FINDINGS
# =========================================================

def collect_findings(
    findings,
    form_findings,
    link_findings,
    mixed_content_findings,
    exposure_findings,
    redirect_findings,
    cookie_findings,
    broken_link_findings
):

    all_findings = []

    all_findings.extend(
        findings
    )

    all_findings.extend(
        form_findings
    )

    all_findings.extend(
        link_findings
    )

    all_findings.extend(
        mixed_content_findings
    )

    all_findings.extend(
        exposure_findings
    )

    all_findings.extend(
        redirect_findings
    )

    all_findings.extend(
        cookie_findings
    )

    all_findings.extend(
        broken_link_findings
    )

    return all_findings


# =========================================================
# SCAN SINGLE PAGE
# =========================================================

def scan_page(url):

    start_time = time.time()

    try:

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        response_time = round(
            time.time() - start_time,
            3
        )

        findings = []

        # -------------------------------------------------
        # SECURITY HEADERS
        # -------------------------------------------------

        header_findings = analyze_security_headers(
            url,
            response.headers
        )

        findings.extend(
            header_findings
        )

        # -------------------------------------------------
        # HTTPS
        # -------------------------------------------------

        if url.startswith("https://"):

            findings.append({
                "check": "HTTPS",
                "type": "https",
                "severity": "info",
                "status": "secure"
            })

        else:

            findings.append({
                "check": "HTTPS",
                "type": "https",
                "severity": "high",
                "status": "insecure",
                "description":
                    "Website is using HTTP instead of HTTPS.",
                "recommendation":
                    "Use HTTPS to protect data in transit."
            })

        # -------------------------------------------------
        # REDIRECTS
        # -------------------------------------------------

        redirect_findings = []

        if response.history:

            redirect_chain = []

            for redirect in response.history:

                redirect_chain.append({
                    "url": redirect.url,
                    "status_code": redirect.status_code
                })

            redirect_chain.append({
                "url": response.url,
                "status_code": response.status_code
            })

            redirect_findings.append({
                "check": "Redirect",
                "type": "redirect",
                "severity": "info",
                "status": "detected",
                "description":
                    "Redirect chain detected.",
                "chain": redirect_chain
            })

        # -------------------------------------------------
        # SERVER INFORMATION
        # -------------------------------------------------

        server_info = {

            "server":
                response.headers.get("Server"),

            "content_type":
                response.headers.get("Content-Type"),

            "content_length":
                response.headers.get("Content-Length"),

            "powered_by":
                response.headers.get("X-Powered-By")
        }

        # -------------------------------------------------
        # COOKIE ANALYSIS
        # -------------------------------------------------

        cookie_findings = analyze_cookies(
            url,
            response
        )

        # -------------------------------------------------
        # HTML ANALYSIS
        # -------------------------------------------------

        html_data = {

            "title": None,

            "forms": 0,

            "links": 0,

            "scripts": 0,

            "images": 0,

            "form_findings": [],

            "link_findings": [],

            "mixed_content_findings": [],

            "exposure_findings": [],

            "_discovered_links": []
        }

        content_type = response.headers.get(
            "Content-Type",
            ""
        )

        if "text/html" in content_type.lower():

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            html_data = analyze_html(
                url,
                response,
                soup
            )

        # -------------------------------------------------
        # BROKEN LINKS
        # -------------------------------------------------

        broken_link_findings = []

        # We intentionally limit broken-link checks
        # to discovered same-domain links.
        discovered_links = html_data[
            "_discovered_links"
        ]

        if discovered_links:

            broken_link_findings = analyze_broken_links(
                discovered_links,
                url
            )

        # -------------------------------------------------
        # COMBINE FINDINGS
        # -------------------------------------------------

        all_findings = collect_findings(

            findings,

            html_data[
                "form_findings"
            ],

            html_data[
                "link_findings"
            ],

            html_data[
                "mixed_content_findings"
            ],

            html_data[
                "exposure_findings"
            ],

            redirect_findings,

            cookie_findings,

            broken_link_findings
        )

        # -------------------------------------------------
        # FINAL PAGE RESULT
        # -------------------------------------------------

        result = {

            "url": url,

            "final_url": response.url,

            "status_code":
                response.status_code,

            "response_time":
                response_time,

            "content_type":
                content_type,

            "findings":
                all_findings,

            "redirects":
                redirect_findings,

            "server_info":
                server_info,

            "title":
                html_data["title"],

            "forms":
                html_data["forms"],

            "links":
                html_data["links"],

            "scripts":
                html_data["scripts"],

            "images":
                html_data["images"],

            "_discovered_links":
                discovered_links
        }

        return result

    except requests.exceptions.RequestException as e:

        print(
            "REQUEST ERROR:",
            repr(e)
        )

        return {
            "url": url,
            "error":
                f"Request failed: {str(e)}"
        }

    except Exception as e:

        print(
            "ERROR:",
            repr(e)
        )

        return {
            "url": url,
            "error": str(e)
        }


# =========================================================
# CRAWLER
# =========================================================

def crawl(start_url):

    pages = []

    visited = set()

    queue = [
        canonicalize_url(
            start_url
        )
    ]

    base_domain = urlparse(
        start_url
    ).netloc.lower()

    while (
        queue
        and len(pages) < MAX_PAGES
    ):

        current_url = queue.pop(0)

        current_url = canonicalize_url(
            current_url
        )

        # -------------------------------------------------
        # SKIP DUPLICATES
        # -------------------------------------------------

        if current_url in visited:
            continue

        visited.add(
            current_url
        )

        print(
            f"Scanning {len(pages) + 1}/{MAX_PAGES}: {current_url}"
        )

        # -------------------------------------------------
        # SCAN PAGE
        # -------------------------------------------------

        result = scan_page(
            current_url
        )

        # -------------------------------------------------
        # GET DISCOVERED LINKS
        # -------------------------------------------------

        discovered_links = result.pop(
            "_discovered_links",
            []
        )

        pages.append(
            result
        )

        # -------------------------------------------------
        # ADD SAME-DOMAIN LINKS
        # -------------------------------------------------

        for link in discovered_links:

            parsed = urlparse(
                link
            )

            if parsed.netloc.lower() != base_domain:
                continue

            if parsed.scheme not in (
                "http",
                "https"
            ):
                continue

            link = canonicalize_url(
                link
            )

            # Only queue HTML-looking URLs.
            # Skip obvious static files.
            path = parsed.path.lower()

            blocked_extensions = (
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".svg",
                ".webp",
                ".ico",
                ".css",
                ".js",
                ".pdf",
                ".zip",
                ".mp3",
                ".mp4",
                ".avi",
                ".mov",
                ".woff",
                ".woff2",
                ".ttf"
            )

            if path.endswith(
                blocked_extensions
            ):
                continue

            if (
                link not in visited
                and link not in queue
            ):

                queue.append(
                    link
                )

        # -------------------------------------------------
        # STOP AT MAX PAGES
        # -------------------------------------------------

        if len(pages) >= MAX_PAGES:
            break

    return pages


# =========================================================
# SUMMARY
# =========================================================

def generate_summary(pages):

    summary = {

        "pages_scanned":
            len(pages),

        "info":
            0,

        "low":
            0,

        "medium":
            0,

        "high":
            0,

        "errors":
            0
    }

    for page in pages:

        if "error" in page:

            summary["errors"] += 1

            continue

        for finding in page.get(
            "findings",
            []
        ):

            severity = finding.get(
                "severity"
            )

            if severity in summary:

                summary[
                    severity
                ] += 1

    return summary


# =========================================================
# SCAN API
# =========================================================

@app.post("/scan")
def scan():

    data = request.get_json(
        silent=True
    ) or {}

    url = data.get(
        "url"
    )

    # -----------------------------------------------------
    # VALIDATE URL
    # -----------------------------------------------------

    valid, error = validate_url(
        url
    )

    if not valid:

        return jsonify({
            "error": error
        }), 400

    # -----------------------------------------------------
    # CANONICALIZE TARGET
    # -----------------------------------------------------

    url = canonicalize_url(
        url
    )

    # -----------------------------------------------------
    # CRAWL
    # -----------------------------------------------------

    pages = crawl(
        url
    )

    # -----------------------------------------------------
    # GENERATE SUMMARY
    # -----------------------------------------------------

    summary = generate_summary(
        pages
    )

    # -----------------------------------------------------
    # FINAL RESPONSE
    # -----------------------------------------------------

    return jsonify({

        "target":
            url,

        "summary":
            summary,

        "pages":
            pages
    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def home():

    return jsonify({

        "message":
            "SimplyScan scanner is running"
    })


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        port=5001,
        debug=True,
        use_reloader=False
    )