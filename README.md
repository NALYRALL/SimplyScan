<div align="center">

# SimplyScan

### Passive Website Security Scanner

Inspect publicly accessible websites for common security configuration issues through a React dashboard, an Express API, and a Python scanning engine.

<p>
  <img alt="React" src="https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=111827">
  <img alt="Vite" src="https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white">
  <img alt="Node.js" src="https://img.shields.io/badge/Node.js-Express-339933?logo=nodedotjs&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-Not%20specified-lightgrey">
</p>

</div>

---

## Overview

**SimplyScan** is a small, web-based tool for performing bounded, passive checks against a website. Enter a URL, let the scanner inspect a limited number of same-domain pages, and review the results in a dashboard.

The project is split into three services:

- **Client:** React and Vite interface for starting scans and viewing results.
- **API:** Node.js and Express endpoint that receives browser requests and forwards them to the scanner.
- **Scanner:** Python and Flask service that fetches public pages and runs the checks.

> **Responsible use:** Only scan websites you own or have explicit permission to assess. SimplyScan is an educational project. Its findings are signals for investigation, not proof of exploitability or a replacement for a professional security assessment.

## At a glance

| Area | Current implementation |
|---|---|
| Frontend | React 19, Vite 8 |
| API | Node.js, Express 5 |
| Scanning engine | Python, Flask, Requests, Beautiful Soup |
| Crawl limit | Up to 5 same-domain pages per scan |
| Link checks | Up to 10 discovered links per page |
| Redirect handling | Limited to 5 redirects |
| Scan mode | Passive HTTP response and HTML analysis |
| Scan history | Browser local storage, up to 5 recent entries |

## How it works

~~~mermaid
flowchart TD
    A[User enters a website URL] --> B[React + Vite client]
    B -->|POST /scan| C[Node.js + Express API]
    C -->|POST /scan| D[Python + Flask scanner]
    D --> E[Public target website]
    E --> D
    D -->|JSON scan report| C
    C -->|JSON response| B
    B --> F[Dashboard: summary, score, pages and findings]
~~~

The browser calls the Node API. The Node API calls the Python scanner over HTTP. The scanner returns a JSON report containing an overall summary and per-page results.

## Features

### Website inspection

- Normalize and validate HTTP/HTTPS target URLs.
- Crawl up to five pages on the target's domain.
- Follow a bounded redirect chain.
- Limit response-body processing to 2 MB per page.
- Check a small number of discovered same-domain links.

### Security checks

The scanner currently includes checks for:

- **HTTP security headers:** Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy and Permissions-Policy.
- **Cookie attributes:** Secure, HttpOnly and SameSite, with additional attention to potentially sensitive cookies.
- **CORS configuration:** Potentially risky wildcard and credential combinations.
- **Cache-Control:** Missing or weak directives on responses considered potentially sensitive.
- **Subresource Integrity (SRI):** External scripts and stylesheets without integrity metadata.
- **Forms and links:** Insecure form actions and selected link observations.
- **Mixed content:** HTTP resources referenced by HTTPS pages.
- **Broken links:** A limited availability check for discovered links.
- **HTML exposure:** HTML comments and patterns that may indicate exposed secrets.
- **Connection and server metadata:** HTTPS, response status, redirects, response time and selected server headers.

These checks are intentionally limited. A missing header is not automatically a vulnerability, and a pattern match may be a false positive. Review the evidence and recommendations before drawing conclusions.

### Results dashboard

- Finding counts grouped by severity.
- A presentation score based on detected finding severity.
- Per-page status and response details.
- Security header, cookie, connection and server information.
- Redirect and HTML-analysis summaries.
- Severity filters and page search.
- A local history of the five most recent scans.

## Project structure

~~~text
SimplyScan/
├── client/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── .env.example
│   ├── package.json
│   └── vite.config.js
│
├── server/
│   ├── .env.example
│   ├── package.json
│   ├── package-lock.json
│   └── server.js
│
├── scanner/
│   ├── .env.example
│   ├── requirements.txt
│   └── scanner.py
│
├── .gitattributes
├── .gitignore
└── README.md
~~~

## Requirements

Install the following before running the project:

- Node.js and npm (use a current version supported by Vite).
- Python 3.10 or newer.
- Git.

## Run locally

Start the scanner, API and frontend in **three separate terminals** from the repository root.

### 1. Python scanner

~~~bash
cd scanner
python -m venv .venv
~~~

Activate the virtual environment.

**Windows PowerShell:**

~~~powershell
.venv\Scripts\Activate.ps1
~~~

**Git Bash on Windows:**

~~~bash
source .venv/Scripts/activate
~~~

**macOS / Linux:**

~~~bash
source .venv/bin/activate
~~~

Install dependencies and start the scanner:

~~~bash
python -m pip install -r requirements.txt
python scanner.py
~~~

The scanner listens on port <code>5001</code> by default. The hosting environment can override this with the <code>PORT</code> variable.

### 2. Node.js API

Open a second terminal:

~~~bash
cd server
npm ci
npm start
~~~

The API listens on port <code>5000</code> by default. It forwards scan requests to the scanner at <code>http://127.0.0.1:5001</code> unless <code>SCANNER_URL</code> is configured.

### 3. React frontend

Open a third terminal:

~~~bash
cd client
npm ci
npm run dev
~~~

Open the local URL printed by Vite, usually <code>http://localhost:5173</code>.

### Optional frontend checks

From the <code>client/</code> directory:

~~~bash
npm run build
npm run lint
~~~

The production build is written to <code>client/dist/</code>.

## Configuration

Each service has an <code>.env.example</code> file showing its expected variables.

| Variable | Service | Purpose | Local default |
|---|---|---|---|
| <code>VITE_API_URL</code> | Client | Base URL of the Node API | <code>http://localhost:5000</code> |
| <code>PORT</code> | API | Port for the Express server | <code>5000</code> |
| <code>SCANNER_URL</code> | API | Base URL of the Python scanner | <code>http://127.0.0.1:5001</code> |
| <code>CLIENT_URL</code> | API | Comma-separated allowed browser origins for CORS | <code>http://localhost:5173</code> |
| <code>PORT</code> | Scanner | Port for the Flask server | <code>5001</code> |
| <code>FRONTEND_ORIGIN</code> | Scanner | Origin allowed by the scanner's CORS response | <code>*</code> |

### Environment-file notes

- Vite loads client environment files automatically. Copy <code>client/.env.example</code> to <code>client/.env</code> and set <code>VITE_API_URL</code> when needed. Vite exposes only variables prefixed with <code>VITE_</code> to client code.
- The Node and Python services read variables from the process environment. Their <code>.env.example</code> files are templates; the current backend and scanner do not load those files automatically.
- For deployment, set the variables in the hosting provider's service settings. Set <code>CLIENT_URL</code> to the deployed frontend origin and <code>SCANNER_URL</code> to the deployed scanner service URL.
- Never commit real secrets or populated <code>.env</code> files.

## API reference

The browser communicates with the **Node.js API**.

### Node API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | <code>/</code> | Basic API status |
| GET | <code>/health</code> | Checks whether the Python scanner is reachable |
| POST | <code>/scan</code> | Starts a website scan |

### Start a scan

Request:

~~~http
POST /scan
Content-Type: application/json
~~~

~~~json
{
  "url": "https://example.com"
}
~~~

The API forwards the URL to the Python scanner and returns the scanner's JSON response.

### Response shape

~~~json
{
  "target": "https://example.com/",
  "summary": {
    "pages_scanned": 1,
    "info": 1,
    "low": 2,
    "medium": 0,
    "high": 0,
    "errors": 0
  },
  "pages": [
    {
      "url": "https://example.com/",
      "final_url": "https://example.com/",
      "status_code": 200,
      "response_time": 0.123,
      "content_type": "text/html",
      "https": true,
      "redirects": [],
      "security_headers": {},
      "server_info": {},
      "html_analysis": {},
      "cookies": [],
      "findings": [],
      "truncated": false
    }
  ]
}
~~~

The values above illustrate the response structure; actual findings, counts, headers and timings depend on the target website.

### Scanner service endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | <code>/</code> | Scanner status and mode |
| GET | <code>/health</code> | Scanner health |
| POST | <code>/scan</code> | Runs the scan |

## Safety and operating limits

SimplyScan includes basic protections intended to keep scans bounded:

- Rejects invalid URLs and common non-public destinations, including local and private IP ranges.
- Validates redirect destinations rather than blindly following redirects.
- Restricts crawling to the target's domain.
- Limits each scan to five pages and checks at most ten discovered links per page.
- Limits redirect handling and response-body size.
- Uses request timeouts.

These safeguards reduce risk but should not be treated as a guarantee of production-grade isolation or a complete SSRF defense. Run the scanner in an appropriately restricted environment.

## Limitations

- Scans unauthenticated, publicly accessible pages only.
- Does not execute browser-side JavaScript or inspect content that requires an authenticated session.
- Does not attempt exploitation, brute force, password guessing or destructive testing.
- Does not provide a complete vulnerability assessment or compliance certification.
- Some findings require manual validation and may be false positives or context-dependent.

## Development and contribution

Issues and focused improvements are welcome. Before submitting a change:

1. Keep the client, API and scanner responsibilities separate.
2. Preserve conservative request, page and redirect limits.
3. Run the frontend build and lint commands.
4. Run a scanner syntax check with <code>python -m py_compile scanner.py</code> from the <code>scanner/</code> directory.
5. Do not commit environment files, credentials, virtual environments or dependency folders.

## License

No open-source license has been added to this repository yet. Until a license is added, the project remains subject to the default copyright rules; do not assume that reuse or redistribution is permitted.

## Author

**Himanshu Gupta**

[GitHub: @NALYRALL](https://github.com/NALYRALL)
