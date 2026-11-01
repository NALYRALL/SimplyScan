# SimplyScan

SimplyScan is a passive website security scanner with a React frontend, an Express API, and a Python-based scanning service. It inspects publicly accessible pages for selected security configuration issues and presents the results in a web interface.

> **Use responsibly:** Scan only websites that you own or have explicit permission to assess. SimplyScan is an educational project and is not a substitute for a professional security assessment.

## Architecture

```text
React + Vite (client)
        |
        | POST /scan
        v
Node.js + Express (server)
        |
        | POST /scan
        v
Python + Flask (scanner)
        |
        v
Target website
```

The browser communicates with the Node API. The Node service forwards scan requests to the Python scanner.

## Features

- Submit a website URL for scanning.
- Crawl a limited number of same-domain pages.
- Inspect selected HTTP security headers.
- Review cookie security attributes when cookies are returned.
- Identify selected HTML and form configuration observations.
- Detect HTTP resources on HTTPS pages (mixed content).
- Inspect redirect information and selected same-domain links.
- View findings grouped by severity.
- Review per-page scan details.
- Keep a small scan history in browser local storage.

Checks are passive and response-based. Findings are indicators to investigate, not proof that a site is exploitable. Some results may require manual validation.

## Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| API backend | Node.js, Express, Axios, CORS |
| Scanner | Python, Flask, Requests, Beautiful Soup |

## Project Structure

```text
SimplyScan/
├── client/       # React + Vite frontend
├── server/       # Node.js + Express API
├── scanner/      # Python + Flask scanning service
├── .gitignore
└── README.md
```

## Prerequisites

Install:

- Node.js (LTS recommended) and npm
- Python 3.10 or newer
- Git

## Local Setup

Run each service in a separate terminal from the repository root.

### 1. Python scanner

```powershell
cd scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scanner.py
```

The scanner listens on port `5001` by default.

If PowerShell blocks virtual-environment activation, use the Python executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scanner.py
```

### 2. Node.js API

Open another terminal:

```powershell
cd server
npm install
npm start
```

The API listens on port `5000` by default. Configure the scanner URL with the `SCANNER_URL` environment variable when the scanner is not running at `http://127.0.0.1:5001`.

### 3. React frontend

Open another terminal:

```powershell
cd client
npm install
npm run dev
```

Vite prints the local development URL (normally `http://localhost:5173`).

For a deployed frontend, set `VITE_API_URL` to the base URL of the deployed Node API. In local development, the frontend defaults to `http://localhost:5000`.

## API

### Health check

`GET /` on the Node API returns a basic service status response.

### Scan a website

`POST /scan`

Request body:

```json
{
  "url": "https://example.com"
}
```

The API returns a JSON scan result containing the target, summary counts, and scanned page details. A scan can take several seconds depending on the target and the checks performed.

## Configuration

| Variable | Used by | Purpose |
|---|---|---|
| `PORT` | Node / scanner | Port to bind to; platform hosts commonly provide this automatically |
| `SCANNER_URL` | Node | Base URL of the Python scanner |
| `CLIENT_URL` | Node | Allowed frontend origin(s) when CORS is configured |
| `VITE_API_URL` | Vite client | Base URL of the Node API |

Do not commit real credentials, API keys, or private environment files. Use your hosting provider's environment-variable settings for deployment.

## Development Notes

- Install dependencies separately in `client/`, `server/`, and `scanner/`.
- Do not commit `node_modules/`, Python virtual environments, build output, or `.env` files.
- Keep scan limits and request timeouts conservative.
- Treat automated findings as leads for manual review.

## Limitations

SimplyScan currently provides a bounded set of passive checks. It does not perform authenticated testing, exploit validation, brute force, or comprehensive vulnerability assessment. Results depend on what the target exposes to unauthenticated HTTP requests.

## License

No open-source license is currently specified. Unless a license is added, standard copyright restrictions apply to reuse and redistribution.

## Author

Himanshu Gupta
